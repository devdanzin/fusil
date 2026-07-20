"""Unit tests for the --tsan concurrency-stress code generation (WritePythonCode).

Pure generation tests (no target execution): build an options stand-in with tsan on, generate
a script, and assert the emitted stress region is present, valid, and parameterised -- and that
the single-threaded function/class/object sweeps are replaced by it. Mirrors test_oom_fuzz.
"""

import ast
import json
import os
import re
import tempfile
import unittest
from types import ModuleType
from unittest.mock import MagicMock

from fusil.python.write_python_code import WritePythonCode


def _extract_tsan_manifest(src):
    """Pull the emitted `[TSAN-MANIFEST] {json}` payload back out of the generated source."""
    for line in src.splitlines():
        line = line.strip()
        if "[TSAN-MANIFEST]" in line and line.startswith("print("):
            m = re.match(r"print\((.*), file=stderr\)$", line)
            printed = ast.literal_eval(m.group(1))  # the string literal print()s
            return json.loads(printed[len("[TSAN-MANIFEST] ") :])
    raise AssertionError("no [TSAN-MANIFEST] line in generated source")


def _tsan_module():
    """A tiny module with a class and a function so the generator has objects to share."""
    mod = ModuleType("tsanmod")

    class Widget:
        def op(self, *a):
            return a

    def helper(*a):
        return a

    def fork(*a):  # a process-lifecycle call the stress region must NOT invoke
        return a

    def execv(*a):
        return a

    def abort(*a):  # a self-signalling call (os.abort -> SIGABRT); must NOT be invoked
        return a

    mod.Widget = Widget
    mod.helper = helper
    mod.fork = fork
    mod.execv = execv
    mod.abort = abort
    return mod


def _make_tsan_options(
    threads=4,
    iterations=200,
    shared_objects=3,
    weird_subclasses=False,
    mutate_state=False,
    shared_objects_only=False,
):
    o = MagicMock()
    o.tsan = True
    o.tsan_threads = threads
    o.tsan_iterations = iterations
    o.tsan_shared_objects = shared_objects
    # OOM off (mutually exclusive); real values so any range()/comparison is well-defined.
    o.oom_fuzz = False
    o.oom_foreign = False
    o.oom_seq = False
    # General generation knobs the header/definitions/argument-generator paths read.
    o.fuzz_exceptions = False
    o.gc_aggressive = False
    o.test_private = False
    o.no_numpy = True
    o.no_tstrings = True
    o.external_references = True
    o.functions_number = 5
    o.classes_number = 0
    o.objects_number = 0
    o.methods_number = 2
    o.tsan_weird_subclasses = weird_subclasses  # Slice E, opt-in
    # Opt-in concurrent-mutation ops. MUST be set explicitly: a bare MagicMock would auto-vivify
    # a truthy attribute and turn the machinery on in every test.
    o.tsan_mutate_state = mutate_state
    o.tsan_shared_objects_only = shared_objects_only  # same auto-vivify caveat
    return o


def _generate_tsan(plugin_manager=None, **opt_overrides):
    parent = MagicMock()
    parent.options = _make_tsan_options(**opt_overrides)
    parent.filenames = ["/bin/sh"]
    fd, path = tempfile.mkstemp(suffix="_tsan_test.py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            parent,
            path,
            _tsan_module(),
            "tsanmod",
            threads=False,
            _async=False,
            plugin_manager=plugin_manager,
        )
        writer.generate_fuzzing_script()
        with open(path) as fp:
            return fp.read()
    finally:
        os.unlink(path)


class TestTSanGeneration(unittest.TestCase):
    def test_emitted_script_is_valid_python(self):
        ast.parse(_generate_tsan())

    def test_stress_region_present(self):
        src = _generate_tsan()
        self.assertIn("TSan concurrency-stress region", src)
        self.assertIn("_tsan_threading.Barrier", src)
        self.assertIn("def _tsan_worker(", src)
        # workers share objects and start together, then join (clean, no timeout).
        self.assertIn("_tsan_barrier.wait()", src)
        self.assertIn("_t.start()", src)
        self.assertIn("_t.join()", src)
        self.assertNotIn("join(timeout", src)

    def test_free_threading_preflight_emitted(self):
        # The harness must refuse to run GIL-enabled (else it is serialised noise).
        src = _generate_tsan()
        self.assertIn("_is_gil_enabled", src)
        self.assertIn("raise SystemExit(3)", src)

    def test_enriched_op_mix_emitted(self):
        # Phase 3: the worker exercises the FT-race-rich classes, not just method calls.
        src = _generate_tsan()
        self.assertIn("import gc as _tsan_gc", src)
        self.assertIn("import weakref as _tsan_weakref", src)
        self.assertIn("_tsan_gc.collect()", src)  # concurrent GC
        self.assertIn("_tsan_weakref.ref(_obj)", src)  # weakref churn
        self.assertIn("setattr(_obj,", src)  # managed-dict / attribute churn
        self.assertIn("isinstance(_bag,", src)  # shared-container mutation

    def test_shared_iterator_op_emitted(self):
        # (h) shared-iterator races: one iterator advanced by every sibling worker, plus a
        # repr() reading its state -- the class behind cpython#153928/#154013/#153981.
        src = _generate_tsan()
        self.assertIn("_tsan_iter_factories", src)
        self.assertIn("_tsan_iters.append([_f()])", src)  # guarded, length-aligned build (Slice C)
        self.assertIn("next(_it)", src)  # concurrent cursor advance on the shared iterator
        self.assertIn("repr(_it)", src)  # state read racing the concurrent next()
        # covers the builtin iterator family + the stdlib C iterators from the linked issues
        self.assertIn("iter_unpack", src)  # struct (cpython#154013)
        self.assertIn("_tsan_itertools.count(10 ** 18, 2)", src)  # count slow mode (cpython#153981)

    def test_read_while_mutate_op_emitted(self):
        # (i) iterate / copy / sort the shared container while siblings mutate it in (f).
        src = _generate_tsan()
        self.assertIn("sorted(_bag)", src)  # concurrent sort of a shared list (binarysort)
        self.assertIn("list(_bag.items())", src)  # dict iter-vs-resize

    def test_worker_roles_emitted(self):
        # Slice A: workers take complementary reader/writer roles by _wid so a reader always
        # races a writer on the SAME shared object / container / iterator (per-group sharing).
        src = _generate_tsan()
        self.assertIn("_role = _wid % 3", src)
        self.assertIn("if _role != 1:", src)  # reader-gated ops (read-churn, iterate, length_hint)
        self.assertIn("if _role != 0:", src)  # writer-gated ops (mutate, advance)
        # the group shares ONE iterator (rotated per session) so roles collide on it
        self.assertIn("_ITER_OFF =", src)
        self.assertIn("_cell = _tsan_iters[(_idx + _ITER_OFF) % len(_tsan_iters)]", src)
        self.assertIn("_tsan_operator.length_hint(_it, 0)", src)  # non-advancing it_index read

    def test_provenance_markers_emitted(self):
        # Slice B: the region prints a human `[TSAN] provenance ...` line and a machine-parseable
        # `[TSAN-MANIFEST] {json}` line, so a crash dir's stdout carries the real generation
        # context (fixing the "builtin race stamped with whatever module the session picked" bug).
        src = _generate_tsan()
        self.assertIn("[TSAN] provenance module=tsanmod", src)
        self.assertIn("[TSAN-MANIFEST] ", src)
        # both markers land BEFORE the region does any work (so a later abort can't lose them):
        self.assertLess(src.index("[TSAN-MANIFEST]"), src.index("def _tsan_worker"))
        manifest = _extract_tsan_manifest(src)
        self.assertEqual(manifest["kind"], "tsan-provenance")
        self.assertEqual(manifest["module"], "tsanmod")
        # the fixture has one class (Widget) -> a real target object is shared:
        self.assertEqual(manifest["shared_classes"], ["Widget"])
        self.assertEqual(manifest["shared_kind"], "target-objects")
        self.assertEqual(manifest["roles"], {"0": "writer", "1": "reader", "2": "both"})
        self.assertIn("h:shared-iter", manifest["ops"])
        # fork/execv/abort are filtered out of the module-func pool -> only helper remains:
        self.assertEqual(manifest["func_count"], 1)
        self.assertEqual(manifest["iters"], 200)

    def test_provenance_iter_off_matches_emitted(self):
        # The manifest's iter_off must equal the emitted `_ITER_OFF` (single source, so triage can
        # reconstruct which iterator each worker group shared).
        src = _generate_tsan()
        manifest = _extract_tsan_manifest(src)
        off_line = next(ln for ln in src.splitlines() if ln.startswith("_ITER_OFF = "))
        self.assertEqual(int(off_line.split("=")[1]), manifest["iter_off"])

    def test_shares_objects_and_module_functions(self):
        src = _generate_tsan()
        # a module class is instantiated as a guarded FACTORY into the shared pool (Slice C),
        # and the module itself is always appended.
        self.assertIn(
            "_tsan_obj_factories.append(lambda: getattr(fuzz_target_module, 'Widget')())", src
        )
        self.assertIn("_tsan_shared.append(fuzz_target_module)", src)
        # the pool is capped for concentration, then built from the factories under a guard.
        self.assertIn("_TSAN_MAX_SHARED = ", src)
        self.assertIn("_tsan_shared.append(_of())", src)
        # module functions are called concurrently with the shared object as an argument.
        self.assertIn("'helper'", src)
        self.assertIn("_tsan_shared_args", src)

    def test_extension_object_iterators_folded(self):
        # Slice C: each iterable shared-object factory also seeds an iter(factory()) into op (h),
        # pointing the shared-iterator machinery at the target's own tp_iternext.
        src = _generate_tsan()
        self.assertIn(
            "_tsan_iter_factories.append(lambda: iter(getattr(fuzz_target_module, 'Widget')()))",
            src,
        )
        manifest = _extract_tsan_manifest(src)
        self.assertGreaterEqual(manifest["ext_iterators"], 1)  # >=1 (Widget); 2 if args built

    def test_plugin_shared_factory_spliced(self):
        # Slice C: a plugin-contributed target object is spliced into the shared pool + iterator
        # pool, and its label lands in the provenance manifest.
        from fusil.plugin_manager import PluginManager

        pm = PluginManager()
        pm.add_tsan_shared_factory(
            "__import__('collections').OrderedDict()", label="cereggii:AtomicDict", iterable=True
        )
        src = _generate_tsan(plugin_manager=pm)
        self.assertIn(
            "_tsan_obj_factories.append(lambda: __import__('collections').OrderedDict())", src
        )
        self.assertIn(
            "_tsan_iter_factories.append(lambda: iter(__import__('collections').OrderedDict()))",
            src,
        )
        manifest = _extract_tsan_manifest(src)
        self.assertIn("cereggii:AtomicDict", manifest["plugin_factories"])
        self.assertEqual(manifest["shared_kind"], "target-objects")

    def test_non_iterable_plugin_factory_not_folded(self):
        # iterable=False -> spliced into the shared pool but NOT the iterator pool.
        from fusil.plugin_manager import PluginManager

        pm = PluginManager()
        pm.add_tsan_shared_factory("object()", label="opaque", iterable=False)
        src = _generate_tsan(plugin_manager=pm)
        self.assertIn("_tsan_obj_factories.append(lambda: object())", src)
        self.assertNotIn("_tsan_iter_factories.append(lambda: iter(object()))", src)

    def test_weird_subclasses_off_by_default(self):
        # Slice E is opt-in: default output has no hostile-subclass machinery (so the flag-gated
        # emitter leaves the default --tsan script unchanged).
        src = _generate_tsan()
        self.assertNotIn("_tsan_make_weird", src)
        self.assertEqual(_extract_tsan_manifest(src)["weird_subclasses"], [])

    def test_weird_subclasses_emitted_when_enabled(self):
        # With --tsan-weird-subclasses, hostile subclasses of the discovered C types are built
        # (guarded on subclassability) and their instances join the shared + iterator pools.
        src = _generate_tsan(weird_subclasses=True)
        ast.parse(src)  # still valid Python
        self.assertIn("def _tsan_make_weird(_base):", src)
        # curated, DELAYED, exception-diverse failure-injection dunders (the bomb pattern)
        self.assertIn("def _tsan_arm_slot(_name, _base):", src)
        self.assertIn("_tsan_bomb_delay", src)  # delay: succeed then detonate
        self.assertIn("_TSAN_WEIRD_EXCS = (", src)  # exception diversity
        self.assertIn('raise choice(_TSAN_WEIRD_EXCS)("tsan weird via " + _name)', src)
        # reuses tricky_weird's WeirdBase metaclass, with a plain-subclass fallback
        self.assertIn('WeirdBase("_TsanWeird_" + _base.__name__, (_base,), dict(_ns))', src)
        self.assertIn('type("_TsanWeird_" + _base.__name__, (_base,), dict(_ns))', src)
        # the Widget C base is fed to the weird-class builder (guarded)
        self.assertIn("_tsan_make_weird(getattr(fuzz_target_module, 'Widget'))", src)
        # instances + iterators of the weird classes join the pools
        self.assertIn("_tsan_obj_factories.append((lambda _wb=_wb: _wb()))", src)
        self.assertIn("_tsan_iter_factories.append((lambda _wb=_wb: iter(_wb())))", src)
        # provenance records the count
        manifest = _extract_tsan_manifest(src)
        self.assertEqual(manifest["weird_subclasses"], ["Widget"])
        self.assertIn("weird=1", src)

    def test_weird_subclasses_curated_arm_list(self):
        # The arm-vs-leave contract: ARM comparison/hash/eq/repr/index; LEAVE the container /
        # iteration protocol to the C base (so op a/h/i still race its OWN slots), and keep the
        # exception mix free of the OOM (MemoryError) / crash (SystemError) signal words.
        src = _generate_tsan(weird_subclasses=True)
        # extract the full (possibly multi-line) armed-dunder tuple text
        start = src.index("_TSAN_WEIRD_ARM = (")
        arm_text = src[start : src.index(")", start)]
        for armed in ("__eq__", "__hash__", "__lt__", "__gt__", "__repr__", "__index__"):
            self.assertIn(armed, arm_text, armed)
        for left in ("__iter__", "__next__", "__len__", "__getitem__", "__contains__"):
            self.assertNotIn(left, arm_text, left)  # left to the C base
        exc_start = src.index("_TSAN_WEIRD_EXCS = (")
        exc_text = src[exc_start : src.index(")", exc_start)]
        self.assertIn("ValueError", exc_text)
        self.assertNotIn("MemoryError", exc_text)  # OOM signal
        self.assertNotIn("SystemError", exc_text)  # crash word

    def test_weird_base_boilerplate_available(self):
        # The hostile subclasses rely on tricky_weird's WeirdBase being spliced into the script.
        src = _generate_tsan(weird_subclasses=True)
        self.assertIn("class WeirdBase", src)

    def test_knobs_are_parameterised(self):
        src = _generate_tsan(threads=7, iterations=42)
        self.assertIn("_WORKERS_PER_OBJ = 7", src)
        self.assertIn("_ITERS = 42", src)

    def test_process_lifecycle_calls_excluded(self):
        # fork/exec/spawn/... must not be in the module-function list, and the runtime dir()
        # filter must guard the shared module object too (forking a worker crashes the child
        # under TSan -- __tsan::TraceSwitchPart -- and would fork/replace the fuzzer anyway).
        src = _generate_tsan()
        funcs_line = next(ln for ln in src.splitlines() if ln.startswith("_tsan_funcs = "))
        self.assertIn("'helper'", funcs_line)
        self.assertNotIn("'fork'", funcs_line)
        self.assertNotIn("'execv'", funcs_line)
        # os.abort() -> SIGABRT was the pre-#205 posix-sigabrt NOPARSE self-abort; keep it out.
        self.assertNotIn("'abort'", funcs_line)
        self.assertIn("_tsan_unsafe = frozenset(", src)
        self.assertIn("n not in _tsan_unsafe", src)

    def test_replaces_single_threaded_sweeps(self):
        # Under --tsan the normal function-fuzzing sweep is skipped in favour of the stress
        # region, so its banner must be absent.
        src = _generate_tsan()
        self.assertNotIn("functions in tsanmod", src)

    def test_mutate_state_off_by_default(self):
        # --tsan-mutate-state is opt-in: the default script does not run op (j) or the enriched
        # op (b) (the _MUTATE_STATE runtime gate is False), so the manifest advertises neither.
        src = _generate_tsan()
        self.assertIn("_MUTATE_STATE = False", src)
        manifest = _extract_tsan_manifest(src)
        self.assertFalse(manifest["mutate_state"])
        self.assertNotIn("j:prop-reassign", manifest["ops"])
        self.assertIn("ops=a-i", src)  # human provenance line
        # op (b) still uses the original shared-container args when the gate is off
        self.assertIn("_m(*_tsan_shared_args[: (_i % 3)])", src)

    def test_mutate_state_ops_emitted_when_enabled(self):
        # With --tsan-mutate-state the worker gains a property-reassign op (j) and op (b) draws
        # type-diverse args; the manifest and provenance advertise op j.
        src = _generate_tsan(mutate_state=True)
        ast.parse(src)  # still valid Python
        self.assertIn("_MUTATE_STATE = True", src)
        manifest = _extract_tsan_manifest(src)
        self.assertTrue(manifest["mutate_state"])
        self.assertIn("j:prop-reassign", manifest["ops"])
        self.assertIn("ops=a-j", src)  # human provenance line
        # generic tiers: type-diverse call args + the self-reassign property fallback
        self.assertIn("_tsan_call_args = ", src)
        self.assertIn("setattr(_obj, _pn, getattr(_obj, _pn))", src)
        # settable-property discovery is emitted
        self.assertIn('hasattr(getattr(type(_obj), _n, None), "__set__")', src)

    def test_plugin_mutator_registry_spliced_and_consulted(self):
        # A plugin publishes a curated per-type registry via a definitions provider; it is spliced
        # into the child BEFORE the stress region, and the region reads it defensively (the
        # sanctioned child-side-global pattern -- no live callable crosses the process boundary).
        from fusil.plugin_manager import PluginManager

        pm = PluginManager()
        pm.add_definitions_provider(
            lambda config, module_name: (
                "_FUSIL_STATEFUL_MUTATORS = {\n"
                "    getattr(fuzz_target_module, 'Widget'): {\n"
                "        'mutators': [('op', lambda: ('x',))],\n"
                "        'properties': {},\n"
                "    },\n"
                "}\n"
            )
        )
        src = _generate_tsan(plugin_manager=pm, mutate_state=True)
        ast.parse(src)
        # the registry is defined in the child, and core reads it AFTER (ordering guarantee)
        self.assertIn("_FUSIL_STATEFUL_MUTATORS = {", src)
        self.assertIn('_MUT_REG = globals().get("_FUSIL_STATEFUL_MUTATORS", {})', src)
        self.assertLess(
            src.index("_FUSIL_STATEFUL_MUTATORS = {"),
            src.index('_MUT_REG = globals().get("_FUSIL_STATEFUL_MUTATORS"'),
        )
        # the worker consults the curated mutators (op b) and properties (op j)
        self.assertIn('_mut["mutators"]', src)
        self.assertIn('_mut["properties"]', src)

    def test_shared_objects_only_off_by_default(self):
        # Default: the generic builtin iterators (op h) and shared-container ops (f/i) are present.
        src = _generate_tsan()
        self.assertIn("_TSAN_OBJ_ONLY = False", src)
        manifest = _extract_tsan_manifest(src)
        self.assertFalse(manifest["shared_objects_only"])
        self.assertIn("f:container-mutate", manifest["ops"])
        self.assertIn("i:read-while-mutate", manifest["ops"])
        self.assertEqual(len(manifest["iterators"]), 8)  # the builtin iterator pool
        self.assertEqual(manifest["shared_args"], ["list", "dict", "set", "bytearray"])
        self.assertIn("iterators=8+", src)  # human provenance line

    def test_shared_objects_only_drops_generic_state(self):
        # --tsan-shared-objects-only: builtin iterators gone (op h races only ext-object iters),
        # container ops f/i dropped, so an extension hunt stops flooding with CPython-core races.
        src = _generate_tsan(shared_objects_only=True)
        ast.parse(src)  # still valid Python
        self.assertIn("_TSAN_OBJ_ONLY = True", src)
        manifest = _extract_tsan_manifest(src)
        self.assertTrue(manifest["shared_objects_only"])
        self.assertNotIn("f:container-mutate", manifest["ops"])
        self.assertNotIn("i:read-while-mutate", manifest["ops"])
        self.assertEqual(manifest["iterators"], [])  # no builtin iterators
        self.assertEqual(manifest["shared_args"], [])
        self.assertIn("iterators=0+", src)
        self.assertIn("objonly", src)  # human provenance marker
        # the builtin iterator factory list is reset before the ext-object iterators are folded in
        self.assertIn("_tsan_iter_factories = []", src)
        # ops f/i are gated off; op (h) guards an empty iterator pool
        self.assertIn("if _role != 0 and not _TSAN_OBJ_ONLY:", src)
        self.assertIn("if _role != 1 and not _TSAN_OBJ_ONLY:", src)
        self.assertIn("if _cell is not None:", src)

    def test_shared_objects_only_composes_with_mutate_state(self):
        # The two extension-hunt levers stack: obj-only drops generics, mutate-state adds op j.
        src = _generate_tsan(shared_objects_only=True, mutate_state=True)
        ast.parse(src)
        manifest = _extract_tsan_manifest(src)
        self.assertTrue(manifest["shared_objects_only"])
        self.assertTrue(manifest["mutate_state"])
        self.assertNotIn("f:container-mutate", manifest["ops"])
        self.assertIn("j:prop-reassign", manifest["ops"])


if __name__ == "__main__":
    unittest.main()
