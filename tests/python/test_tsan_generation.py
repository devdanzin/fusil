"""Unit tests for the --tsan concurrency-stress code generation (WritePythonCode).

Pure generation tests (no target execution): build an options stand-in with tsan on, generate
a script, and assert the emitted stress region is present, valid, and parameterised -- and that
the single-threaded function/class/object sweeps are replaced by it. Mirrors test_oom_fuzz.
"""

import ast
import os
import tempfile
import unittest
from types import ModuleType
from unittest.mock import MagicMock

from fusil.python.write_python_code import WritePythonCode


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


def _make_tsan_options(threads=4, iterations=200, shared_objects=3):
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
    return o


def _generate_tsan(**opt_overrides):
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
            plugin_manager=None,
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
        self.assertIn("_tsan_iters = [[_f()] for _f in _tsan_iter_factories]", src)
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

    def test_shares_objects_and_module_functions(self):
        src = _generate_tsan()
        # a module class is instantiated into the shared pool, plus the module itself.
        self.assertIn("_tsan_shared.append(getattr(fuzz_target_module, 'Widget')())", src)
        self.assertIn("_tsan_shared.append(fuzz_target_module)", src)
        # module functions are called concurrently with the shared object as an argument.
        self.assertIn("'helper'", src)
        self.assertIn("_tsan_shared_args", src)

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


if __name__ == "__main__":
    unittest.main()
