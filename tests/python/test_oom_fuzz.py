"""Tests for OOM (out-of-memory) fuzzing mode code generation (Phases 1 & 2).

These verify that ``--oom-fuzz`` makes ``WritePythonCode`` emit the set_nomemory
boilerplate, the ``oom_call`` dense-sweep harness, per-function sweep sites
(Phase 1), and -- for modules with classes -- constructor and method sweeps
(Phase 2); and that none of that appears when the mode is off (gating / regression).

The fixture builds a ``MagicMock`` options object with the few real-typed
attributes the generator needs; it does not depend on the (currently stale)
``test_write_python_code`` fixture.
"""

import ast
import json
import math
import os
import random
import re
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)

from fusil.python.write_python_code import WritePythonCode

OOM_MAX_START = 50
OOM_CALLS = 3


def _make_options(oom_fuzz, oom_verbose=False):
    """Build an options stand-in with the attributes generation reads."""
    o = MagicMock()
    # OOM mode
    o.oom_fuzz = oom_fuzz
    o.oom_max_start = OOM_MAX_START
    o.oom_start_min = 0
    o.oom_calls = OOM_CALLS
    o.oom_verbose = oom_verbose
    # General generation knobs
    o.fuzz_exceptions = False
    o.gc_aggressive = False
    o.oom_foreign = False
    o.oom_foreign_pythonmalloc = False
    # TSan mode OFF (explicit: a bare MagicMock attr would be truthy and divert generation).
    o.tsan = False
    # Alt-interpreter generic modes OFF too (same MagicMock-is-truthy divert hazard as tsan).
    o.concurrency_stress = False
    o.new_uninit = False
    o.test_private = False
    o.no_numpy = True
    o.no_tstrings = True
    o.functions_number = 5
    o.classes_number = 0
    o.objects_number = 0
    o.methods_number = 2
    # OOM class fuzzing (Phase 2). Real ints so `range(...)` / `> 0` work; default
    # 0 keeps the function-only Phase-1 tests' oom_call counts exact.
    o.oom_classes = 0
    o.oom_methods = 0
    # OOM stateful sequences (Phase 4). Default OFF (real values, not MagicMock auto-attrs)
    # so Phase-1/2 tests keep the single-call path and exact oom_call counts.
    o.oom_seq = False
    o.oom_seq_len = 3
    o.oom_window = 1
    o.oom_seq_randomize = False
    # General arg-gen knob (formerly --no-jit-external-references); still read by
    # WritePythonCode when constructing the ArgumentGenerator.
    o.external_references = True
    return o


def _generate(
    oom_fuzz,
    oom_verbose=False,
    module=math,
    module_name="math",
    oom_classes=0,
    oom_methods=0,
    test_private=False,
    oom_seq=False,
    oom_seq_len=3,
    oom_window=1,
    oom_seq_randomize=False,
    oom_foreign=False,
    oom_start_min=0,
):
    """Generate a fuzzing script against ``module`` and return its source."""
    parent = MagicMock()
    options = _make_options(oom_fuzz, oom_verbose)
    options.oom_classes = oom_classes
    options.oom_methods = oom_methods
    options.test_private = test_private
    options.oom_seq = oom_seq
    options.oom_seq_len = oom_seq_len
    options.oom_window = oom_window
    options.oom_seq_randomize = oom_seq_randomize
    options.oom_foreign = oom_foreign
    options.oom_start_min = oom_start_min
    parent.options = options
    parent.filenames = ["/bin/sh"]
    fd, path = tempfile.mkstemp(suffix="_oom_test.py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            parent,
            path,
            module,
            module_name,
            threads=False,
            _async=False,
            plugin_manager=None,
        )
        writer.generate_fuzzing_script()
        with open(path) as fp:
            return fp.read()
    finally:
        os.unlink(path)


class TestOOMFuzzGeneration(unittest.TestCase):
    def test_oom_mode_emits_harness_and_sweeps(self):
        src = _generate(oom_fuzz=True)

        # Generated script must be valid Python.
        ast.parse(src)

        # Guarded _testcapi boilerplate + faulthandler.
        self.assertIn("faulthandler.enable()", src)
        self.assertIn("from _testcapi import set_nomemory", src)
        self.assertIn("_OOM_AVAILABLE", src)

        # The dense-sweep harness, parameterised by --oom-max-start, now takes a label.
        self.assertIn("def oom_call(label, func", src)
        self.assertIn(f"_OOM_MAX_START = {OOM_MAX_START}", src)
        self.assertIn("_OOM_MIN_START = 0", src)
        self.assertIn("range(_OOM_MIN_START, _OOM_MAX_START)", src)
        # The allocation hook is installed ONCE (disarmed) and the loop re-arms/disarms the
        # failure window without swapping the allocator -- swapping (remove_mem_hooks) inside
        # the loop races fuzzed worker threads and corrupts the heap. So the per-iteration
        # _remove_mem_hooks() swap is gone; the finally disarms via set_nomemory instead.
        self.assertIn("_OOM_DISABLE", src)
        self.assertIn("_set_nomemory(_OOM_DISABLE, 0)", src)
        self.assertNotIn("_remove_mem_hooks()", src)

        # Per-call marker (the pinpointing signal) and exception policy:
        # MemoryError swallowed silently, SystemError surfaced.
        self.assertIn('print("[OOM] " + label', src)
        self.assertIn("except MemoryError:", src)
        self.assertIn("except SystemError:", src)
        # The old noisy "print every exception type" surfacing is gone.
        self.assertNotIn("print(type(_err).__name__)", src)

        # Verbose off by default.
        self.assertIn("_OOM_VERBOSE = False", src)

        # One labelled sweep site per --oom-calls.
        self.assertEqual(src.count('oom_call("'), OOM_CALLS)

    def test_verbose_emits_per_iteration_start(self):
        src = _generate(oom_fuzz=True, oom_verbose=True)
        ast.parse(src)
        self.assertIn("_OOM_VERBOSE = True", src)
        self.assertIn('print("[OOM]   start=" + str(_start)', src)

    def test_oom_start_min_sets_sweep_lower_bound(self):
        # --oom-start-min emits _OOM_MIN_START and makes each sweep range(min, max) --
        # skipping shallow failure points (e.g. for fast targeted replay near a known start).
        src = _generate(oom_fuzz=True, oom_start_min=30)
        ast.parse(src)
        self.assertIn("_OOM_MIN_START = 30", src)
        self.assertIn("range(_OOM_MIN_START, _OOM_MAX_START)", src)
        # default (0) is the unchanged full sweep from the bottom.
        src0 = _generate(oom_fuzz=True)
        self.assertIn("_OOM_MIN_START = 0", src0)

    def test_non_oom_mode_has_no_oom_artifacts(self):
        src = _generate(oom_fuzz=False)

        ast.parse(src)
        for marker in (
            "oom_call",
            "set_nomemory",
            "_OOM_AVAILABLE",
            "_OOM_MAX_START",
            "_OOM_MIN_START",
            "_OOM_VERBOSE",
            "remove_mem_hooks",
        ):
            self.assertNotIn(marker, src, f"unexpected OOM artifact {marker!r} in non-OOM script")


class TestOOMClassFuzzGeneration(unittest.TestCase):
    """Phase 2: constructor + method sweeps for module classes (json has classes)."""

    def test_constructor_and_method_sweeps_emitted(self):
        src = _generate(
            oom_fuzz=True, module=json, module_name="json", oom_classes=2, oom_methods=3
        )
        ast.parse(src)  # valid Python
        # A constructor sweep: the class object is the swept callable.
        self.assertIn("() constructor", src)
        self.assertIn('oom_call("oc1:json.', src)
        self.assertIn("getattr(fuzz_target_module, ", src)
        # A live instance is built once (outside the sweep) for method fuzzing.
        self.assertIn('callFunc("oc1_init"', src)
        self.assertIn("is not SENTINEL_VALUE:", src)
        self.assertIn("oom_inst_oc1_", src)
        # Method sweeps run on that instance: oom_call over a bound method.
        self.assertRegex(src, r'oom_call\("oc1m\d+:json\.')
        self.assertRegex(src, r"getattr\(oom_inst_oc1_\w+, ")

    def test_oom_classes_zero_disables_class_fuzzing(self):
        src = _generate(
            oom_fuzz=True, module=json, module_name="json", oom_classes=0, oom_methods=3
        )
        ast.parse(src)
        self.assertNotIn("constructor", src)
        self.assertNotIn("oom_inst_", src)
        # function sweeps still present
        self.assertIn("oom_call(", src)

    def test_method_target_uses_safe_getattr_default(self):
        # getattr(inst, "m", None) + the harness's `func is None` guard means a
        # missing bound method degrades to a no-op sweep, never a NameError/raise.
        src = _generate(
            oom_fuzz=True, module=json, module_name="json", oom_classes=1, oom_methods=2
        )
        self.assertIn(", None)", src)  # safe getattr default on method
        self.assertIn("if not _OOM_AVAILABLE or func is None:", src)


class TestOOMSeqGeneration(unittest.TestCase):
    """Phase 4 stateful call sequences (--oom-seq)."""

    def test_seq_emits_windowed_oom_run_harness(self):
        src = _generate(oom_fuzz=True, oom_seq=True, oom_seq_len=3, oom_window=2)
        ast.parse(src)
        # The oom_run harness + the bounded-window primitive (start .. start+k).
        self.assertIn("def oom_run(label, thunk, window=_OOM_WINDOW):", src)
        self.assertIn("_OOM_WINDOW = 2", src)
        self.assertIn("_set_nomemory(_start, _start + window)", src)
        self.assertIn("_set_nomemory(_start, 0)", src)  # window==0 fallback branch
        self.assertIn('print("[OOM-SEQ] " + label', src)
        # Function sequences: a guarded multi-step thunk fed to oom_run.
        self.assertRegex(src, r"def _oom_seq_f\d+\(\):")
        self.assertRegex(src, r"oom_run\(\"f\d+:math\[")

    def test_seq_thunk_is_guarded_per_step_and_valid(self):
        # Each step is wrapped so a failing step doesn't abort the tail; the thunk must
        # contain >1 call (a real sequence) and parse.
        src = _generate(oom_fuzz=True, oom_seq=True, oom_seq_len=3)
        ast.parse(src)
        thunk = src[src.index("def _oom_seq_f1") :]
        thunk = thunk[: thunk.index("oom_run(")]
        self.assertGreaterEqual(thunk.count("except BaseException:"), 3)
        self.assertGreaterEqual(thunk.count("getattr(fuzz_target_module, "), 3)

    def test_seq_default_window_is_one(self):
        src = _generate(oom_fuzz=True, oom_seq=True)
        self.assertIn("_OOM_WINDOW = 1", src)

    def test_seq_method_chain_reuses_one_instance(self):
        # Method-chain sequence: several methods on the SAME live instance under one
        # window (the OOM-0035 write...->getvalue() shape).
        src = _generate(
            oom_fuzz=True,
            oom_seq=True,
            module=json,
            module_name="json",
            oom_classes=1,
            oom_methods=3,
            oom_seq_len=3,
        )
        ast.parse(src)
        self.assertRegex(src, r"def _oom_seq_oc1\(\):")
        self.assertRegex(src, r'oom_run\("oc1:json\.')
        # all steps target the same oom_inst_oc1_* instance (not the module)
        self.assertRegex(src, r"getattr\(oom_inst_oc1_\w+, ")
        self.assertNotIn('oom_call("oc1m', src)  # single-call method sweep replaced

    def test_seq_no_randomize_omits_per_call_window(self):
        # Default (randomize off): oom_run() calls take no per-sequence window override,
        # so the harness default (_OOM_WINDOW) applies -- output is unchanged.
        src = _generate(oom_fuzz=True, oom_seq=True, oom_seq_len=3, oom_window=2)
        calls = re.findall(r"oom_run\([^\n]*?, _oom_seq_f\d+\)", src)
        self.assertTrue(calls, "expected default 2-arg oom_run() calls")
        self.assertEqual(re.findall(r"oom_run\([^\n]*?, window=\d+\)", src), [])

    def test_seq_randomize_emits_per_sequence_window_within_bounds(self):
        random.seed(20240623)
        src = _generate(
            oom_fuzz=True, oom_seq=True, oom_seq_len=6, oom_window=8, oom_seq_randomize=True
        )
        ast.parse(src)
        windows = [int(w) for w in re.findall(r"oom_run\([^\n]*?, window=(\d+)\)", src)]
        self.assertTrue(windows, "randomize on should emit per-sequence window= kwargs")
        self.assertTrue(all(1 <= w <= 8 for w in windows), windows)

    def test_seq_randomize_varies_length_within_bounds(self):
        # Across the per-session sequences, step counts stay in [1, oom_seq_len] and (with a
        # wide bound + seed) are not all identical -> real per-sequence variety.
        random.seed(42)
        src = _generate(
            oom_fuzz=True,
            oom_seq=True,
            oom_verbose=True,  # emits a "step sN:" marker per step so we can count
            oom_seq_len=6,
            oom_window=4,
            oom_seq_randomize=True,
        )
        ast.parse(src)
        lengths = [
            len(re.findall(r"step s\d+:", body))
            for body in re.split(r"def _oom_seq_f\d+\(\):", src)[1:]
        ]
        self.assertTrue(lengths, "expected function sequences")
        self.assertTrue(all(1 <= n <= 6 for n in lengths), lengths)
        self.assertGreater(len(set(lengths)), 1, f"lengths did not vary: {lengths}")

    def test_non_seq_oom_mode_has_no_seq_artifacts(self):
        src = _generate(oom_fuzz=True, oom_seq=False)
        for marker in ("oom_run", "_OOM_WINDOW", "[OOM-SEQ]", "_oom_seq_"):
            self.assertNotIn(marker, src, f"unexpected seq artifact {marker!r} without --oom-seq")


class TestForeignOOMGeneration(unittest.TestCase):
    """--oom-foreign arms the LD_PRELOAD malloc shim (via ctypes) instead of set_nomemory."""

    def test_foreign_mode_arms_shim_via_ctypes(self):
        src = _generate(oom_fuzz=True, oom_foreign=True)
        ast.parse(src)
        # arms the shim's fusil_malloc_arm, resolved from the preloaded lib
        self.assertIn("fusil_malloc_arm", src)
        self.assertIn("ctypes.CDLL(None)", src)
        # does NOT use the _testcapi backend in foreign mode
        self.assertNotIn("from _testcapi import set_nomemory", src)
        # but still emits the shared OOM harness (aliased to _set_nomemory)
        self.assertIn("oom_call", src)
        self.assertIn("_set_nomemory", src)

    def test_default_mode_uses_testcapi_not_shim(self):
        src = _generate(oom_fuzz=True, oom_foreign=False)
        self.assertIn("from _testcapi import set_nomemory", src)
        self.assertNotIn("fusil_malloc_arm", src)


if __name__ == "__main__":
    unittest.main()
