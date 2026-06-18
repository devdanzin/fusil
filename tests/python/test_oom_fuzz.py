"""Tests for OOM (out-of-memory) fuzzing mode code generation (Phase 1).

These verify that ``--oom-fuzz`` makes ``WritePythonCode`` emit the set_nomemory
boilerplate, the ``oom_call`` dense-sweep harness, and per-function sweep sites,
and that none of that appears when the mode is off (gating / regression).

The fixture builds a ``MagicMock`` options object with the few real-typed
attributes the generator needs; it does not depend on the (currently stale)
``test_write_python_code`` fixture.
"""

import ast
import math
import os
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
    o.oom_calls = OOM_CALLS
    o.oom_verbose = oom_verbose
    # General generation knobs
    o.fuzz_exceptions = False
    o.test_private = False
    o.no_numpy = True
    o.no_tstrings = True
    o.functions_number = 5
    o.classes_number = 0
    o.objects_number = 0
    o.methods_number = 2
    # JIT options (WriteJITCode is constructed unconditionally); OOM mode never
    # dispatches to it, so legacy defaults are fine.
    o.jit_fuzz = False
    o.jit_external_references = True
    o.jit_mode = "legacy"
    o.jit_correctness_testing = False
    o.jit_loop_iterations = 100
    o.jit_hostile_prob = 0.1
    o.jit_fuzz_classes = False
    o.jit_fuzz_ast_mutation = False
    o.jit_wrap_statements = False
    o.jit_pattern_name = "ALL"
    return o


def _generate(oom_fuzz, oom_verbose=False):
    """Generate a fuzzing script against the ``math`` module and return its source."""
    parent = MagicMock()
    parent.options = _make_options(oom_fuzz, oom_verbose)
    parent.filenames = ["/bin/sh"]
    fd, path = tempfile.mkstemp(suffix="_oom_test.py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            parent, path, math, "math",
            threads=False, _async=False, plugin_manager=None,
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
        self.assertIn("range(_OOM_MAX_START)", src)
        self.assertIn("_remove_mem_hooks()", src)

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

    def test_non_oom_mode_has_no_oom_artifacts(self):
        src = _generate(oom_fuzz=False)

        ast.parse(src)
        for marker in (
            "oom_call",
            "set_nomemory",
            "_OOM_AVAILABLE",
            "_OOM_MAX_START",
            "_OOM_VERBOSE",
            "remove_mem_hooks",
        ):
            self.assertNotIn(marker, src, f"unexpected OOM artifact {marker!r} in non-OOM script")


if __name__ == "__main__":
    unittest.main()
