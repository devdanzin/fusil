"""Tests for the --sys-monitoring (PEP 669) hostile-callback region code generation.

Pure generation tests (no target execution): build an options object with --sys-monitoring on,
generate a script, and assert the emitted region is present, valid Python, and self-contained
(guards sys.monitoring, acquires + releases tool ids, registers hostile callbacks, sets global +
local events, and runs instrumented targets) -- and that none of it appears when the mode is off.
Mirrors test_tsan_generation / test_oom_fuzz.
"""

import ast
import os
import sys
import tempfile
import unittest
from types import ModuleType

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))  # repo root -> import fusil.*
sys.path.insert(0, os.path.join(SCRIPT_DIR, ".."))  # tests/ -> import python._test_options

from unittest.mock import MagicMock

from python._test_options import make_test_options

from fusil.python.write_python_code import WritePythonCode


def _module():
    mod = ModuleType("monmod")

    def helper(*a):
        return a

    mod.helper = helper
    return mod


def _generate(**overrides):
    o = make_test_options(no_numpy=True, no_tstrings=True, **overrides)
    parent = MagicMock()
    parent.options = o
    parent.filenames = ["/bin/sh"]
    fd, path = tempfile.mkstemp(suffix="_mon_test.py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            parent, path, _module(), "monmod", threads=False, _async=False, plugin_manager=None
        )
        writer.generate_fuzzing_script()
        with open(path) as fp:
            return fp.read()
    finally:
        os.unlink(path)


class TestMonitoringGeneration(unittest.TestCase):
    def test_off_by_default(self):
        src = _generate()
        self.assertNotIn("sys.monitoring hostile-callback region", src)
        self.assertNotIn("_mon_run", src)

    def test_region_emitted_when_enabled(self):
        src = _generate(sys_monitoring=True)
        ast.parse(src)  # valid Python
        self.assertIn("# --- sys.monitoring hostile-callback region (--sys-monitoring) ---", src)
        self.assertIn("import sys as _mon_sys", src)
        # guarded against interpreters without sys.monitoring
        self.assertIn('_mon = getattr(_mon_sys, "monitoring", None)', src)
        self.assertIn("if _mon is None:", src)
        self.assertIn("def _mon_run():", src)
        self.assertIn("[MONITORING] sys.monitoring region complete", src)

    def test_hostile_callback_and_lifecycle_emitted(self):
        src = _generate(sys_monitoring=True)
        # tool-id lifecycle
        self.assertIn("_mon.use_tool_id(", src)
        self.assertIn("_mon.free_tool_id(", src)
        # hostile callback: raise / DISABLE / junk / re-entrant state mutation from inside dispatch
        self.assertIn("def _mon_cb(", src)
        self.assertIn("raise ValueError(", src)
        self.assertIn("return _mon.DISABLE", src)
        self.assertIn("_mon.register_callback(", src)
        self.assertIn("_mon.restart_events()", src)
        # events are set globally + locally on instrumented target code
        self.assertIn("_mon.set_events(", src)
        self.assertIn("_mon.set_local_events(", src)
        # the second tool (multi-tool dispatch is the fragile area)
        self.assertIn("_TID2", src)
        self.assertIn('_mon.use_tool_id(_cand, "fusil2")', src)

    def test_targets_include_generic_and_module_functions(self):
        src = _generate(sys_monitoring=True)
        self.assertIn("def _mon_target(", src)  # generic instrumented loop
        self.assertIn("for _name in list(dir(fuzz_target_module)):", src)  # module's own functions


if __name__ == "__main__":
    unittest.main()
