"""Tests for PythonSource module-loading robustness.

Regression: a discovered target module that runs argparse/optparse on sys.argv or calls
sys.exit() at *import* time raises SystemExit, which used to propagate straight through the
fuzzer and kill it (clean exit code 2 -> "Project done" -> systemd restart, churning the
fleet). loadModule's handler now treats such a module as unloadable, while a real
KeyboardInterrupt still propagates.
"""

import os
import shutil
import sys
import tempfile
import types
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

from fusil.python.python_source import PythonSource


def _bare_source(modules_list):
    """A PythonSource with just the state on_session_start touches (no MAS/project)."""
    ps = PythonSource.__new__(PythonSource)
    ps.source_output_path = "unused.py"  # truthy -> skip session().createFilename()
    # on_session_start reads options.discover_in_target to choose runner-import vs target-subprocess
    # discovery; default off keeps this exercising the runner-import (loadModule) path.
    ps.options = types.SimpleNamespace(discover_in_target=False)
    ps.modules_list = list(modules_list)
    ps.sent = []
    ps.debug = lambda *a, **k: None
    ps.error = lambda *a, **k: None
    ps.warning = lambda *a, **k: None
    ps.send = lambda event, *a: ps.sent.append(event)
    return ps


class TestModuleImportExit(unittest.TestCase):
    def test_module_that_exits_at_import_is_skipped_not_fatal(self):
        tmpdir = tempfile.mkdtemp()
        modname = "_fusil_exit_bomb_mod"
        with open(os.path.join(tmpdir, modname + ".py"), "w") as fh:
            fh.write("import sys\nsys.exit(2)\n")  # SystemExit(2) at import time
        sys.path.insert(0, tmpdir)
        try:
            ps = _bare_source([modname])
            # Must NOT raise SystemExit out of on_session_start.
            ps.on_session_start()
            # The bomb module is treated as unloadable and dropped...
            self.assertNotIn(modname, ps.modules_list)
            # ...and with no modules left, the run ends cleanly via project_stop rather than
            # the process dying with exit code 2.
            self.assertEqual(ps.sent, ["project_stop"])
        finally:
            sys.path.remove(tmpdir)
            sys.modules.pop(modname, None)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_keyboard_interrupt_during_import_still_propagates(self):
        ps = _bare_source(["anything"])

        def _boom(_name):
            raise KeyboardInterrupt

        ps.loadModule = _boom  # a real Ctrl-C must not be swallowed as an unloadable module
        with self.assertRaises(KeyboardInterrupt):
            ps.on_session_start()


if __name__ == "__main__":
    unittest.main()
