"""Unit tests for fusil.process.prepare -- the fuzzed-child preparation run in the
preexec_fn (after fork(), before exec()).

Three functions live here, all security-critical because they run while still privileged:

- ``changeUserGroup`` drops root to the configured process user/group and *verifies the
  drop actually took effect* -- a silent no-op is treated as fatal (raises ``ChildError``)
  so a fuzzed file-write can never run as root.
- ``limitResources`` applies the rlimit caps (memory / core / nproc / niceness).
- ``prepareProcess`` orchestrates: chown the workdir, drop privileges, chdir, check the
  program is executable, then limit resources.

Runtime-free: every OS-level call (setuid/setgid/setgroups/getuid/getgid, chdir/chown/
access) and every rlimit helper is mocked, so nothing is actually dropped, changed, or
limited. prepare.py does NOT depend on python-ptrace, so no skip guard is needed (mirrors
tests/python/test_process_limits.py, which this file complements without duplicating -- the
memory-cap gating tests there are not repeated here).
"""

import unittest
from errno import EACCES, EPERM
from types import SimpleNamespace
from unittest.mock import patch

from fusil.process import prepare
from fusil.process.prepare import ChildError, changeUserGroup, limitResources, prepareProcess


# --------------------------------------------------------------------------- helpers
def _config(**kw):
    defaults = dict(
        process_uid=None,
        process_gid=None,
        process_user=None,
        fusil_max_memory=0,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _options(**kw):
    defaults = dict(unsafe=True, fast=True)
    defaults.update(kw)
    return SimpleNamespace(**defaults)


# =========================================================================== changeUserGroup
class TestChangeUserGroupNoop(unittest.TestCase):
    def test_both_none_is_noop(self):
        """--unsafe: neither uid nor gid configured -> nothing is dropped."""
        with (
            patch.object(prepare, "setuid") as su,
            patch.object(prepare, "setgid") as sg,
            patch.object(prepare, "setgroups") as sgr,
        ):
            self.assertIsNone(changeUserGroup(_config(), _options()))
            su.assert_not_called()
            sg.assert_not_called()
            sgr.assert_not_called()


class TestChangeUserGroupSuccess(unittest.TestCase):
    def test_gid_only_success(self):
        with (
            patch.object(prepare, "setgroups") as sgr,
            patch.object(prepare, "setgid") as sg,
            patch.object(prepare, "setuid") as su,
            patch.object(prepare, "getgid", return_value=1001),
            patch.object(prepare, "getuid", return_value=0),
        ):
            # No exception means the drop verified clean.
            self.assertIsNone(changeUserGroup(_config(process_gid=1001), _options()))
            sgr.assert_called_once_with([1001])
            sg.assert_called_once_with(1001)
            su.assert_not_called()

    def test_uid_and_gid_success_order(self):
        with (
            patch.object(prepare, "setgroups"),
            patch.object(prepare, "setgid") as sg,
            patch.object(prepare, "setuid") as su,
            patch.object(prepare, "getgid", return_value=1001),
            patch.object(prepare, "getuid", return_value=1002),
        ):
            self.assertIsNone(
                changeUserGroup(_config(process_uid=1002, process_gid=1001), _options())
            )
            sg.assert_called_once_with(1001)
            su.assert_called_once_with(1002)

    def test_setgroups_failure_is_swallowed(self):
        # setgroups is best-effort: an OSError there must NOT abort as long as the
        # authoritative setgid/effectiveness checks pass.
        with (
            patch.object(prepare, "setgroups", side_effect=OSError(EPERM, "nope")),
            patch.object(prepare, "setgid") as sg,
            patch.object(prepare, "getgid", return_value=1001),
        ):
            self.assertIsNone(changeUserGroup(_config(process_gid=1001), _options()))
            sg.assert_called_once_with(1001)


class TestChangeUserGroupFailure(unittest.TestCase):
    def test_setgid_raises_aborts(self):
        with (
            patch.object(prepare, "setgroups"),
            patch.object(prepare, "setgid", side_effect=OSError(EPERM, "nope")),
            # Effective gid still root -> second error appended too.
            patch.object(prepare, "getgid", return_value=0),
            patch.object(prepare, "permissionHelp", return_value=None),
        ):
            with self.assertRaises(ChildError) as ctx:
                changeUserGroup(_config(process_gid=1001), _options())
            self.assertIn("group to 1001", str(ctx.exception))

    def test_silent_gid_failure_is_fatal(self):
        # The security-critical case: setgid() "succeeds" (no raise) but the effective gid
        # did not change. This MUST be treated as a failed drop.
        with (
            patch.object(prepare, "setgroups"),
            patch.object(prepare, "setgid"),  # no raise
            patch.object(prepare, "getgid", return_value=0),  # still root!
            patch.object(prepare, "permissionHelp", return_value=None),
        ):
            with self.assertRaises(ChildError) as ctx:
                changeUserGroup(_config(process_gid=1001), _options())
            self.assertIn("effective gid", str(ctx.exception))

    def test_setuid_raises_aborts(self):
        with (
            patch.object(prepare, "setuid", side_effect=OSError(EPERM, "nope")),
            patch.object(prepare, "getuid", return_value=0),
            patch.object(prepare, "permissionHelp", return_value=None),
        ):
            with self.assertRaises(ChildError) as ctx:
                changeUserGroup(_config(process_uid=1002), _options())
            self.assertIn("user to 1002", str(ctx.exception))

    def test_silent_uid_failure_is_fatal(self):
        with (
            patch.object(prepare, "setuid"),  # no raise
            patch.object(prepare, "getuid", return_value=0),  # still root!
            patch.object(prepare, "permissionHelp", return_value=None),
        ):
            with self.assertRaises(ChildError) as ctx:
                changeUserGroup(_config(process_uid=1002), _options())
            self.assertIn("effective uid", str(ctx.exception))

    def test_permission_help_appended_to_message(self):
        with (
            patch.object(prepare, "setuid"),
            patch.object(prepare, "getuid", return_value=0),
            patch.object(prepare, "permissionHelp", return_value="retry as root"),
        ):
            with self.assertRaises(ChildError) as ctx:
                changeUserGroup(_config(process_uid=1002), _options())
            self.assertIn("(retry as root)", str(ctx.exception))


# =========================================================================== limitResources
class TestLimitResources(unittest.TestCase):
    """Complements tests/python/test_process_limits.py (which pins the memory-cap gating);
    here we cover the *other* branches: niceness, the fusil-memory reset, core dumps, and
    the user-process cap."""

    def _process(self, **kw):
        defaults = dict(max_memory=0, core_dump=False, max_user_process=0)
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def _run(self, process, config, options):
        with (
            patch.object(prepare, "beNice") as be_nice,
            patch.object(prepare, "limitMemory") as limit_memory,
            patch.object(prepare, "allowCoreDump") as allow_core,
            patch.object(prepare, "limitUserProcess") as limit_nproc,
        ):
            limitResources(process, config, options)
            return SimpleNamespace(
                beNice=be_nice,
                limitMemory=limit_memory,
                allowCoreDump=allow_core,
                limitUserProcess=limit_nproc,
            )

    def test_benice_called_when_not_fast(self):
        m = self._run(self._process(), _config(), _options(fast=False))
        m.beNice.assert_called_once_with()

    def test_benice_skipped_when_fast(self):
        m = self._run(self._process(), _config(), _options(fast=True))
        m.beNice.assert_not_called()

    def test_fusil_memory_reset_when_no_child_cap(self):
        # max_memory == 0 but the fusil process itself has a cap -> reset it with -1.
        m = self._run(self._process(max_memory=0), _config(fusil_max_memory=500), _options())
        m.limitMemory.assert_called_once_with(-1)

    def test_no_memory_call_when_nothing_to_reset(self):
        m = self._run(self._process(max_memory=0), _config(fusil_max_memory=0), _options())
        m.limitMemory.assert_not_called()

    def test_core_dump_allowed_when_enabled(self):
        m = self._run(self._process(core_dump=True), _config(), _options())
        m.allowCoreDump.assert_called_once_with(hard=True)

    def test_core_dump_not_touched_when_disabled(self):
        m = self._run(self._process(core_dump=False), _config(), _options())
        m.allowCoreDump.assert_not_called()

    def test_user_process_cap_applied(self):
        m = self._run(
            self._process(max_user_process=64),
            _config(process_user="fusil"),
            _options(),
        )
        m.limitUserProcess.assert_called_once_with(64, hard=True)

    def test_user_process_cap_skipped_without_process_user(self):
        m = self._run(
            self._process(max_user_process=64),
            _config(process_user=None),
            _options(),
        )
        m.limitUserProcess.assert_not_called()


# =========================================================================== prepareProcess
class _FakeProc:
    """Minimal CreateProcess stand-in for prepareProcess: exposes project()/application(),
    a working directory, and current_arguments[0] (the program to exec)."""

    def __init__(self, directory="/work", program="/bin/python", config=None, options=None):
        self._directory = directory
        self.current_arguments = [program]
        self._config = config if config is not None else _config()
        self._options = options if options is not None else _options()

    def project(self):
        return SimpleNamespace(config=self._config)

    def application(self):
        return SimpleNamespace(options=self._options)

    def getWorkingDirectory(self):
        return self._directory


class TestPrepareProcess(unittest.TestCase):
    def _patches(self, **overrides):
        """Patch every OS-level dependency of prepareProcess with harmless defaults.
        chdir/access succeed, chown is a no-op, changeUserGroup/limitResources are
        swapped for recorders. Override any via kwargs (a side_effect or return_value)."""
        cm = {
            "chdir": patch.object(prepare, "chdir"),
            "chown": patch.object(prepare, "chown"),
            "access": patch.object(prepare, "access", return_value=True),
            "changeUserGroup": patch.object(prepare, "changeUserGroup"),
            "limitResources": patch.object(prepare, "limitResources"),
            "getpwuid": patch.object(
                prepare, "getpwuid", return_value=SimpleNamespace(pw_name="tester")
            ),
            # Non-None so the "(... help)" message-append branches are exercised on the
            # EACCES/non-executable error paths.
            "permissionHelp": patch.object(prepare, "permissionHelp", return_value="retry as root"),
        }
        started = {name: p.start() for name, p in cm.items()}
        for p in cm.values():
            self.addCleanup(p.stop)
        for name, value in overrides.items():
            # value is applied as the mock's return/side effect via configure.
            started[name].configure_mock(**value)
        return started

    def test_happy_path_unsafe(self):
        m = self._patches()
        proc = _FakeProc(directory="/work", program="/bin/python")
        prepareProcess(proc)
        m["changeUserGroup"].assert_called_once()
        m["chdir"].assert_called_once_with("/work")
        m["access"].assert_called_once_with("/bin/python", prepare.X_OK)
        m["limitResources"].assert_called_once()
        # No privilege drop configured -> no chown.
        m["chown"].assert_not_called()

    def test_chown_when_uid_and_gid_configured(self):
        m = self._patches()
        cfg = _config(process_uid=1002, process_gid=1001)
        proc = _FakeProc(directory="/work", config=cfg)
        prepareProcess(proc)
        m["chown"].assert_called_once_with("/work", 1002, 1001)

    def test_chown_failure_is_nonfatal(self):
        m = self._patches(chown={"side_effect": OSError(EPERM, "nope")})
        cfg = _config(process_uid=1002, process_gid=1001)
        proc = _FakeProc(directory="/work", config=cfg)
        # A chown failure prints a warning but must NOT abort preparation.
        prepareProcess(proc)
        m["limitResources"].assert_called_once()

    def test_chdir_eacces_raises_childerror(self):
        self._patches(chdir={"side_effect": OSError(EACCES, "denied")})
        proc = _FakeProc(directory="/forbidden")
        with self.assertRaises(ChildError):
            prepareProcess(proc)

    def test_chdir_other_oserror_is_reraised(self):
        # A non-EACCES chdir error propagates as the original OSError, not ChildError.
        self._patches(chdir={"side_effect": OSError(2, "missing")})
        proc = _FakeProc(directory="/gone")
        with self.assertRaises(OSError) as ctx:
            prepareProcess(proc)
        self.assertNotIsInstance(ctx.exception, ChildError)
        self.assertEqual(ctx.exception.errno, 2)

    def test_non_executable_program_raises_childerror(self):
        m = self._patches(access={"return_value": False})
        proc = _FakeProc(program="/bin/not-exec")
        with self.assertRaises(ChildError):
            prepareProcess(proc)
        # Resources are never limited once the exec check fails.
        m["limitResources"].assert_not_called()

    def test_limit_resources_called_last_on_success(self):
        m = self._patches()
        proc = _FakeProc()
        prepareProcess(proc)
        # changeUserGroup (drop) must happen before limitResources.
        self.assertTrue(m["changeUserGroup"].called)
        self.assertTrue(m["limitResources"].called)


if __name__ == "__main__":
    unittest.main()
