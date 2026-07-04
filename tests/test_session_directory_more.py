"""Complementary unit tests for SessionDirectory: the filesystem-lifecycle methods.

``tests/test_session_directory.py`` already covers ``on_session_rename`` and every
``checkKeepDirectory`` branch. This file fills the remaining gaps -- ``init()``,
``changeOwner()`` (including the ``EPERM`` -> ``FusilError`` path), ``keepDirectory()``
(the rename path) and ``deinit()`` -- all on bare ``__new__`` instances with ``grp``/
``chown``/``rename``/``permissionHelp`` and the filesystem patched out. Runtime-free.
"""

import errno
import unittest
from types import SimpleNamespace
from unittest import mock

from fusil.error import FusilError
from fusil.session_directory import SessionDirectory


def _bare():
    """A SessionDirectory with just the state the lifecycle methods touch."""
    sd = SessionDirectory.__new__(SessionDirectory)
    sd.directory = "/fake/session-1"
    sd.rename_parts = []
    sd.rename_set = set()
    sd.info = lambda *a, **k: None
    sd.warning = lambda *a, **k: None
    sd.error = lambda *a, **k: None
    return sd


class TestInit(unittest.TestCase):
    """init() creates the directory and (unless only-generate) hands it to changeOwner."""

    def _wire(self, sd, *, only_generate, process_uid=None):
        sd.mkdir_calls = []
        sd.changeowner_calls = []
        sd.mkdir = lambda change_owner=True: sd.mkdir_calls.append(change_owner)
        sd.changeOwner = lambda uid: sd.changeowner_calls.append(uid)
        sd.application = lambda: SimpleNamespace(
            options=SimpleNamespace(only_generate=only_generate),
            config=SimpleNamespace(process_uid=process_uid),
        )

    def test_only_generate_mkdir_without_owner_and_returns_early(self):
        sd = _bare()
        self._wire(sd, only_generate=True, process_uid=1000)
        sd.init()
        # mkdir(not only_generate) == mkdir(False); the uid block is never reached.
        self.assertEqual(sd.mkdir_calls, [False])
        self.assertEqual(sd.changeowner_calls, [])

    def test_no_process_uid_skips_changeowner(self):
        sd = _bare()
        self._wire(sd, only_generate=False, process_uid=None)
        sd.init()
        self.assertEqual(sd.mkdir_calls, [True])
        self.assertEqual(sd.changeowner_calls, [])

    def test_process_uid_triggers_changeowner(self):
        sd = _bare()
        self._wire(sd, only_generate=False, process_uid=1000)
        sd.init()
        self.assertEqual(sd.mkdir_calls, [True])
        self.assertEqual(sd.changeowner_calls, [1000])


class TestChangeOwner(unittest.TestCase):
    """changeOwner chown()s the dir to fusil's gid; EPERM becomes a helpful FusilError,
    any other OSError propagates untouched."""

    def test_success_calls_chown_with_fusil_gid(self):
        sd = _bare()
        with (
            mock.patch("fusil.session_directory.grp") as grp_mock,
            mock.patch("fusil.session_directory.chown") as chown_mock,
        ):
            grp_mock.getgrnam.return_value = SimpleNamespace(gr_gid=42)
            sd.changeOwner(1000)
        grp_mock.getgrnam.assert_called_once_with("fusil")
        chown_mock.assert_called_once_with("/fake/session-1", 1000, 42)

    def test_non_eperm_oserror_is_reraised(self):
        sd = _bare()
        with (
            mock.patch("fusil.session_directory.grp") as grp_mock,
            mock.patch(
                "fusil.session_directory.chown",
                side_effect=OSError(errno.ENOENT, "no such dir"),
            ),
        ):
            grp_mock.getgrnam.return_value = SimpleNamespace(gr_gid=42)
            with self.assertRaises(OSError) as cm:
                sd.changeOwner(1000)
        self.assertEqual(cm.exception.errno, errno.ENOENT)

    def test_eperm_with_help_becomes_fusilerror(self):
        sd = _bare()
        sd.application = lambda: SimpleNamespace(options=SimpleNamespace(unsafe=False))
        with (
            mock.patch("fusil.session_directory.grp") as grp_mock,
            mock.patch(
                "fusil.session_directory.chown",
                side_effect=OSError(errno.EPERM, "denied"),
            ),
            mock.patch("fusil.session_directory.permissionHelp", return_value="retry as root"),
        ):
            grp_mock.getgrnam.return_value = SimpleNamespace(gr_gid=42)
            with self.assertRaises(FusilError) as cm:
                sd.changeOwner(1000)
        message = str(cm.exception)
        self.assertIn("/fake/session-1", message)
        self.assertIn("retry as root", message)
        # The original OSError is chained (raise ... from err).
        self.assertIsInstance(cm.exception.__cause__, OSError)

    def test_eperm_without_help_becomes_fusilerror_no_suffix(self):
        sd = _bare()
        sd.application = lambda: SimpleNamespace(options=SimpleNamespace(unsafe=True))
        with (
            mock.patch("fusil.session_directory.grp") as grp_mock,
            mock.patch(
                "fusil.session_directory.chown",
                side_effect=OSError(errno.EPERM, "denied"),
            ),
            mock.patch("fusil.session_directory.permissionHelp", return_value=None),
        ):
            grp_mock.getgrnam.return_value = SimpleNamespace(gr_gid=42)
            with self.assertRaises(FusilError) as cm:
                sd.changeOwner(1000)
        # No help -> no parenthesised suffix appended to the message.
        self.assertNotIn("(", str(cm.exception))


class _FakeProjectDir:
    """Stand-in for a project's Directory: records ignore()/uniqueFilename() calls."""

    def __init__(self, unique="/fake/json-segfault"):
        self.ignored = []
        self.unique_calls = []
        self._unique = unique

    def ignore(self, filename):
        self.ignored.append(filename)

    def uniqueFilename(self, name, save=True):
        self.unique_calls.append((name, save))
        return self._unique


class TestKeepDirectory(unittest.TestCase):
    """keepDirectory asks the project dir to keep the session, then optionally renames
    it from the accumulated rename_parts."""

    def test_no_rename_parts_only_ignores(self):
        sd = _bare()
        pd = _FakeProjectDir()
        sd.project = lambda: SimpleNamespace(directory=pd)
        with mock.patch("fusil.session_directory.rename") as rename_mock:
            sd.keepDirectory()
        self.assertEqual(pd.ignored, ["session-1"])
        rename_mock.assert_not_called()
        self.assertEqual(sd.directory, "/fake/session-1")

    def test_rename_parts_renames_directory(self):
        sd = _bare()
        sd.rename_parts = ["json", "segfault"]
        pd = _FakeProjectDir(unique="/fake/json-segfault")
        sd.project = lambda: SimpleNamespace(directory=pd)
        with mock.patch("fusil.session_directory.rename") as rename_mock:
            sd.keepDirectory()
        self.assertEqual(pd.ignored, ["session-1"])
        self.assertEqual(pd.unique_calls, [("json-segfault", False)])
        self.assertEqual(sd.directory, "/fake/json-segfault")
        rename_mock.assert_called_once_with("/fake/session-1", "/fake/json-segfault")


class TestDeinit(unittest.TestCase):
    """deinit keeps (and renames) or removes the directory based on checkKeepDirectory."""

    def test_keep_true_calls_keepdirectory_and_returns(self):
        sd = _bare()
        calls = []
        sd.checkKeepDirectory = lambda: True
        sd.keepDirectory = lambda: calls.append("keep")
        sd.rmtree = lambda: calls.append("rmtree")
        sd.deinit()
        self.assertEqual(calls, ["keep"])

    def test_keep_false_removes_tree(self):
        sd = _bare()
        calls = []
        sd.checkKeepDirectory = lambda: False
        sd.keepDirectory = lambda: calls.append("keep")
        sd.rmtree = lambda: calls.append("rmtree")
        sd.deinit()
        self.assertEqual(calls, ["rmtree"])


if __name__ == "__main__":
    unittest.main()
