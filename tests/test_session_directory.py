"""Unit tests for SessionDirectory.on_session_rename — the crash-dir labeling logic.

The session directory's name encodes the crash signature (module, signal, exit code, OOM
id, ...). on_session_rename normalizes, truncates, and de-dupes those parts. It's pure
string logic on rename_parts/rename_set, so we exercise it on a bare instance (no MAS,
no filesystem). Runtime-free.
"""

import unittest
from types import SimpleNamespace

from fusil.session_directory import PART_MAXLEN, SessionDirectory


def _bare_session_directory():
    """A SessionDirectory with just the state on_session_rename touches."""
    sd = SessionDirectory.__new__(SessionDirectory)
    sd.rename_parts = []
    sd.rename_set = set()
    sd.info = lambda *a, **k: None
    return sd


class TestOnSessionRename(unittest.TestCase):
    def test_simple_part_appended(self):
        sd = _bare_session_directory()
        sd.on_session_rename("json")
        self.assertEqual(sd.rename_parts, ["json"])

    def test_normalizes_disallowed_chars(self):
        sd = _bare_session_directory()
        sd.on_session_rename("xml.dom.minidom")
        sd.on_session_rename("segfault:0x10")
        self.assertEqual(sd.rename_parts, ["xml_dom_minidom", "segfault_0x10"])

    def test_truncates_long_parts(self):
        sd = _bare_session_directory()
        sd.on_session_rename("a" * (PART_MAXLEN + 25))
        self.assertEqual(len(sd.rename_parts[0]), PART_MAXLEN)

    def test_deduplicates_parts(self):
        sd = _bare_session_directory()
        sd.on_session_rename("sigsegv")
        sd.on_session_rename("sigsegv")
        self.assertEqual(sd.rename_parts, ["sigsegv"])

    def test_empty_part_ignored(self):
        sd = _bare_session_directory()
        sd.on_session_rename("")
        self.assertEqual(sd.rename_parts, [])

    def test_order_preserved_across_distinct_parts(self):
        sd = _bare_session_directory()
        for part in ("module", "segmentation_fault", "OOM-0004"):
            sd.on_session_rename(part)
        self.assertEqual(sd.rename_parts, ["module", "segmentation_fault", "OOM-0004"])


def _keep_dir(
    *,
    empty,
    empty_ignore_generated=None,
    success,
    exitcode=0,
    keep_sessions=False,
    keep_generated=False,
    only_generate=False,
    policy="absent",
):
    """A bare SessionDirectory wired for checkKeepDirectory().

    ``empty`` is isEmpty(False) (truly empty); ``empty_ignore_generated`` is isEmpty(True)
    (empty once registered generated files are ignored). A truly empty dir is also empty
    ignoring generated files, so that defaults to ``empty`` when not given.
    """
    if empty_ignore_generated is None:
        empty_ignore_generated = empty
    sd = SessionDirectory.__new__(SessionDirectory)
    sd.directory = "/fake/session-1"
    sd.rename_parts = []
    sd.rename_set = set()
    sd.info = lambda *a, **k: None
    sd.warning = lambda *a, **k: None

    def isEmpty(ignore_generated=False):
        return empty_ignore_generated if ignore_generated else empty

    sd.isEmpty = isEmpty
    sd.session = lambda: SimpleNamespace(isSuccess=lambda: success)
    options = SimpleNamespace(
        keep_sessions=keep_sessions,
        keep_generated_files=keep_generated,
        only_generate=only_generate,
    )
    application = SimpleNamespace(exitcode=exitcode, options=options)
    if policy != "absent":
        application.session_keep_policy = policy
    sd.application = lambda: application
    return sd


class TestCheckKeepDirectory(unittest.TestCase):
    """The keep/drop decision that produces (or discards) crash dirs. The MAS rewrite
    routes session teardown through this, so pin every branch."""

    def test_empty_dir_dropped_even_on_success(self):
        # The success/exitcode/keep_sessions block is guarded by `if not isEmpty(False)`,
        # so a *successful* session with an empty directory is still dropped.
        sd = _keep_dir(empty=True, success=True)
        self.assertFalse(sd.checkKeepDirectory())

    def test_nonempty_success_no_policy_kept(self):
        sd = _keep_dir(empty=False, success=True)
        self.assertTrue(sd.checkKeepDirectory())

    def test_nonempty_success_policy_keep_relabels(self):
        sd = _keep_dir(empty=False, success=True, policy=lambda s: (True, "OOM-0001"))
        self.assertTrue(sd.checkKeepDirectory())
        self.assertEqual(sd.rename_parts, ["OOM-0001"])

    def test_nonempty_success_policy_prune_drops_and_relabels(self):
        sd = _keep_dir(empty=False, success=True, policy=lambda s: (False, "OOM-0001"))
        self.assertFalse(sd.checkKeepDirectory())
        self.assertEqual(sd.rename_parts, ["OOM-0001"])

    def test_nonempty_success_policy_keep_without_label(self):
        sd = _keep_dir(empty=False, success=True, policy=lambda s: (True, None))
        self.assertTrue(sd.checkKeepDirectory())
        self.assertEqual(sd.rename_parts, [])

    def test_nonempty_fusil_error_kept(self):
        sd = _keep_dir(empty=False, success=False, exitcode=1)
        self.assertTrue(sd.checkKeepDirectory())

    def test_nonempty_keep_sessions_kept(self):
        sd = _keep_dir(empty=False, success=False, keep_sessions=True)
        self.assertTrue(sd.checkKeepDirectory())

    def test_nonempty_no_flags_dropped(self):
        sd = _keep_dir(empty=False, success=False)
        self.assertFalse(sd.checkKeepDirectory())

    def test_only_generate_keeps_empty_dir(self):
        sd = _keep_dir(empty=True, success=False, only_generate=True)
        self.assertTrue(sd.checkKeepDirectory())

    def test_keep_generated_with_nongenerated_files_kept(self):
        # keep_generated_files keeps the dir when isEmpty(ignore_generated=True) is False,
        # i.e. there are files beyond the registered generated ones.
        sd = _keep_dir(
            empty=False, empty_ignore_generated=False, success=False, keep_generated=True
        )
        self.assertTrue(sd.checkKeepDirectory())

    def test_keep_generated_only_generated_files_dropped(self):
        # A dir holding only registered generated files: isEmpty(True) is True, so the
        # keep_generated branch does NOT fire and the dir is dropped.
        sd = _keep_dir(empty=False, empty_ignore_generated=True, success=False, keep_generated=True)
        self.assertFalse(sd.checkKeepDirectory())


if __name__ == "__main__":
    unittest.main()
