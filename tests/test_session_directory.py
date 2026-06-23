"""Unit tests for SessionDirectory.on_session_rename — the crash-dir labeling logic.

The session directory's name encodes the crash signature (module, signal, exit code, OOM
id, ...). on_session_rename normalizes, truncates, and de-dupes those parts. It's pure
string logic on rename_parts/rename_set, so we exercise it on a bare instance (no MAS,
no filesystem). Runtime-free.
"""

import unittest

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


if __name__ == "__main__":
    unittest.main()
