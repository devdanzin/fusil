"""Tests for the pure stats engine (fusil/python/session_stats.py).

Pure-Python, no runtime stack -- same isolation as test_oom_dedup.
"""

import json
import os
import sys
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

from fusil.python.session_stats import SCHEMA_VERSION, SessionStats


class TestRecord(unittest.TestCase):
    def _stats(self):
        # deterministic clock so updated_at is pinned
        ticks = iter(range(1, 10_000))
        return SessionStats(started_at=0.0, clock=lambda: next(ticks))

    def test_counters_and_per_module(self):
        s = self._stats()
        s.record("json", crash=True)
        s.record("json")
        s.record("sqlite3", timeout=True)
        s.record("json", crash=True, cpu_load=True)
        self.assertEqual(s.sessions, 4)
        self.assertEqual(s.crashes, 2)
        self.assertEqual(s.timeouts, 1)
        self.assertEqual(s.cpu_load_kills, 1)
        self.assertEqual(s.modules["json"], {"hits": 3, "crashes": 2, "timeouts": 0})
        self.assertEqual(s.modules["sqlite3"], {"hits": 1, "crashes": 0, "timeouts": 1})

    def test_tsan_kinds_counted(self):
        # Slice B: --tsan sessions record their shared-object composition; non-tsan sessions
        # (tsan_kind=None) never touch the counter.
        s = self._stats()
        s.record("m", tsan_kind="target-objects")
        s.record("m", tsan_kind="target-objects", crash=True)
        s.record("m", tsan_kind="module-only")
        s.record("m")  # no tsan_kind -> not counted
        self.assertEqual(s.tsan_kinds, {"target-objects": 2, "module-only": 1})

    def test_none_module_bucketed_as_question(self):
        s = self._stats()
        s.record(None)
        self.assertIn("?", s.modules)
        self.assertEqual(s.modules["?"]["hits"], 1)

    def test_updated_at_advances_with_clock(self):
        s = self._stats()
        self.assertEqual(s.updated_at, 0.0)  # == started_at before any record
        s.record("m")
        first = s.updated_at
        s.record("m")
        self.assertGreater(s.updated_at, first)


class TestSerialization(unittest.TestCase):
    def test_to_dict_schema(self):
        s = SessionStats(
            gil_mode="1", pid=42, run_dir="python-2", started_at=5.0, clock=lambda: 9.0
        )
        s.record("m", crash=True)
        d = s.to_dict()
        self.assertEqual(d["schema"], SCHEMA_VERSION)
        for key in (
            "gil_mode",
            "pid",
            "run_dir",
            "started_at",
            "updated_at",
            "sessions",
            "crashes",
            "timeouts",
            "cpu_load_kills",
            "modules",
        ):
            self.assertIn(key, d)
        self.assertEqual(d["gil_mode"], "1")
        self.assertEqual(d["pid"], 42)
        self.assertEqual(d["sessions"], 1)

    def test_write_is_atomic_and_roundtrips(self):
        s = SessionStats(started_at=1.0, clock=lambda: 2.0)
        s.record("m", crash=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fusil_stats.json")
            s.write(path)
            # no leftover temp files (atomic replace cleaned up)
            self.assertEqual(os.listdir(tmp), ["fusil_stats.json"])
            with open(path) as fh:
                loaded = json.load(fh)
            self.assertEqual(loaded, s.to_dict())
            self.assertEqual(SessionStats.load(path), s.to_dict())


class TestMerge(unittest.TestCase):
    def test_merge_sums_and_unions(self):
        a = SessionStats(started_at=10.0, clock=lambda: 20.0)
        a.record("json", crash=True)
        b = SessionStats(started_at=5.0, clock=lambda: 30.0)
        b.record("json")
        b.record("sqlite3", timeout=True)
        merged = SessionStats.merge([a.to_dict(), b.to_dict()])
        self.assertEqual(merged["sessions"], 3)
        self.assertEqual(merged["crashes"], 1)
        self.assertEqual(merged["timeouts"], 1)
        self.assertEqual(merged["runs"], 2)
        self.assertEqual(merged["modules"]["json"], {"hits": 2, "crashes": 1, "timeouts": 0})
        self.assertEqual(merged["started_at"], 5.0)  # earliest
        self.assertEqual(merged["updated_at"], 30.0)  # latest

    def test_merge_empty(self):
        merged = SessionStats.merge([])
        self.assertEqual(merged["sessions"], 0)
        self.assertEqual(merged["runs"], 0)
        self.assertEqual(merged["modules"], {})
        self.assertIsNone(merged["started_at"])


if __name__ == "__main__":
    unittest.main()
