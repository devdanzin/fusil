"""Unit tests for the pure-logic core helpers: fusil.tools and fusil.score.

Runtime-free (no python-ptrace, no subprocess). These modules have doctests that do not
currently run in the suite (the doctest harness is broken), so this pins them properly.
"""

import unittest
from datetime import timedelta
from types import SimpleNamespace

from fusil.score import normalizeScore, scoreLogFunc
from fusil.tools import listDiff, makeFilename, makeUnicode, minmax, timedeltaSeconds


class TestMinmax(unittest.TestCase):
    def test_clamps_below(self):
        self.assertEqual(minmax(-2, -3, 10), -2)

    def test_clamps_above(self):
        self.assertEqual(minmax(-2, 27, 10), 10)

    def test_within_range_unchanged(self):
        self.assertEqual(minmax(-2, 0, 10), 0)


class TestListDiff(unittest.TestCase):
    def test_item_by_item(self):
        self.assertEqual(listDiff([4, 0, 3], [10, 0, 50]), [6, 0, 47])

    def test_truncates_to_shortest(self):
        self.assertEqual(listDiff([1, 2, 3], [10, 20]), [9, 18])

    def test_empty(self):
        self.assertEqual(listDiff([], []), [])


class TestTimedeltaSeconds(unittest.TestCase):
    def test_seconds_and_microseconds(self):
        self.assertAlmostEqual(timedeltaSeconds(timedelta(seconds=2, microseconds=40000)), 2.04)

    def test_minutes_and_milliseconds(self):
        self.assertAlmostEqual(timedeltaSeconds(timedelta(minutes=1, milliseconds=250)), 60.25)

    def test_days_contribute(self):
        # days are counted as 3600*24 "seconds" by this helper's (quirky) formula
        self.assertEqual(timedeltaSeconds(timedelta(days=1)), 3600 * 24)


class TestMakeUnicode(unittest.TestCase):
    def test_str_passthrough(self):
        self.assertEqual(makeUnicode("already text"), "already text")

    def test_utf8_bytes(self):
        self.assertEqual(makeUnicode("café".encode("utf8")), "café")

    def test_latin1_fallback_on_invalid_utf8(self):
        # 0xff is not valid UTF-8; must fall back to ISO-8859-1 rather than raise.
        self.assertEqual(makeUnicode(b"\xff"), "\xff")


class TestMakeFilename(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(makeFilename("Fatal error!"), "fatal_error")

    def test_collapses_and_strips_underscores(self):
        self.assertEqual(makeFilename("a   b  !!"), "a_b")

    def test_bytes_input(self):
        self.assertEqual(makeFilename(b"Fatal Error!"), b"fatal_error")


class TestNormalizeScore(unittest.TestCase):
    def test_clamps_to_unit_range(self):
        self.assertEqual(normalizeScore(5.0), 1.0)
        self.assertEqual(normalizeScore(-5.0), -1.0)

    def test_rounds_to_two_dp(self):
        self.assertEqual(normalizeScore(0.123456), 0.12)


class TestScoreLogFunc(unittest.TestCase):
    def setUp(self):
        self.obj = SimpleNamespace(info="INFO", warning="WARN", error="ERR")

    def test_none_and_zero_are_info(self):
        self.assertEqual(scoreLogFunc(self.obj, None), "INFO")
        self.assertEqual(scoreLogFunc(self.obj, 0), "INFO")

    def test_large_magnitude_is_error(self):
        self.assertEqual(scoreLogFunc(self.obj, 0.5), "ERR")
        self.assertEqual(scoreLogFunc(self.obj, -0.9), "ERR")

    def test_small_magnitude_is_warning(self):
        self.assertEqual(scoreLogFunc(self.obj, 0.1), "WARN")
        self.assertEqual(scoreLogFunc(self.obj, -0.49), "WARN")


if __name__ == "__main__":
    unittest.main()
