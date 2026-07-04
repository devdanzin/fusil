"""Unit tests for fusil.python.utils.

Pure-Python: no runtime stack, so it runs in the dev venv.
"""

import re
import time
import unittest

from fusil.python import utils


class TestFormatDuration(unittest.TestCase):
    def test_whole_seconds_keep_two_fractional_digits(self):
        # Regression: the old print_running_time sliced a fixed 4 chars off the timedelta
        # string, corrupting whole-second durations ("0:01:30" -> "0:0"). format_duration
        # must always render H:MM:SS.ss.
        self.assertEqual(utils.format_duration(90), "0:01:30.00")
        self.assertEqual(utils.format_duration(0), "0:00:00.00")

    def test_fractional_seconds_truncated_to_two_digits(self):
        self.assertEqual(utils.format_duration(90.5), "0:01:30.50")
        self.assertEqual(utils.format_duration(3661.239), "1:01:01.24")  # round(_,2)=3661.24

    def test_shape_is_always_hmmss_dot_ss(self):
        for value in (0, 1, 59.99, 60, 3600, 3661.239, 86399.5):
            self.assertRegex(utils.format_duration(value), r"^\d+:\d\d:\d\d\.\d\d$")


class TestPrintRunningTime(unittest.TestCase):
    def test_format_has_both_lines(self):
        out = utils.print_running_time(time.time())
        self.assertIn("Running time:", out)
        self.assertIn("User time:", out)
        # Leading blank line + two labelled lines, each ending in a H:MM:SS.ss duration.
        self.assertTrue(out.startswith("\n"))
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertRegex(line, r":\s+\d+:\d\d:\d\d\.\d\d$")

    def test_elapsed_total_is_rendered(self):
        out = utils.print_running_time(time.time() - 90)
        m = re.search(r"Running time:\s+(\d+:\d\d:\d\d\.\d\d)", out)
        self.assertIsNotNone(m, out)
        assert m is not None  # for type-checkers
        self.assertTrue(m.group(1).startswith("0:01:3"), out)

    def test_no_stale_pycache_helper_remains(self):
        # The parent-side remove_logging_pycache() workaround (issue #36) was removed; guard
        # against it being reintroduced without the accompanying analysis.
        self.assertFalse(hasattr(utils, "remove_logging_pycache"))


if __name__ == "__main__":
    unittest.main()
