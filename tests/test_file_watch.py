"""Unit tests for fusil.file_watch.FileWatch — the stdout crash-scoring engine.

FileWatch reads a watched file (a fuzzed child's stdout) line by line and scores it against
word/regex patterns; a high enough score marks the session a crash. It is the substrate the
Python fuzzer's WatchStdout builds on, and it had essentially no direct coverage. Runtime-free:
a real MTA-backed FakeProject constructs the agent, `send` is intercepted to capture emitted
``session_rename`` events, and file I/O uses temp files.
"""

import os
import tempfile
import unittest

from fusil.file_watch import VALID_POS, FileWatch
from tests.mas_harness import FakeProject


def _watch(*, words=None, kill_words=None, regexs=None, max_nb_line=None, start=None):
    """Build an initialized FileWatch with `send` captured into ``.sent``."""
    project = FakeProject()
    w = FileWatch(project, None, "watch:test", start=start)
    if words is not None:
        w.words = words
    if kill_words is not None:
        w.kill_words = set(kill_words)
    if max_nb_line is not None:
        w.max_nb_line = max_nb_line
    for pattern, score in regexs or ():
        w.addRegex(pattern, score)
    w.init()
    w.sent = []
    w.send = lambda event, *args: w.sent.append((event, args))
    return w


class TestConstruction(unittest.TestCase):
    def test_invalid_start_position_rejected(self):
        with self.assertRaises(ValueError):
            FileWatch(FakeProject(), None, "w", start="middle")

    def test_valid_positions(self):
        for pos in VALID_POS:
            w = FileWatch(FakeProject(), None, "w", start=pos)
            self.assertEqual(w.start, pos)

    def test_default_start_is_zero(self):
        self.assertEqual(FileWatch(FakeProject(), None, "w").start, "zero")


class TestPatternRegistration(unittest.TestCase):
    def test_add_regex_encodes_str_and_marks_recompile(self):
        w = FileWatch(FakeProject(), None, "w")
        w._need_compile = False
        w.addRegex("boom", 1.0)
        pattern, score, match = w.regexs[0]
        self.assertEqual(pattern, b"boom")
        self.assertEqual(score, 1.0)
        self.assertTrue(w._need_compile)

    def test_ignore_regex_appends_search_callable(self):
        w = FileWatch(FakeProject(), None, "w")
        w.ignoreRegex("skip.*me")
        self.assertEqual(len(w.ignore), 1)
        self.assertTrue(w.ignore[0](b"skip and me"))
        self.assertFalse(w.ignore[0](b"unrelated"))

    def test_compile_patterns_wraps_words_with_word_boundaries(self):
        w = _watch(words={"error": 0.3})
        # "error" matches as a whole token but not as a substring of "errors".
        self.assertIsNone(w.processLine(b"errors everywhere"))
        self.assertEqual(w.score, 0.0)
        self.assertIsNone(w.processLine(b"an error occurred"))
        self.assertEqual(w.score, 0.3)


class TestProcessLineScoring(unittest.TestCase):
    def test_word_match_adds_score_and_renames(self):
        w = _watch(words={"segfault": 1.0})
        w.processLine(b"got a segfault here")
        self.assertEqual(w.score, 1.0)
        self.assertIn(("session_rename", (b"segfault",)), w.sent)

    def test_highest_absolute_score_wins(self):
        w = _watch(words={"warning": 0.1, "critical": 1.0})
        w.processLine(b"warning: critical failure")
        self.assertEqual(w.score, 1.0)

    def test_non_matching_line_scores_nothing(self):
        w = _watch(words={"segfault": 1.0})
        self.assertIsNone(w.processLine(b"all good here"))
        self.assertEqual(w.score, 0.0)
        self.assertEqual(w.sent, [])

    def test_ignored_line_skips_scoring(self):
        w = _watch(words={"error": 1.0})
        w.ignoreRegex("ast.Assert")  # emulate the WatchStdout false-positive filter
        # Recompile ignore is separate from patterns; ignore is consulted directly.
        self.assertIsNone(w.processLine(b"ast.Assert() error"))
        self.assertEqual(w.score, 0.0)

    def test_kill_word_returns_KILL(self):
        w = _watch(words={"error": 0.3}, kill_words={"MemoryError"})
        self.assertEqual(w.processLine(b"MemoryError: out of memory"), "KILL")

    def test_cleanup_func_applied_before_matching(self):
        w = _watch(words={"boom": 1.0})
        w.cleanup_func = lambda line: line.replace(b"XXX", b"boom")
        w.processLine(b"a XXX happened")
        self.assertEqual(w.score, 1.0)

    def test_empty_line_after_cleanup_is_skipped(self):
        w = _watch(words={"boom": 1.0})
        w.cleanup_func = lambda line: b""
        self.assertIsNone(w.processLine(b"boom"))
        self.assertEqual(w.score, 0.0)

    def test_long_output_increments_and_renames_once(self):
        w = _watch(words={}, max_nb_line=(2, 0.5))
        w.processLine(b"line one")
        w.processLine(b"line two")  # total_line hits 2 -> trigger
        self.assertEqual(w.score, 0.5)
        self.assertIn(("session_rename", ("long_output",)), w.sent)
        # Only fires once (max_nb_line cleared).
        w.processLine(b"line three")
        self.assertEqual(w.score, 0.5)


class TestSessionStopAndScore(unittest.TestCase):
    def test_get_score_returns_accumulated(self):
        w = _watch(words={"boom": 1.0})
        w.processLine(b"boom")
        self.assertEqual(w.getScore(), 1.0)

    def test_min_nb_line_penalty_applied(self):
        w = _watch(words={})
        w.min_nb_line = (5, -0.2)
        w.total_line = 2
        w.on_session_stop()
        self.assertAlmostEqual(w.score, -0.2)

    def test_min_nb_line_not_applied_when_enough_lines(self):
        w = _watch(words={})
        w.min_nb_line = (5, -0.2)
        w.total_line = 10
        w.on_session_stop()
        self.assertEqual(w.score, 0.0)


class TestFileReading(unittest.TestCase):
    def _watch_over(self, data: bytes, read_size=4096):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        os.write(fd, data)
        os.close(fd)
        project = FakeProject()
        w = FileWatch(project, None, "w")
        w.read_size = read_size
        w.setFileObject(open(path, "rb"))
        self.addCleanup(w.close)
        w.init()
        return w

    def test_readlines_splits_complete_lines(self):
        w = self._watch_over(b"alpha\nbeta\ngamma\n")
        self.assertEqual(list(w.readlines()), [b"alpha", b"beta", b"gamma"])

    def test_readlines_buffers_partial_trailing_line(self):
        w = self._watch_over(b"one\ntwo\npartial", read_size=1)
        # The trailing 'partial' has no newline yet, so it is buffered, not yielded.
        self.assertEqual(list(w.readlines()), [b"one", b"two"])

    def test_live_accumulates_score_from_file(self):
        w = self._watch_over(b"nothing\na segfault occurred\nmore\n")
        w.words = {"segfault": 1.0}
        w.init()  # recompile with the new words + reset position
        w.sent = []
        w.send = lambda event, *a: w.sent.append((event, a))
        w.live()
        self.assertGreaterEqual(w.getScore(), 1.0)

    def test_close_is_idempotent(self):
        w = self._watch_over(b"x\n")
        w.close()
        w.close()  # second close must not raise
        self.assertIsNone(w.file_obj)

    def test_from_filename_builds_watch(self):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        os.write(fd, b"hello\n")
        os.close(fd)
        w = FileWatch.fromFilename(FakeProject(), path)
        self.addCleanup(w.close)
        w.init()
        self.assertEqual(list(w.readlines()), [b"hello"])


if __name__ == "__main__":
    unittest.main()
