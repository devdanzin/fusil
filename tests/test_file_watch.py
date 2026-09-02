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

    def test_synthetic_systemerror_signatures_ignored_but_real_still_scores(self):
        # The Python fuzzer sets up SystemError as a 1.0 crash-word and ignores fusil's OWN
        # synthetic signatures (the bomb-message family + plugin raise_SystemError). A
        # caught+printed synthetic SystemError must NOT score (so the session isn't
        # stopped/kept), while a genuine target SystemError still does.
        w = _watch(words={"SystemError": 1.0})
        # the exact production patterns (core bomb family + a cereggii-plugin signature)
        w.ignoreRegex(
            r"fusil (bomb|iter bomb|superbomb|fileno bomb|hidden name|descriptor (get|set)"
            r"|stateful hash)"
        )
        w.ignoreRegex("C-API level error simulation")
        for line in (
            b"SystemError: fusil hidden name: __module__",
            b"SystemError: fusil superbomb via __getitem__",
            b"SystemError: fusil stateful hash",
            b"SystemError: Exception from weird X: C-API level error simulation",
        ):
            self.assertIsNone(w.processLine(line))
        self.assertEqual(w.score, 0.0)
        # A genuine, differently-worded SystemError is still a hit.
        w.processLine(b"SystemError: null argument to internal routine")
        self.assertEqual(w.score, 1.0)

    def test_kill_word_returns_KILL(self):
        w = _watch(words={"error": 0.3}, kill_words={"MemoryError"})
        self.assertEqual(w.processLine(b"MemoryError: out of memory"), "KILL")

    def test_new_uninit_marker_lines_ignored_but_real_still_scores(self):
        # The --new-uninit region prints "[NEW-UNINIT] poking <TypeName>" per poked type.
        # The type name collides with detection words: "SystemError" is a 1.0 hit word and
        # "MemoryError" is a kill word. Without the ignore filter, "[NEW-UNINIT] poking
        # MemoryError" would return KILL and drop a genuinely-crashing session. The core
        # ignore regex (mirrored from fusil.python.Fuzzer) must skip every marker line.
        w = _watch(words={"SystemError": 1.0}, kill_words={"MemoryError"})
        w.ignoreRegex(r"^\[NEW-UNINIT\] ")
        for line in (
            b"[NEW-UNINIT] entering uninitialized-object region",
            b"[NEW-UNINIT] discovered 115 candidate types",
            b"[NEW-UNINIT] poking SystemError",  # collides with the SystemError hit word
            b"[NEW-UNINIT] poking MemoryError",  # collides with the MemoryError kill word
            b"[NEW-UNINIT] region complete",
        ):
            self.assertIsNone(w.processLine(line))
        self.assertEqual(w.score, 0.0)
        self.assertEqual(w.sent, [])
        # Real signatures on their own lines are unaffected: SystemError still scores, and a
        # genuine MemoryError still kills.
        w.processLine(b"SystemError: null argument to internal routine")
        self.assertEqual(w.score, 1.0)
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


class TestBombSignaturesAreIgnored(unittest.TestCase):
    """Every "fusil ..." exception the bomb objects raise must be ignored, not scored.

    These are the harness's OWN hostile objects proving the target propagates exceptions --
    never a target crash. Several are raised as SystemError, which is a 1.0 word, so a
    signature missing from the ignore regex does not merely add noise: it manufactures
    crashes. `instancecheck` (added with the metaclass bomb) was missing and kept 7 sessions
    in a single PyPy fleet.
    """

    def test_ignore_regex_covers_every_raised_bomb_signature(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent
        # The alternation fusil/python/__init__.py installs, kept as one source of truth.
        pattern = re.compile(
            r"fusil (bomb|iter bomb|superbomb|fileno bomb|hidden name|descriptor (get|set)"
            r"|stateful hash|instancecheck|junk return|monitoring callback bomb)"
        )
        sources = [
            root / "fusil" / "python" / "samples" / "bomb_objects.py",
            root / "fusil" / "python" / "write_python_code.py",
        ]
        raised = set()
        for path in sources:
            for line in path.read_text().splitlines():
                if "raise " not in line and "return " not in line:
                    continue
                for match in re.findall(r'"(fusil [^"%]+)', line):
                    raised.add(match.strip())
        self.assertTrue(raised, "found no bomb signatures to check -- did the raise sites move?")
        uncovered = sorted(sig for sig in raised if not pattern.search(sig))
        self.assertEqual(
            uncovered,
            [],
            "these bomb signatures are raised but not in the ignore regex in "
            "fusil/python/__init__.py, so they will be scored as target crashes: "
            + ", ".join(uncovered),
        )


class TestTracebackEchoIgnored(unittest.TestCase):
    """A traceback is the target quoting ITSELF; neither half of it may score as a crash.

    A routine fuzz traceback through ``concurrent/futures/_base.py`` kept a crash dir in a
    PyPy fleet twice, via two different lines of the same traceback:

      * the frame line   ``File ".../logging/__init__.py", line 1536, in critical``
      * the source line  ``LOGGER.critical('Future %s in unexpected state: %s',``

    ``critical`` is a 1.0 word, so either alone scores the session 100%. Both are ignored; a
    real critical-level MESSAGE (``CRITICAL:root:...``) matches neither and still scores.

    The frame-line rule requires the comma that Python tracebacks put before ``in``.
    faulthandler writes ``line N in func`` WITHOUT one, so a genuine fatal-signal report is
    untouched -- covered by the last test here.
    """

    FRAME_LINE = r'^\s*File "[^"]*", line \d+, in '
    SOURCE_LINE = r"\.critical\("

    def _watch_with_rules(self):
        w = _watch(words={"critical": 1.0})
        w.ignoreRegex(self.FRAME_LINE)
        w.ignoreRegex(self.SOURCE_LINE)
        return w

    def test_echoed_source_line_is_ignored(self):
        """Shape 2: the offending source, echoed below the frame line."""
        w = self._watch_with_rules()
        self.assertIsNone(
            w.processLine(b"    LOGGER.critical('Future %s in unexpected state: %s',")
        )
        self.assertEqual(w.score, 0.0)

    def test_traceback_frame_line_is_ignored(self):
        """Shape 1: the frame line, whose FUNCTION name is the scored word."""
        w = self._watch_with_rules()
        self.assertIsNone(
            w.processLine(b'  File "/usr/lib/pypy3.11/logging/__init__.py", line 1536, in critical')
        )
        self.assertEqual(w.score, 0.0)

    def test_a_real_critical_message_still_scores(self):
        w = self._watch_with_rules()
        w.processLine(b"CRITICAL:root:the target said something critical")
        self.assertEqual(w.score, 1.0)

    def test_bdb_tracer_lines_are_ignored(self):
        """bdb echoes the VALUE of every traced event; its repr may hold a scored word."""
        w = _watch(words={"systemerror": 1.0})
        w.ignoreRegex(r"^(\+\+\+|---|!!!) ")
        self.assertIsNone(w.processLine(b"+++ return <class 'SystemError'>"))
        self.assertEqual(w.score, 0.0)
        w.processLine(b"SystemError: the target actually raised one")
        self.assertEqual(w.score, 1.0)

    def test_faulthandler_stack_lines_are_not_swallowed(self):
        """faulthandler writes `line N in func` with NO comma; only real tracebacks have one.

        The frame-line rule must not reach faulthandler's stack, which is how a genuine
        fatal-signal crash is reported.
        """
        w = self._watch_with_rules()
        w.processLine(b'  File "/tmp/session/source.py", line 1360 in critical')
        self.assertEqual(w.score, 1.0)


class TestWarningSourceEchoIgnored(unittest.TestCase):
    """`warnings` echoes the source of whatever frame it fired in; that source may score.

    The default warning formatter prints two lines -- a header naming a file and line, and
    then that line's SOURCE, verbatim:

        /.../logging/__init__.py:1536: RuntimeWarning: coroutine '...' was never awaited
          self._log(CRITICAL, msg, args, **kwargs)

    So an un-awaited coroutine collected while `logging` happens to be on the stack echoes
    `logging`'s own source, and the `CRITICAL` in it is the level CONSTANT being passed as an
    argument -- not a diagnostic. This is a third, distinct route to the same 1.0 word as the
    traceback shapes above, and the traceback rules do not cover it: the line is neither a
    `File "...", line N, in ...` frame nor a `.critical(` call. 14 kept dirs in one PyPy
    fleet came in this way.

    The rule matches the constant only in an argument position, so a real formatted record
    and English prose both still score.
    """

    ARG_CONSTANT = r"[(,]\s*CRITICAL\s*[),]"

    def _watch_with_rule(self):
        w = _watch(words={"critical": 1.0})
        w.ignoreRegex(self.ARG_CONSTANT)
        return w

    def test_logging_source_echo_is_ignored(self):
        for line in (
            b"  self._log(CRITICAL, msg, args, **kwargs)",
            b"  if self.isEnabledFor(CRITICAL):",
            b"        self.log(CRITICAL, msg, *args, **kwargs)",
        ):
            with self.subTest(line=line):
                w = self._watch_with_rule()
                self.assertIsNone(w.processLine(line))
                self.assertEqual(w.score, 0.0)

    def test_a_real_record_or_prose_still_scores(self):
        for line in (
            b"CRITICAL:root:something exploded",
            b"CRITICAL: target failed",
            b"a critical error occurred in the target",
        ):
            with self.subTest(line=line):
                w = self._watch_with_rule()
                w.processLine(line)
                self.assertEqual(w.score, 1.0)


class TestCookiejarWarningIgnored(unittest.TestCase):
    """http.cookiejar's own "bug!" warning must not push a boring session over the threshold.

    The message is the target's benign diagnostic for a malformed cookie -- routine input for
    a fuzzer -- but it contains the "bug" word (0.10). On its own that is harmless; combined
    with another weak signal it kept 6 dirs in one PyPy fleet.
    """

    def test_cookiejar_warning_is_ignored_but_a_real_hit_still_scores(self):
        w = _watch(words={"bug": 0.10, "segfault": 1.0})
        w.ignoreRegex(r"http\.cookiejar bug!")
        self.assertIsNone(w.processLine(b"x.py:1369: UserWarning: http.cookiejar bug!"))
        self.assertEqual(w.score, 0.0)
        w.processLine(b"got a segfault here")
        self.assertEqual(w.score, 1.0)
