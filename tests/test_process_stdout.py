"""Unit tests for fusil.process.stdout.WatchStdout — the stdout crash probe wiring.

WatchStdout is the thin FileWatch subclass the Python fuzzer attaches to a child's stdout:
it opens the stdout file when the process announces it (``on_process_stdout``), drains and
scores it on exit (``on_process_exit``), and closes the handle on teardown (``deinit``).
Both handlers are agent-scoped — they only act on *their* process. WHY it matters: this is
where the textual crash detector gets connected to the fuzzed child's output.

Runtime-free: a real MTA-backed FakeProject builds the agent, the "process" is a minimal
weakref-able stub exposing ``project()``, ``send`` is intercepted, and stdout is a temp file.
"""

import os
import tempfile
import unittest

from tests.mas_harness import FakeProject

try:
    from fusil.process.stdout import WatchStdout

    HAVE_STDOUT = True
except Exception:  # pragma: no cover - defensive; stdout.py has no ptrace dependency
    HAVE_STDOUT = False


class _FakeProcess:
    """Weakref-able CreateProcess stand-in exposing only ``project()`` (what WatchStdout
    needs at construction and for its agent-identity checks)."""

    def __init__(self, project):
        self._project = project

    def project(self):
        return self._project


def _make(words=None):
    """Build a WatchStdout over a fresh FakeProject; returns (watch, process)."""
    project = FakeProject()
    proc = _FakeProcess(project)
    w = WatchStdout(proc)
    if words is not None:
        w.words = words
    return w, proc


def _tempfile(data: bytes):
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


@unittest.skipUnless(HAVE_STDOUT, "fusil.process.stdout not importable")
class TestConstruction(unittest.TestCase):
    def test_name_and_initial_state(self):
        w, proc = _make()
        self.assertEqual(w.name, "watch:stdout")
        self.assertIsNone(w.file_obj)

    def test_process_weakref_resolves(self):
        w, proc = _make()
        self.assertIs(w.process(), proc)


@unittest.skipUnless(HAVE_STDOUT, "fusil.process.stdout not importable")
class TestOnProcessStdout(unittest.TestCase):
    def test_matching_agent_opens_stdout_file(self):
        w, proc = _make()
        path = _tempfile(b"hello world\n")
        self.addCleanup(os.unlink, path)
        self.addCleanup(w.close)

        w.on_process_stdout(proc, path)
        self.assertIsNotNone(w.file_obj)
        # File was opened in binary mode.
        self.assertEqual(w.file_obj.read(), b"hello world\n")

    def test_other_agent_is_ignored(self):
        w, _ = _make()
        other = _FakeProcess(FakeProject())
        path = _tempfile(b"data\n")
        self.addCleanup(os.unlink, path)

        w.on_process_stdout(other, path)
        self.assertIsNone(w.file_obj)

    def test_stdout_then_live_scores(self):
        # After wiring stdout, a direct live() drains and scores the file.
        w, proc = _make(words={"segfault": 1.0})
        path = _tempfile(b"nothing here\na segfault happened\n")
        self.addCleanup(os.unlink, path)
        self.addCleanup(w.close)

        w.init()  # file_obj still None here (matches real activation order)
        w.sent = []
        w.send = lambda event, *a: w.sent.append((event, a))
        w.on_process_stdout(proc, path)
        w.live()
        self.assertGreaterEqual(w.getScore(), 1.0)


@unittest.skipUnless(HAVE_STDOUT, "fusil.process.stdout not importable")
class TestOnProcessExit(unittest.TestCase):
    def _wire(self, data, words):
        w, proc = _make(words=words)
        path = _tempfile(data)
        self.addCleanup(os.unlink, path)
        w.init()
        w.sent = []
        w.send = lambda event, *a: w.sent.append((event, a))
        w.on_process_stdout(proc, path)
        return w, proc

    def test_matching_agent_drains_scores_and_closes(self):
        w, proc = self._wire(b"boring\na segfault occurred\n", {"segfault": 1.0})
        w.on_process_exit(proc, 0)
        self.assertGreaterEqual(w.getScore(), 1.0)
        self.assertIn(("session_rename", (b"segfault",)), w.sent)
        # Exit handling closes the stdout handle.
        self.assertIsNone(w.file_obj)

    def test_other_agent_neither_scores_nor_closes(self):
        w, _ = self._wire(b"a segfault occurred\n", {"segfault": 1.0})
        other = _FakeProcess(FakeProject())
        w.on_process_exit(other, 0)
        # Early-return: no draining, no scoring, file left open.
        self.assertEqual(w.getScore(), 0)
        self.assertIsNotNone(w.file_obj)
        w.close()


@unittest.skipUnless(HAVE_STDOUT, "fusil.process.stdout not importable")
class TestDeinit(unittest.TestCase):
    def test_deinit_closes_file(self):
        w, proc = _make()
        path = _tempfile(b"x\n")
        self.addCleanup(os.unlink, path)
        w.on_process_stdout(proc, path)
        self.assertIsNotNone(w.file_obj)

        w.deinit()
        self.assertIsNone(w.file_obj)

    def test_deinit_is_idempotent(self):
        w, _ = _make()
        w.deinit()
        w.deinit()  # second teardown must not raise
        self.assertIsNone(w.file_obj)


if __name__ == "__main__":
    unittest.main()
