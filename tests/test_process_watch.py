"""Unit tests for fusil.process.watch.WatchProcess — the exit-status crash scorer.

WatchProcess is the ProjectAgent that turns a fuzzed child's *termination* into a session
score: a signal death or non-zero exit is interesting, a timeout is maximally interesting,
and a clean exit is boring. It had almost no direct coverage. WHY it matters: this is the
non-textual half of crash detection (WatchStdout is the textual half), so its status→score
mapping decides whether a real segfault/abort is surfaced.

Runtime-free: a real MTA-backed FakeProject constructs the agent, ``send`` is intercepted to
capture emitted ``session_stop`` events, the process is a lightweight fake (weakref-able,
exposing ``poll()`` / ``timeout_reached`` / ``process.pid``), and the CpuProbe is swapped for
a recorder so no ``/proc`` reads happen. WatchProcess is imported through python-ptrace
(``cpu_probe`` → ``ptrace.linux_proc``), so the tests skip-guard on that import.
"""

import unittest
from types import SimpleNamespace

from tests.mas_harness import FakeProject

try:
    from fusil.process.watch import (
        DEFAULT_EXITCODE_SCORE,
        DEFAULT_SIGNAL_SCORE,
        DEFAULT_TIMEOUT_SCORE,
        WatchProcess,
    )

    HAVE_WATCH = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_WATCH = False


class _RecordingCpu:
    """Stand-in for CpuProbe: truthy (so ``if self.cpu:`` passes) and records setPid()."""

    def __init__(self):
        self.set_pids = []

    def setPid(self, pid):
        self.set_pids.append(pid)


class _FakeProcess:
    """Minimal CreateProcess stand-in: weakref-able and exposing the attributes WatchProcess
    reads — ``project()``, ``name``, ``process.pid``, ``poll()`` and ``timeout_reached``."""

    def __init__(self, project, name="target", pid=4321, timeout_reached=False, poll_status=None):
        self._project = project
        self.name = name
        self.process = SimpleNamespace(pid=pid)
        self.timeout_reached = timeout_reached
        self.poll_status = poll_status

    def project(self):
        return self._project

    def poll(self):
        return self.poll_status


def _make(*, stub_cpu=True, **proc_kwargs):
    """Build an initialized WatchProcess plus its fake process.

    Score-tuning kwargs (exitcode_score/signal_score/default_score/timeout_score) are peeled
    off and forwarded to the constructor; the rest configure the fake process. The process is
    pinned onto the agent (``_keepalive``) so the internal weakref stays live for the test.
    """
    score_kwargs = {
        k: proc_kwargs.pop(k)
        for k in ("exitcode_score", "signal_score", "default_score", "timeout_score")
        if k in proc_kwargs
    }
    project = FakeProject()
    proc = _FakeProcess(project, **proc_kwargs)
    w = WatchProcess(proc, **score_kwargs)
    w._keepalive = proc
    if stub_cpu:
        w.cpu = _RecordingCpu()
    w.init()
    w.sent = []
    w.send = lambda event, *args: w.sent.append((event, args))
    return w, proc


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestConstruction(unittest.TestCase):
    def test_name_derived_from_process(self):
        w, _ = _make(name="json")
        self.assertEqual(w.name, "watch:json")

    def test_default_scores(self):
        w, _ = _make()
        self.assertEqual(w.exitcode_score, DEFAULT_EXITCODE_SCORE)
        self.assertEqual(w.signal_score, DEFAULT_SIGNAL_SCORE)
        self.assertEqual(w.timeout_score, DEFAULT_TIMEOUT_SCORE)
        self.assertEqual(w.default_score, 0.0)

    def test_custom_scores_stored(self):
        w, _ = _make(exitcode_score=0.2, signal_score=0.9, default_score=0.1, timeout_score=0.7)
        self.assertEqual(w.exitcode_score, 0.2)
        self.assertEqual(w.signal_score, 0.9)
        self.assertEqual(w.default_score, 0.1)
        self.assertEqual(w.timeout_score, 0.7)

    def test_registers_agent_and_cpu_probe(self):
        # The watch registers itself, and its CpuProbe also registers, both on the project.
        project = FakeProject()
        proc = _FakeProcess(project)
        w = WatchProcess(proc)
        self.assertIn(w, project.registered)
        # Two agents were registered: the watch and its cpu probe.
        self.assertEqual(len(project.registered), 2)

    def test_injected_cpu_probe_is_used_and_no_probe_constructed(self):
        # An injected cpu_probe is used verbatim; the default CpuProbe (which reaches /proc via
        # setPid) is not constructed, so only the watch itself registers on the project.
        project = FakeProject()
        proc = _FakeProcess(project)
        stub = _RecordingCpu()
        w = WatchProcess(proc, cpu_probe=stub)
        self.assertIs(w.cpu, stub)
        self.assertEqual(project.registered, [w])


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestInit(unittest.TestCase):
    def test_init_resets_score_and_pid(self):
        w, _ = _make()
        w.score = 0.5
        w.pid = 99
        w.init()
        self.assertIsNone(w.score)
        self.assertIsNone(w.pid)


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestComputeScore(unittest.TestCase):
    def test_positive_exit_code_returns_exitcode_score(self):
        w, _ = _make(exitcode_score=0.5)
        self.assertEqual(w.computeScore(1), 0.5)
        self.assertEqual(w.computeScore(42), 0.5)

    def test_negative_status_is_signal_death(self):
        # A signal death is reported as a negative status (-signum), e.g. -11 for SIGSEGV.
        w, _ = _make(signal_score=1.0)
        self.assertEqual(w.computeScore(-11), 1.0)
        self.assertEqual(w.computeScore(-6), 1.0)

    def test_zero_status_returns_default_score(self):
        # Clean exit: distinguish from 0.0 by using a non-zero default_score sentinel.
        w, _ = _make(default_score=0.3)
        self.assertEqual(w.computeScore(0), 0.3)

    def test_none_status_returns_none(self):
        w, _ = _make()
        self.assertIsNone(w.computeScore(None))

    def test_timeout_reached_returns_timeout_score(self):
        w, _ = _make(timeout_reached=True, timeout_score=1.0)
        self.assertEqual(w.computeScore(0), 1.0)

    def test_timeout_takes_priority_over_signal(self):
        # Timeout is checked before the status branches: even a signal death scores as timeout.
        w, _ = _make(timeout_reached=True, timeout_score=0.8, signal_score=1.0)
        self.assertEqual(w.computeScore(-11), 0.8)

    def test_timeout_takes_priority_over_none_status(self):
        w, _ = _make(timeout_reached=True, timeout_score=0.8)
        self.assertEqual(w.computeScore(None), 0.8)


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestProcessDone(unittest.TestCase):
    def test_sets_score_emits_session_stop_and_clears_pid(self):
        w, _ = _make(exitcode_score=0.5)
        w.pid = 4321
        w.processDone(7)
        self.assertEqual(w.score, 0.5)
        self.assertEqual(w.sent, [("session_stop", ())])
        self.assertIsNone(w.pid)

    def test_uses_signal_score_for_signal_death(self):
        w, _ = _make(signal_score=1.0)
        w.pid = 4321
        w.processDone(-11)
        self.assertEqual(w.score, 1.0)

    def test_getscore_reflects_processDone(self):
        w, _ = _make(exitcode_score=0.5)
        self.assertIsNone(w.getScore())
        w.pid = 1
        w.processDone(1)
        self.assertEqual(w.getScore(), 0.5)


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestLive(unittest.TestCase):
    def test_no_pid_is_noop(self):
        w, _ = _make(poll_status=1)
        w.pid = None
        w.live()
        self.assertIsNone(w.score)
        self.assertEqual(w.sent, [])

    def test_process_still_running_does_not_score(self):
        # poll() returning None means "still alive": no processDone, pid retained.
        w, _ = _make(poll_status=None)
        w.pid = 4321
        w.live()
        self.assertIsNone(w.score)
        self.assertEqual(w.pid, 4321)
        self.assertEqual(w.sent, [])

    def test_process_done_scores_and_stops(self):
        w, _ = _make(poll_status=5, exitcode_score=0.5)
        w.pid = 4321
        w.live()
        self.assertEqual(w.score, 0.5)
        self.assertIsNone(w.pid)
        self.assertEqual(w.sent, [("session_stop", ())])

    def test_process_killed_by_signal_scores_signal(self):
        w, _ = _make(poll_status=-9, signal_score=1.0)
        w.pid = 4321
        w.live()
        self.assertEqual(w.score, 1.0)


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestEventHandlers(unittest.TestCase):
    def test_on_process_create_matching_agent_captures_pid_and_prepares(self):
        w, proc = _make(pid=1234)
        w.on_process_create(proc)
        self.assertEqual(w.pid, 1234)
        # prepareProcess wired the pid through to the cpu probe.
        self.assertEqual(w.cpu.set_pids, [1234])

    def test_on_process_create_other_agent_is_ignored(self):
        w, _ = _make(pid=1234)
        other = SimpleNamespace(process=SimpleNamespace(pid=777))
        w.on_process_create(other)
        self.assertIsNone(w.pid)
        self.assertEqual(w.cpu.set_pids, [])

    def test_on_session_start_with_pid_prepares(self):
        w, _ = _make(pid=1234)
        w.pid = 4321
        w.on_session_start()
        self.assertEqual(w.cpu.set_pids, [4321])

    def test_on_session_start_without_pid_is_noop(self):
        w, _ = _make()
        w.pid = None
        w.on_session_start()
        self.assertEqual(w.cpu.set_pids, [])

    def test_prepare_process_without_cpu_probe_is_safe(self):
        w, _ = _make()
        w.cpu = None
        w.pid = 4321
        w.prepareProcess()  # must not raise


@unittest.skipUnless(HAVE_WATCH, "fusil runtime stack (python-ptrace) not importable")
class TestDeinit(unittest.TestCase):
    def test_deinit_clears_pid(self):
        w, _ = _make()
        w.pid = 4321
        w.deinit()
        self.assertIsNone(w.pid)


if __name__ == "__main__":
    unittest.main()
