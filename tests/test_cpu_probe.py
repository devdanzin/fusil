"""Unit tests for fusil.process.cpu_probe.CpuProbe — the CPU-runaway detection agent.

CpuProbe polls a child process's CPU load each MAS step and, once the load stays above a
threshold for long enough, scores the session as a hit (a wedged/spinning child). All the
interesting behaviour is the ``live()`` state machine — reset timer below threshold, arm the
timer on first overload, then fire after ``max_duration`` — plus its handling of a missing
sample / ``ProcError``. We drive it with a fake ``load`` object (so no real process or
``/proc`` is read) and a patched ``time()`` clock, so the timing decisions are deterministic.
Runtime-free apart from the ``ptrace`` import the module requires to load at all.
"""

import unittest
from unittest import mock

try:
    from ptrace.linux_proc import ProcError

    from fusil.process import cpu_probe
    from fusil.process.cpu_probe import CpuProbe

    HAS_PTRACE = True
except ImportError:  # pragma: no cover - ptrace is a hard runtime dependency
    HAS_PTRACE = False

if HAS_PTRACE:
    from tests.mas_harness import FakeProject

_SKIP = "python-ptrace is required to import fusil.process.cpu_probe"


class _FakeLoad:
    """Stand-in for ProcessCpuLoad: its ``get()`` returns a fixed value or raises."""

    def __init__(self, value=None, exc=None):
        self._value = value
        self._exc = exc
        self.calls = 0

    def get(self):
        self.calls += 1
        if self._exc is not None:
            raise self._exc
        return self._value


def _probe(max_load=0.75, max_duration=10.0, max_score=1.0):
    """An initialized CpuProbe with ``send`` captured (avoids needing an active agent)."""
    probe = CpuProbe(
        FakeProject(),
        "cpu:test",
        max_load=max_load,
        max_duration=max_duration,
        max_score=max_score,
    )
    probe.init()
    probe.sent = []
    probe.send = lambda event, *args: probe.sent.append((event, args))
    return probe


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestConstruction(unittest.TestCase):
    def test_defaults(self):
        probe = CpuProbe(FakeProject(), "cpu")
        self.assertEqual(probe.max_load, 0.75)
        self.assertEqual(probe.max_duration, 10.0)
        self.assertEqual(probe.max_score, 1.0)

    def test_custom_thresholds(self):
        probe = CpuProbe(FakeProject(), "cpu", max_load=0.5, max_duration=3.0, max_score=0.8)
        self.assertEqual(probe.max_load, 0.5)
        self.assertEqual(probe.max_duration, 3.0)
        self.assertEqual(probe.max_score, 0.8)

    def test_init_resets_state(self):
        probe = _probe()
        self.assertIsNone(probe.score)
        self.assertIsNone(probe.timeout)
        self.assertIsNone(probe.load)

    def test_get_score_returns_score(self):
        probe = _probe()
        self.assertIsNone(probe.getScore())
        probe.score = 0.42
        self.assertEqual(probe.getScore(), 0.42)


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestSetPid(unittest.TestCase):
    def test_setpid_builds_process_cpu_load(self):
        probe = _probe()
        sentinel = object()
        seen = {}

        def fake_ctor(pid):
            seen["pid"] = pid
            return sentinel

        with mock.patch.object(cpu_probe, "ProcessCpuLoad", fake_ctor):
            probe.setPid(31337)
        self.assertIs(probe.load, sentinel)
        self.assertEqual(seen["pid"], 31337)

    def test_injected_load_factory_is_used(self):
        # An injected load_factory is preferred over the default ProcessCpuLoad, so setPid
        # can be exercised without touching /proc (no module patching needed).
        seen = {}
        sentinel = object()

        def factory(pid):
            seen["pid"] = pid
            return sentinel

        probe = CpuProbe(FakeProject(), "cpu", load_factory=factory)
        probe.setPid(4242)
        self.assertIs(probe.load, sentinel)
        self.assertEqual(seen["pid"], 4242)


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestLive(unittest.TestCase):
    """The overload-detection state machine."""

    def test_noop_without_load(self):
        probe = _probe()
        probe.load = None
        probe.live()
        self.assertIsNone(probe.score)
        self.assertIsNone(probe.timeout)

    def test_ignores_missing_sample(self):
        # get() returning a falsy value (None/0.0) means "no reading yet": bail, don't arm.
        for value in (None, 0.0):
            probe = _probe()
            probe.timeout = None
            probe.load = _FakeLoad(value=value)
            probe.live()
            self.assertIsNone(probe.timeout)
            self.assertIsNone(probe.score)

    def test_clears_load_on_procerror(self):
        probe = _probe()
        probe.load = _FakeLoad(exc=ProcError("process gone"))
        probe.live()
        self.assertIsNone(probe.load)
        self.assertIsNone(probe.score)

    def test_resets_timer_below_threshold(self):
        probe = _probe(max_load=0.75)
        probe.timeout = 1000.0  # an armed timer...
        probe.load = _FakeLoad(value=0.5)  # ...but load dropped back below the threshold
        probe.live()
        self.assertIsNone(probe.timeout)
        self.assertIsNone(probe.score)

    def test_arms_timer_on_first_overload(self):
        probe = _probe(max_load=0.75)
        probe.load = _FakeLoad(value=0.9)
        with mock.patch.object(cpu_probe, "time", lambda: 1000.0):
            probe.live()
        self.assertEqual(probe.timeout, 1000.0)
        self.assertIsNone(probe.score)
        self.assertEqual(probe.sent, [])  # not a hit yet
        self.assertIn(("warning", "CPU load: 90.0%"), probe.logger.records)

    def test_holds_during_grace_period(self):
        probe = _probe(max_load=0.75, max_duration=10.0)
        probe.timeout = 1000.0
        probe.load = _FakeLoad(value=0.9)
        with mock.patch.object(cpu_probe, "time", lambda: 1005.0):  # duration 5s < 10s
            probe.live()
        self.assertIsNone(probe.score)
        self.assertEqual(probe.sent, [])
        self.assertEqual(probe.timeout, 1000.0)  # timer keeps running

    def test_scores_after_sustained_overload(self):
        probe = _probe(max_load=0.75, max_duration=10.0, max_score=1.0)
        probe.timeout = 1000.0
        probe.load = _FakeLoad(value=0.9)
        with mock.patch.object(cpu_probe, "time", lambda: 1011.0):  # duration 11s >= 10s
            probe.live()
        self.assertEqual(probe.score, 1.0)
        self.assertEqual(probe.getScore(), 1.0)
        self.assertIn(("session_rename", ("cpu_load",)), probe.sent)
        self.assertIsNone(probe.load)  # detached after firing

    def test_custom_max_score_is_used(self):
        probe = _probe(max_load=0.5, max_duration=2.0, max_score=0.6)
        probe.timeout = 100.0
        probe.load = _FakeLoad(value=0.8)
        with mock.patch.object(cpu_probe, "time", lambda: 103.0):
            probe.live()
        self.assertEqual(probe.score, 0.6)


if __name__ == "__main__":
    unittest.main()
