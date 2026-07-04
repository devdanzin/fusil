"""Unit tests for fusil.system_calm.SystemCalm — the "wait until the box is idle" gate.

Before spawning a fuzzed child, the fuzzer blocks in ``SystemCalm.wait`` until the system CPU
load drops under a threshold, escalating log messages (info once, then repeated errors) and
giving up with a ``FusilError`` after ``max_wait`` seconds. The decision logic (break/continue,
message escalation, timeout) is what matters; the actual load reading and wall-clock sleeping
are side effects. Runtime-free: ``SystemCpuLoad`` is replaced with an injected fake load queue,
``time`` is a fake clock, and ``sleep`` advances that clock, so the loop is fully deterministic
with no real I/O or waiting.
"""

import os
import unittest
from unittest import mock

from fusil.error import FusilError
from fusil.system_calm import SystemCalm


class FakeClock:
    """A monotonic fake clock; ``advance`` is wired to the patched ``sleep`` so time only
    passes when the loop sleeps (as it does in reality)."""

    def __init__(self, start=1000.0):
        self.now = start

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeLoad:
    """Stand-in for ``SystemCpuLoad``: returns queued load values (the last value repeats so a
    persistently-busy system can be modelled), and records the ``estimate`` kwarg per call."""

    def __init__(self, loads):
        self._loads = list(loads)
        self.calls = []

    def get(self, estimate=False):
        self.calls.append(estimate)
        if len(self._loads) > 1:
            return self._loads.pop(0)
        return self._loads[0]


class FakeAgent:
    """Captures the info/error log calls ``wait`` makes on the driving agent."""

    def __init__(self):
        self.infos = []
        self.errors = []

    def info(self, message):
        self.infos.append(message)

    def error(self, message):
        self.errors.append(message)


class _CalmTest(unittest.TestCase):
    def make_calm(self, loads, *, max_load=0.5, sleep_second=1.0, start=1000.0):
        """Build a SystemCalm with SystemCpuLoad/time/sleep patched; returns (sc, clock, load)."""
        clock = FakeClock(start)
        fake_load = FakeLoad(loads)
        for target, new in (
            ("fusil.system_calm.SystemCpuLoad", mock.Mock(return_value=fake_load)),
            ("fusil.system_calm.time", clock.time),
            ("fusil.system_calm.sleep", clock.advance),
        ):
            patcher = mock.patch(target, new)
            patcher.start()
            self.addCleanup(patcher.stop)
        sc = SystemCalm(max_load, sleep_second)
        return sc, clock, fake_load


class TestConstruction(_CalmTest):
    def test_init_stores_parameters_and_defaults(self):
        sc, _clock, fake_load = self.make_calm([0.1], max_load=0.7, sleep_second=2.5)
        self.assertEqual(sc.max_load, 0.7)
        self.assertEqual(sc.sleep, 2.5)
        self.assertIs(sc.load, fake_load)
        self.assertEqual(sc.first_message, 3.0)
        self.assertEqual(sc.repeat_message, 5.0)
        self.assertEqual(sc.max_wait, 60 * 5)


class TestWaitImmediateCalm(_CalmTest):
    def test_returns_immediately_when_load_under_threshold(self):
        sc, clock, _load = self.make_calm([0.1], max_load=0.5)
        agent = FakeAgent()
        sc.wait(agent)
        self.assertEqual(agent.infos, [])
        self.assertEqual(agent.errors, [])
        # No sleeping happened, so the clock did not move.
        self.assertEqual(clock.now, 1000.0)

    def test_load_equal_to_threshold_counts_as_calm(self):
        # `load <= self.max_load`, so the boundary value must not block.
        sc, _clock, _load = self.make_calm([0.5], max_load=0.5)
        agent = FakeAgent()
        sc.wait(agent)
        self.assertEqual(agent.infos, [])
        self.assertEqual(agent.errors, [])

    def test_load_read_with_estimate_false(self):
        sc, _clock, fake_load = self.make_calm([0.1], max_load=0.5)
        sc.wait(FakeAgent())
        # wait() must poll the *real* (non-estimated) load exactly once here.
        self.assertEqual(fake_load.calls, [False])


class TestWaitEscalation(_CalmTest):
    def test_info_then_calm_message_on_transient_load(self):
        # High once, then calm: one "waiting" info up front, one "now calm" info at the end.
        sc, _clock, _load = self.make_calm([0.9, 0.1], max_load=0.5, sleep_second=1.0)
        agent = FakeAgent()
        sc.wait(agent)
        self.assertEqual(len(agent.infos), 2)
        self.assertIn("Wait until system load is under", agent.infos[0])
        self.assertIn("System is now calm", agent.infos[1])
        self.assertEqual(agent.errors, [])

    def test_error_repeated_when_load_persists_past_first_message(self):
        # sleep advances 4s/iter and first_message is 3.0s, so the 2nd iteration crosses the
        # threshold and escalates from info to error before the load finally drops.
        sc, _clock, _load = self.make_calm([0.9, 0.9, 0.1], max_load=0.5, sleep_second=4.0)
        agent = FakeAgent()
        sc.wait(agent)
        self.assertEqual(len(agent.errors), 1)
        self.assertIn("Wait until system load is under", agent.errors[0])
        self.assertIn("since", agent.errors[0])
        # Still ends with the "now calm" info once the load drops.
        self.assertIn("System is now calm", agent.infos[-1])


class TestWaitTimeout(_CalmTest):
    def test_raises_fusilerror_after_max_wait(self):
        sc, _clock, _load = self.make_calm([0.9], max_load=0.5, sleep_second=5.0)
        sc.max_wait = 10  # keep the deterministic loop short
        agent = FakeAgent()
        with self.assertRaises(FusilError) as ctx:
            sc.wait(agent)
        self.assertIn("Unable to calm down system load", str(ctx.exception))

    def test_timeout_still_logs_before_raising(self):
        sc, _clock, _load = self.make_calm([0.9], max_load=0.5, sleep_second=5.0)
        sc.max_wait = 10
        agent = FakeAgent()
        with self.assertRaises(FusilError):
            sc.wait(agent)
        # The first waiting message is emitted before the timeout fires.
        self.assertTrue(agent.infos or agent.errors)


@unittest.skipUnless(
    os.path.exists("/proc/stat"), "real SystemCpuLoad needs /proc/stat (Linux only)"
)
class TestRealConstructionSmoke(unittest.TestCase):
    """One unpatched construction to prove the real SystemCpuLoad wiring imports and runs; the
    load *value* is real system state, so nothing about it is asserted."""

    def test_constructs_with_real_cpu_load(self):
        from fusil.linux.cpu_load import SystemCpuLoad

        sc = SystemCalm(0.5, 0.5)
        self.assertIsInstance(sc.load, SystemCpuLoad)


if __name__ == "__main__":
    unittest.main()
