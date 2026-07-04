"""Unit tests for fusil.linux.cpu_load — the CPU-load measurement helpers.

These classes read the running kernel's ``/proc/stat`` and per-process ``stat`` files and
turn the raw tick counters into load fractions. The *arithmetic* (idle-percent, tick deltas,
process-start reconstruction, clamping) and the *data-selection* logic (``searchLast`` picking
the freshest valid sample) are what matter and where the bugs would hide, but they are buried
behind ``ptrace.linux_proc`` readers. We inject fakes for those readers (``openProc``,
``readProcessStat``, ``getSystemBoot``) and for the sample classes themselves, so every
computation runs deterministically with no real ``/proc`` access. Runtime-free apart from the
``ptrace`` import the module requires to load at all.
"""

import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest import mock

try:
    from fusil.linux import cpu_load
    from fusil.linux.cpu_load import (
        CpuLoad,
        CpuLoadError,
        ProcessCpuLoad,
        ProcessCpuLoadValue,
        SystemCpuLoad,
        SystemCpuLoadValue,
    )

    HAS_PTRACE = True
except ImportError:  # pragma: no cover - ptrace is a hard runtime dependency
    HAS_PTRACE = False

_SKIP = "python-ptrace is required to import fusil.linux.cpu_load"


class _FakeProcStat:
    """Stand-in for the file object ``openProc('stat')`` returns: iterable of lines with a
    ``close()`` the reader is expected to call."""

    def __init__(self, lines):
        self._lines = lines
        self.closed = False

    def __iter__(self):
        return iter(self._lines)

    def close(self):
        self.closed = True


def _val(timestamp, data=True):
    """A minimal CpuLoadValue-shaped sample (only ``.timestamp``/``.data`` are read)."""
    return SimpleNamespace(timestamp=timestamp, data=data)


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestCpuLoadBase(unittest.TestCase):
    """The abstract ``CpuLoad`` base: ``isValid`` is a contract stub, ``searchLast`` is pure
    sample-selection logic driven by timestamps + an injected ``isValid``."""

    def _cpuload(self, datas, is_valid, mesure_duration=timedelta(seconds=1.0)):
        cl = CpuLoad()
        cl.datas = datas
        cl.mesure_duration = mesure_duration
        cl.isValid = is_valid  # instance override of the abstract method
        return cl

    def test_isvalid_is_abstract(self):
        with self.assertRaises(NotImplementedError):
            CpuLoad().isValid(object(), object())

    def test_searchlast_returns_single_valid_recent_item(self):
        # One sample, younger than mesure_duration so the loop skips it, but isValid -> True,
        # so the `ok is None` fallback returns datas[0].
        now = datetime(2020, 1, 1, 12, 0, 0)
        v0 = _val(now - timedelta(seconds=0.5))
        cl = self._cpuload([v0], is_valid=lambda item, current: True)
        self.assertIs(cl.searchLast(_val(now)), v0)

    def test_searchlast_returns_none_when_only_item_invalid(self):
        now = datetime(2020, 1, 1, 12, 0, 0)
        v0 = _val(now - timedelta(seconds=3))
        cl = self._cpuload([v0], is_valid=lambda item, current: False)
        self.assertIsNone(cl.searchLast(_val(now)))

    def test_searchlast_trims_older_samples_and_returns_pivot(self):
        # v0/v1 are both old + valid (loop advances ok to 1), v2 is too young (skipped).
        # ok == 1 -> datas[0:1] deleted (v0 dropped); the returned pivot is v1.
        now = datetime(2020, 1, 1, 12, 0, 0)
        v0 = _val(now - timedelta(seconds=3))
        v1 = _val(now - timedelta(seconds=2))
        v2 = _val(now - timedelta(seconds=0.5))
        cl = self._cpuload([v0, v1, v2], is_valid=lambda item, current: True)
        result = cl.searchLast(_val(now))
        self.assertIs(result, v1)
        self.assertEqual(cl.datas, [v1, v2])

    def test_searchlast_ok_zero_keeps_all_samples(self):
        # Only index 0 qualifies (ok == 0): no trimming, datas[0] returned unchanged.
        now = datetime(2020, 1, 1, 12, 0, 0)
        v0 = _val(now - timedelta(seconds=3))
        v1 = _val(now - timedelta(seconds=0.5))  # too young to qualify
        cl = self._cpuload([v0, v1], is_valid=lambda item, current: True)
        result = cl.searchLast(_val(now))
        self.assertIs(result, v0)
        self.assertEqual(cl.datas, [v0, v1])

    def test_searchlast_skips_invalid_middle_sample(self):
        # v1 old but invalid -> ok jumps to the last valid (v2); v0 trimmed.
        now = datetime(2020, 1, 1, 12, 0, 0)
        v0 = _val(now - timedelta(seconds=3), data=True)
        v1 = _val(now - timedelta(seconds=2), data=False)
        v2 = _val(now - timedelta(seconds=1.5), data=True)
        cl = self._cpuload([v0, v1, v2], is_valid=lambda item, current: item.data)
        result = cl.searchLast(_val(now))
        self.assertIs(result, v2)
        self.assertEqual(cl.datas, [v2])


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestSystemCpuLoadValue(unittest.TestCase):
    """Parsing of the ``/proc/stat`` 'cpu ' aggregate line into a list of counters."""

    def _parse(self, lines):
        fake = _FakeProcStat(lines)
        with mock.patch.object(cpu_load, "openProc", lambda name: fake):
            value = SystemCpuLoadValue()
        return value, fake

    def test_parses_cpu_line_and_closes_file(self):
        value, fake = self._parse(["cpu  10 20 30 40 50\n", "cpu0 1 2 3 4 5\n"])
        self.assertEqual(value.data, [10, 20, 30, 40, 50])
        self.assertTrue(fake.closed)
        self.assertIsInstance(value.timestamp, datetime)

    def test_negative_counters_clamped_to_zero(self):
        value, _ = self._parse(["cpu 10 -5 30 -1\n"])
        self.assertEqual(value.data, [10, 0, 30, 0])

    def test_skips_non_aggregate_lines(self):
        # Per-core 'cpuN' and other lines must be ignored; only the 'cpu ' line counts.
        value, _ = self._parse(["cpu0 99 99 99\n", "intr 5 6 7\n", "cpu 7 8 9\n"])
        self.assertEqual(value.data, [7, 8, 9])

    def test_missing_cpu_line_raises(self):
        with self.assertRaises(CpuLoadError):
            self._parse(["cpu0 1 2 3\n", "intr 5\n"])

    def test_empty_cpu_line_raises(self):
        # 'cpu ' with no counters -> data == [] -> treated as failure.
        with self.assertRaises(CpuLoadError):
            self._parse(["cpu \n"])


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestSystemCpuLoad(unittest.TestCase):
    """The system-load validity check and the ``load = 1 - idle/total`` computation."""

    def _bare(self, min_cycles=50, min_duration=timedelta(seconds=0.5)):
        s = SystemCpuLoad.__new__(SystemCpuLoad)
        s.datas = []
        s.min_cycles = min_cycles
        s.min_duration = min_duration
        s.mesure_duration = timedelta(seconds=1.0)
        return s

    def test_init_reads_initial_sample(self):
        # Full construction: __init__ reads one /proc/stat sample and seeds datas.
        fake = _FakeProcStat(["cpu 1 2 3 4\n"])
        with mock.patch.object(cpu_load, "openProc", lambda name: fake):
            s = SystemCpuLoad()
        self.assertEqual(len(s.datas), 1)
        self.assertEqual(s.datas[0].data, [1, 2, 3, 4])
        self.assertEqual(s.min_cycles, cpu_load.SYSLOAD_MIN_CYCLES)

    def test_isvalid_true_with_enough_cycles_and_duration(self):
        s = self._bare(min_cycles=50)
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(data=[0, 0, 0, 0], timestamp=now - timedelta(seconds=1))
        current = SimpleNamespace(data=[20, 20, 20, 20], timestamp=now)
        self.assertTrue(s.isValid(item, current))

    def test_isvalid_false_when_too_few_cycles(self):
        s = self._bare(min_cycles=1000)
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(data=[0, 0, 0, 0], timestamp=now - timedelta(seconds=1))
        current = SimpleNamespace(data=[1, 1, 1, 1], timestamp=now)
        self.assertFalse(s.isValid(item, current))

    def test_isvalid_false_when_duration_too_short(self):
        s = self._bare(min_cycles=1)
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(data=[0, 0, 0, 0], timestamp=now - timedelta(seconds=0.1))
        current = SimpleNamespace(data=[20, 20, 20, 20], timestamp=now)
        self.assertFalse(s.isValid(item, current))

    def test_get_computes_one_minus_idle_fraction(self):
        # diff = [10, 20, 30, 40], idle (index 3) = 40, total = 100 -> load = 0.6.
        s = self._bare()
        last = SimpleNamespace(data=[0, 0, 0, 0])
        s.searchLast = lambda current: last
        current = SimpleNamespace(data=[10, 20, 30, 40])
        with mock.patch.object(cpu_load, "SystemCpuLoadValue", lambda: current):
            load = s.get(estimate=True)
        self.assertAlmostEqual(load, 0.6)
        self.assertEqual(s.datas, [current])  # current sample stored

    def test_get_estimate_returns_none_when_no_valid_sample(self):
        s = self._bare()
        s.searchLast = lambda current: None
        with mock.patch.object(
            cpu_load, "SystemCpuLoadValue", lambda: SimpleNamespace(data=[1, 1, 1, 1])
        ):
            self.assertIsNone(s.get(estimate=True))

    def test_get_sleeps_and_retries_until_sample_available(self):
        # First searchLast miss -> sleep() then retry; second call yields a sample.
        s = self._bare()
        last = SimpleNamespace(data=[0, 0, 0, 0])
        results = [None, last]
        s.searchLast = lambda current: results.pop(0)
        slept = []
        with (
            mock.patch.object(
                cpu_load, "SystemCpuLoadValue", lambda: SimpleNamespace(data=[25, 25, 25, 25])
            ),
            mock.patch.object(cpu_load, "sleep", lambda secs: slept.append(secs)),
        ):
            load = s.get(estimate=False)
        self.assertAlmostEqual(load, 0.75)  # idle 25 / total 100
        self.assertEqual(slept, [cpu_load.SYSLOAD_SLEEP])


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestProcessCpuLoadValue(unittest.TestCase):
    """Reading a process's cumulative user+system ticks and start time."""

    def test_reads_start_time_and_tics(self):
        stat = SimpleNamespace(starttime=1000, utime=50, stime=30)
        with mock.patch.object(cpu_load, "readProcessStat", lambda pid: stat):
            value = ProcessCpuLoadValue(4242)
        self.assertEqual(value.start_time, 1000)
        self.assertEqual(value.tics, 80)
        self.assertIsInstance(value.timestamp, datetime)

    def test_unicode_decode_error_is_swallowed(self):
        def boom(pid):
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "bad byte")

        with mock.patch.object(cpu_load, "readProcessStat", boom):
            value = ProcessCpuLoadValue(1)
        # The except clause leaves the fields unset rather than crashing.
        self.assertFalse(hasattr(value, "tics"))
        self.assertFalse(hasattr(value, "start_time"))


@unittest.skipUnless(HAS_PTRACE, _SKIP)
class TestProcessCpuLoad(unittest.TestCase):
    """Process start-datetime reconstruction, validity check, and the ticks/time load calc."""

    def _bare(self, min_cycles=10, min_duration=timedelta(seconds=0.5)):
        p = ProcessCpuLoad.__new__(ProcessCpuLoad)
        p.datas = []
        p.min_cycles = min_cycles
        p.min_duration = min_duration
        p.mesure_duration = timedelta(seconds=1.0)
        p.pid = 1234
        return p

    def test_init_reconstructs_start_datetime(self):
        boot = datetime(2020, 1, 1, 0, 0, 0)
        stat = SimpleNamespace(starttime=cpu_load.HERTZ * 2, utime=0, stime=0)
        with (
            mock.patch.object(cpu_load, "readProcessStat", lambda pid: stat),
            mock.patch.object(cpu_load, "getSystemBoot", lambda: boot),
        ):
            p = ProcessCpuLoad(777)
        # starttime is HERTZ*2 ticks -> 2.0s after boot.
        self.assertEqual(p.pid, 777)
        self.assertEqual(len(p.datas), 1)
        self.assertEqual(p.start, boot + timedelta(seconds=2.0))
        self.assertEqual(p.min_cycles, cpu_load.CPULOAD_MIN_CYCLES)

    def test_isvalid_true_with_enough_tics_and_duration(self):
        p = self._bare(min_cycles=10)
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(tics=0, timestamp=now - timedelta(seconds=1))
        current = SimpleNamespace(tics=50, timestamp=now)
        self.assertTrue(p.isValid(item, current))

    def test_isvalid_false_when_too_few_tics(self):
        p = self._bare(min_cycles=100)
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(tics=0, timestamp=now - timedelta(seconds=1))
        current = SimpleNamespace(tics=5, timestamp=now)
        self.assertFalse(p.isValid(item, current))

    def test_isvalid_false_when_duration_too_short(self):
        p = self._bare(min_cycles=1)
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(tics=0, timestamp=now - timedelta(seconds=0.1))
        current = SimpleNamespace(tics=50, timestamp=now)
        self.assertFalse(p.isValid(item, current))

    def test_isvalid_false_on_missing_tics_attribute(self):
        # A sample built from a UnicodeDecodeError has no `tics` -> AttributeError -> False.
        p = self._bare()
        now = datetime(2020, 1, 1, 12, 0, 0)
        item = SimpleNamespace(timestamp=now - timedelta(seconds=1))  # no tics
        current = SimpleNamespace(tics=50, timestamp=now)
        self.assertFalse(p.isValid(item, current))

    def _get(self, p, current, previous):
        p.searchLast = lambda cur: previous
        with mock.patch.object(cpu_load, "ProcessCpuLoadValue", lambda pid: current):
            return p.get()

    def test_get_uses_delta_between_two_samples(self):
        base = datetime(2020, 1, 1, 12, 0, 0)
        p = self._bare()
        previous = SimpleNamespace(tics=50, timestamp=base)
        # Half of HERTZ ticks over 1 second -> load 0.5.
        current = SimpleNamespace(
            tics=50 + cpu_load.HERTZ // 2, timestamp=base + timedelta(seconds=1)
        )
        load = self._get(p, current, previous)
        self.assertAlmostEqual(load, 0.5)

    def test_get_estimates_from_start_when_no_previous(self):
        base = datetime(2020, 1, 1, 12, 0, 0)
        p = self._bare()
        p.start = base
        ticks = cpu_load.HERTZ  # HERTZ ticks over 2s -> load 0.5
        current = SimpleNamespace(tics=ticks, timestamp=base + timedelta(seconds=2))
        load = self._get(p, current, None)
        self.assertAlmostEqual(load, 0.5)

    def test_get_returns_none_without_previous_when_not_estimating(self):
        base = datetime(2020, 1, 1, 12, 0, 0)
        p = self._bare()
        current = SimpleNamespace(tics=10, timestamp=base)
        p.searchLast = lambda cur: None
        with mock.patch.object(cpu_load, "ProcessCpuLoadValue", lambda pid: current):
            self.assertIsNone(p.get(estimate=False))
        self.assertEqual(p.datas, [current])  # sample stored before the early return

    def test_get_clamps_load_above_one(self):
        base = datetime(2020, 1, 1, 12, 0, 0)
        p = self._bare()
        previous = SimpleNamespace(tics=0, timestamp=base)
        current = SimpleNamespace(tics=cpu_load.HERTZ * 100, timestamp=base + timedelta(seconds=1))
        self.assertEqual(self._get(p, current, previous), 1.0)

    def test_get_clamps_negative_load_to_zero(self):
        # Counter went backwards (tics delta negative) -> clamp to 0.0.
        base = datetime(2020, 1, 1, 12, 0, 0)
        p = self._bare()
        previous = SimpleNamespace(tics=100, timestamp=base)
        current = SimpleNamespace(tics=10, timestamp=base + timedelta(seconds=1))
        self.assertEqual(self._get(p, current, previous), 0.0)

    def test_get_falls_back_to_half_on_missing_tics(self):
        # current sample lacks `tics` -> AttributeError -> default load 0.5.
        base = datetime(2020, 1, 1, 12, 0, 0)
        p = self._bare()
        current = SimpleNamespace(timestamp=base)  # no tics
        load = self._get(p, current, None)
        self.assertEqual(load, 0.5)


if __name__ == "__main__":
    unittest.main()
