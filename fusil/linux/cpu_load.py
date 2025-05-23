from datetime import datetime, timedelta
from os import sysconf
from time import sleep

from ptrace.linux_proc import ProcError, getSystemBoot, openProc, readProcessStat

from fusil.tools import listDiff, minmax, timedeltaSeconds


class CpuLoadError(ProcError):
    pass


# sysconf() keys: values working on Ubuntu Feisty (libc 2.5)
_SC_CLK_TCK = 2
_SC_NPROCESSORS_ONLN = 84

# max(..., 1) is for buggy SPARC glibc
NB_CPU = max(sysconf(_SC_NPROCESSORS_ONLN), 1)
HERTZ = sysconf(_SC_CLK_TCK)

SYSLOAD_MIN_CYCLES = HERTZ // 2  # 500 ms
CPULOAD_MIN_CYCLES = HERTZ // 10  # 100 ms
SYSLOAD_SLEEP = 0.500  # 500 ms


class CpuLoad:
    def __init__(self):
        self.datas = []
        self.min_duration = timedelta(seconds=0.5)
        self.mesure_duration = timedelta(seconds=1.0)

    def isValid(self, item, current):
        raise NotImplementedError()

    def searchLast(self, current):
        ok = None
        for index, item in enumerate(self.datas):
            age = current.timestamp - item.timestamp
            if self.mesure_duration < age and self.isValid(item, current):
                ok = index
        if ok is None:
            item = self.datas[0]
            if self.isValid(item, current):
                return item
            else:
                return None
        if 0 < ok:
            del self.datas[0:ok]
        return self.datas[0]


class CpuLoadValue:
    def __init__(self):
        self.timestamp = datetime.now()


class SystemCpuLoadValue(CpuLoadValue):
    def __init__(self):
        CpuLoadValue.__init__(self)
        self.data = None
        stat_file = openProc("stat")
        for data in stat_file:
            # Look for "cpu ..." line
            if not data.startswith("cpu "):
                continue
            self.data = [max(int(item), 0) for item in data.split()[1:]]
            break
        stat_file.close()
        if not self.data:
            raise CpuLoadError("Unable to get system load!")


class SystemCpuLoad(CpuLoad):
    def __init__(self):
        CpuLoad.__init__(self)
        self.min_cycles = SYSLOAD_MIN_CYCLES
        value = SystemCpuLoadValue()
        self.datas.append(value)

    def isValid(self, item, current):
        data = listDiff(item.data, current.data)
        return (self.min_cycles <= sum(data)) and (
            self.min_duration < current.timestamp - item.timestamp
        )

    def get(self, estimate=False):
        while True:
            current = SystemCpuLoadValue()
            last = self.searchLast(current)
            if last:
                break
            if estimate:
                return None
            else:
                sleep(SYSLOAD_SLEEP)

        # Store value
        self.datas.append(current)

        # Compute system load: 100% - idle percent
        data = listDiff(last.data, current.data)
        load = 1.0 - float(data[3]) / sum(data)
        return load


class ProcessCpuLoadValue(CpuLoadValue):
    def __init__(self, pid):
        CpuLoadValue.__init__(self)
        try:
            stat = readProcessStat(pid)
            self.start_time = stat.starttime
            self.tics = stat.utime + stat.stime
        except UnicodeDecodeError:
            pass


class ProcessCpuLoad(CpuLoad):
    """
    Compute process cpu usage
    """

    def __init__(self, pid):
        CpuLoad.__init__(self)
        self.min_cycles = CPULOAD_MIN_CYCLES
        self.pid = pid

        # Read first value
        value = ProcessCpuLoadValue(self.pid)
        self.datas.append(value)

        # Compute process start datetime
        boot = getSystemBoot()
        start = float(value.start_time) / HERTZ
        start = timedelta(seconds=start)
        self.start = boot + start

    def isValid(self, item, current):
        try:
            return (self.min_cycles <= current.tics - item.tics) and (
                self.min_duration < current.timestamp - item.timestamp
            )
        except AttributeError:
            return False

    def get(self, estimate=True):
        current = ProcessCpuLoadValue(self.pid)
        previous = self.searchLast(current)
        self.datas.append(current)
        try:
            tics = current.tics
            if previous:
                time = current.timestamp - previous.timestamp
                tics -= previous.tics
            else:
                if not estimate:
                    return None
                time = current.timestamp - self.start
            time = timedeltaSeconds(time)
            load = tics / (HERTZ * time)
        except AttributeError:
            load = 0.5
        return minmax(0.0, load, 1.0)
