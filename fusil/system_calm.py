from time import sleep, time

from fusil.error import FusilError
from fusil.linux.cpu_load import SystemCpuLoad


class SystemCalm:
    def __init__(self, max_load, sleep_second, load=None, clock=None, sleeper=None):
        # `load`/`clock`/`sleeper` are injectable for testing (a fake load source, monotonic
        # clock, and no-op sleep). Defaults preserve the original behaviour: a real
        # SystemCpuLoad (reads /proc/stat in its constructor) and the module-global time()/
        # sleep() -- resolved inside wait(), so both stay monkeypatchable too.
        self.load = load if load is not None else SystemCpuLoad()
        self.max_load = max_load
        self.sleep_second = sleep_second
        self._clock = clock
        self._sleeper = sleeper
        self.first_message = 3.0
        self.repeat_message = 5.0
        self.max_wait = 60 * 5  # seconds (5 minutes)

    def wait(self, agent):
        clock = self._clock or time
        sleeper = self._sleeper or sleep
        first_message = False
        start = clock()
        next_message = clock() + self.first_message
        while True:
            load = self.load.get(estimate=False)
            if load <= self.max_load:
                break
            duration = clock() - start
            if next_message < clock():
                first_message = True
                next_message = clock() + self.repeat_message
                agent.error(
                    "Wait until system load is under %.1f%% since %.1f seconds (current: %.1f%%)..."
                    % (self.max_load * 100, duration, load * 100)
                )
            elif not first_message:
                first_message = True
                agent.info(
                    "Wait until system load is under %.1f%% (current: %.1f%%)..."
                    % (self.max_load * 100, load * 100)
                )
            if self.max_wait <= duration:
                raise FusilError(
                    "Unable to calm down system load after "
                    "%.1f seconds (current load: %.1f%% > max: %.1f%%)"
                    % (duration, load * 100, self.max_load * 100)
                )
            sleeper(self.sleep_second)
        if first_message:
            duration = clock() - start
            agent.info(
                "System is now calm after %.1f seconds (current load: %.1f%%)"
                % (duration, load * 100)
            )
