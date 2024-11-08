import sys
from fusil.project_agent import ProjectAgent
from ptrace.os_tools import HAS_PROC
if HAS_PROC:
    from ptrace.linux_proc import (
        ProcError, readProcessStatm, searchProcessByName)
from ptrace.process_tools import dumpProcessInfo
RUNNING_WINDOWS = sys.platform == 'win32'
if HAS_PROC:
    from os import stat
    from fusil.process.cpu_probe import CpuProbe
elif not RUNNING_WINDOWS:
    from os import kill
from errno import ESRCH, ENOENT


class AttachProcessPID(ProjectAgent):
    def __init__(self, project, pid, name=None):
        if not name:
            name = "pid:%s" % pid
        ProjectAgent.__init__(self, project, name)
        if RUNNING_WINDOWS:
            raise NotImplementedError(
                "AttachProcessPID is not supported on Windows")
        self.death_score = 1.0
        self.show_exit = True   # needed by the debugger
        self.max_memory = 100*1024*1024
        self.memory_score = 1.0
        self.debugger = project.debugger
        self.dbg_process = None
        if HAS_PROC and project.config.use_cpu_probe:
            self.cpu = CpuProbe(project, "%s:cpu" % self.name)
        else:
            self.warning("CpuProbe is not available on your OS")
            self.cpu = None
        if pid:
            self.setPid(pid)
        else:
            self.pid = None

    def init(self):
        self.score = 0.0

    def on_project_stop(self):
        if self.dbg_process:
            self.dbg_process.detach()
            self.dbg_process = None

    def setPid(self, pid):
        self.pid = pid
        dumpProcessInfo(self.info, self.pid)
        if self.cpu:
            self.cpu.setPid(pid)
        if not self.dbg_process:
            self.dbg_process = self.debugger.tracePID(self, pid)

    def live(self):
        if self.pid is None:
            return
        if not self.checkAlive():
            return
        if self.max_memory:
            if not self.checkMemory():
                return

    def checkAlive(self):
        if RUNNING_WINDOWS:
            raise NotImplementedError()

        if self.dbg_process:
            status = self.debugger.pollPID(self.pid)
            if status is None:
                return True
        elif HAS_PROC:
            try:
                stat('/proc/%s' % self.pid)
                return True
            except OSError as err:
                if err.errno != ENOENT:
                    raise
        else:
            try:
                kill(self.pid, 0)
                return True
            except OSError as err:
                if err.errno != ESRCH:
                    raise
        self.error("Process %s disappeared" % self.pid)
        self.stop(self.death_score)
        return False

    def checkMemory(self):
        if not HAS_PROC:
            return True
        try:
            memory = readProcessStatm(self.pid)[0]
        except ProcError as error:
            self.error(error)
            self.stop()
            return False
        if memory < self.max_memory:
            return True
        self.error("Memory limit reached: %s > %s" % (
            memory, self.max_memory))
        self.stop(self.memory_score)
        return False

    def stop(self, score=None):
        if score:
            self.score = score
        self.pid = None

    def getScore(self):
        return self.score

class AttachProcess(AttachProcessPID):
    def __init__(self, project, process_name):
        AttachProcessPID.__init__(self, project, None, "attach_process:%s" % process_name)
        self.process_name = process_name
        if not HAS_PROC:
            # Missing searchProcessByName() function
            raise NotImplementedError(
                "AttachProcess is not supported on your OS")

    def init(self):
        AttachProcessPID.init(self)
        self.pid = None

    def on_session_start(self):
        pid = searchProcessByName(self.process_name)
        self.send('process_pid', self, pid)
        self.setPid(pid)

