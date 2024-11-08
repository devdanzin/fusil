from ptrace.os_tools import HAS_PTRACE
from ptrace.signames import signalName

from fusil.process.watch import DEFAULT_SIGNAL_SCORE
from fusil.project_agent import ProjectAgent

if HAS_PTRACE:
    from errno import EPERM
    from signal import SIGCHLD, SIGTRAP

    from ptrace import PtraceError
    from ptrace.binding import ptrace_traceme
    from ptrace.debugger import DebuggerError as PtraceDebuggerError
    from ptrace.debugger import (NewProcessEvent, ProcessExit, ProcessSignal,
                                 PtraceDebugger)

    from fusil.unsafe import permissionHelp

class DebuggerError(Exception):
    pass

# Status for "process terminated abnormally"
ABNORMAL_STATUS = 1

from signal import SIGABRT, SIGFPE, SIGSEGV

FATAL_SIGNALS = set((SIGFPE, SIGSEGV, SIGABRT))
try:
    from signal import SIGBUS
    FATAL_SIGNALS.add(SIGBUS)
except ImportError:
    pass

class Debugger(ProjectAgent):
    def __init__(self, project):
        ProjectAgent.__init__(self, project, "dbg")
        self.debugger = None
        self.enabled = (HAS_PTRACE and project.config.use_debugger)
        self.fusil_processes = {}

        if self.enabled:
            self.error("Use python-ptrace debugger")
            self.debugger = PtraceDebugger()
            if project.config.debugger_trace_forks:
                try:
                    self.debugger.traceFork()
                    self.warning("Debugger trace process forks")
                except PtraceDebuggerError as err:
                    self.error("Unable to trace forks: %s" % err)
        else:
            self.error("Debugger disabled")

    def disable(self):
        if not self.enabled:
            return
        self.warning("Disable the debugger")
        self.enabled = False
        self.debugger = None

    def attachPID(self, agent, pid):
        if not self.enabled:
            raise DebuggerError("Debugger is not enabled")
        try:
            ptrace_process = self.debugger[pid]
        except KeyError:
            ptrace_process = self.debugger.addProcess(pid, True)
            ptrace_process.cont()
        self.registerProcess(agent, ptrace_process)
        return ptrace_process

    def registerProcess(self, agent, process):
        if process in self.fusil_processes:
            return
        self.fusil_processes[process] = agent

    def detach(self, ptrace_process):
        ptrace_process.detach()
        del self.fusil_processes[ptrace_process]

    def pollPID(self, pid):
        event = self.debugger.waitProcessEvent(pid, blocking=False)
        if event:
            return self.useProcessEvent(event)
        else:
            return None

    def useProcessEvent(self, event):
        if isinstance(event, ProcessSignal):
            self.processSignal(event)
            event.process.cont(event.signum)
            return None

        if isinstance(event, ProcessExit):
            return self.processExit(event)

        if isinstance(event, NewProcessEvent):
            new_process = event.process
            self.warning("New process: %s" % new_process)
            new_process.cont()
            return None

        raise event

    def processExit(self, event):
        # Get the Fusil process agent
        fusil_process = self.getFusilProcess(event.process)

        # Create exit status
        if event.signum is not None:
            status = -event.signum
        elif event.exitcode is not None:
            status = event.exitcode
        else:
            status = ABNORMAL_STATUS

        # Display the exit status?
        if fusil_process.show_exit:
            message = str(event)
            if event.signum or (event.exitcode is None):
                # killed by a signal or abnormal exit
                log = self.error
            elif event.exitcode:
                log = self.warning
            else:
                log = self.info
            log(message)
            if event.exitcode:
                fusil_process.send('session_rename', 'exitcode%s' % event.exitcode)
            elif event.signum:
                name = signalName(event.signum)
                name = name.lower()
                fusil_process.send('session_rename', name)
            fusil_process.send("process_exit", fusil_process, status)
        return status

    def getFusilProcess(self, ptrace_process):
        return self.fusil_processes[ptrace_process]

    def processSignal(self, event):
        if event.signum in (SIGCHLD, SIGTRAP):
            # Ignore these signals
            return
        fusil_process = self.getFusilProcess(event.process)
        if not fusil_process.show_exit:
            return
        if event.signum in FATAL_SIGNALS:
            fusil_process.score = DEFAULT_SIGNAL_SCORE
        event.display(self.error)
        reason = event.reason
        if reason:
            fusil_process.send('session_rename', reason.name)

    def tracePID(self, agent, pid):
        if not self.enabled:
            return None
        try:
            process = self.debugger.addProcess(pid, False)
            self.registerProcess(agent, process)
            process.cont()
        except PtraceError as err:
            if err.errno == EPERM:
                msg = "You are not allowed to trace the process %s: permission denied or process already traced" % pid
            else:
                msg = "Process can no be attached! %s" % err
            help = permissionHelp(self.application().options)
            if help:
                msg += " (%s)" % help
            raise DebuggerError("ERROR: %s" % msg)
        return process

    def traceme(self):
        if not self.enabled:
            return False
        ptrace_traceme()
        return True

    def quit(self):
        if not self.enabled:
            return
        self.enabled = False
        self.debugger.quit()

    def destroy(self):
        self.quit()

    def on_project_stop(self):
        self.quit()

