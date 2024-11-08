import sys
from fusil.unsafe import SUPPORT_UID
from errno import ENOENT
from os import devnull
from os.path import basename
from subprocess import Popen, STDOUT
from time import time, sleep
from fusil.process.cmdline import CommandLine
from fusil.process.prepare import prepareProcess, ChildError
from fusil.process.env import Environment
from fusil.process.replay_python import createReplayPythonScript
from fusil.process.tools import (
        locateProgram, displayProcessStatus, splitCommand)
from fusil.project_agent import ProjectAgent
from ptrace.signames import signalName
from fusil.six import string_types, text_type, binary_type
if SUPPORT_UID:
    from pwd import getpwuid

RUNNING_WINDOWS = sys.platform == 'win32'

if RUNNING_WINDOWS:
    from win32api import TerminateProcess
else:
    from os import kill
    from signal import SIGKILL

DEFAULT_TIMEOUT = 10.0

def terminateProcess(process):
    if RUNNING_WINDOWS:
        TerminateProcess(process._handle, 1)
    else:
        kill(process.pid, SIGKILL)

class ProcessError(Exception):
    # Exception raised by Fusil, by the CreateProcess class
    pass

class CreateProcess(ProjectAgent):
    def __init__(self, project, arguments=None,
    stdout="file", stdin=False,
    timeout=DEFAULT_TIMEOUT,
    name=None):
        if isinstance(arguments, string_types):
            arguments = splitCommand(arguments)
        config = project.config
        if not name:
            name = "process:%s" % basename(arguments[0])
        ProjectAgent.__init__(self, project, name)
        self.env = Environment(self)
        if arguments is None:
            arguments = []
        self.cmdline = CommandLine(self, arguments)
        self.timeout = timeout
        self.max_memory = config.process_max_memory
        self.max_user_process = config.process_max_user_process
        self.core_dump = config.process_core_dump
        self.stdout = stdout
        self.debugger = project.debugger
        self.use_x11 = False
        self.popen_args = {
            'stderr': STDOUT,
        }
        if not RUNNING_WINDOWS:
            self.popen_args['close_fds'] = True
        self.stdin = stdin

    def init(self):
        self.score = None
        self.process = None
        self.dbg_process = None
        self.timeout_reached = False
        self.status = None
        self.current_popen_args = None
        self.current_arguments = None
        self.show_exit = True
        self.wrote_replay = False
        self.stdout_file = None

    def prepareProcess(self):
        prepareProcess(self)

    def getWorkingDirectory(self):
        return self.session().directory.directory

    def createProcess(self):
        arguments = self.createArguments()
        for index, argument in enumerate(arguments):
            if isinstance(argument, binary_type):
                has_null = ("\0" in argument)
            elif isinstance(argument, text_type):
                has_null = (u"\0" in argument)
            else:
                raise ValueError("Process argument %s is not a byte or unicode string: (%s) %r" % (
                    index, type(argument).__name__, argument))
            if has_null:
                raise ValueError("Process argument %s contains nul byte: %r" % (
                    index, argument))
        arguments[0] = locateProgram(arguments[0], raise_error=True)
        popen_args = self.createPopenArguments()
        self.info("Create process: %s" % repr(arguments))
        self.info("Working directory: %s" % self.getWorkingDirectory())
        self.writeReplayScripts(arguments, popen_args)
        try:
            self.current_arguments = arguments
            self.current_popen_args = popen_args
            self.time0 = time()
            self.process = Popen(arguments, **popen_args)
        except ChildError as err:
            raise ProcessError(unicode(err))
        except OSError as err:
            if err.errno == ENOENT:
                raise ProcessError("Program doesn't exist: %s" % arguments[0])
            else:
                raise
        pid = self.process.pid
        self.info("Process identifier: %s" % pid)
        self.closeStreams()
        if self.debugger.enabled:
            self._attach()
        self.send('process_create', self)
        self.send('process_pid', self, pid)

    def writeReplayScripts(self, arguments, popen_args):
        if self.wrote_replay:
            return
        self.wrote_replay = True
        createReplayPythonScript(self, arguments, popen_args)

    def _attach(self):
        self.dbg_process = self.debugger.attachPID(self, self.process.pid)

    def createPopenArguments(self):
        popen_args = dict(self.popen_args)
        env = self.env.create()
        if SUPPORT_UID:
            uid = self.project().config.process_uid
            if 'HOME' in env \
            and uid is not None:
                # Use the fuzzer user home directory
                env['HOME'] = getpwuid(uid).pw_dir
        popen_args['env'] = env
        self.stdin_file = self.createStdin()
        if self.stdin_file:
            popen_args['stdin'] = self.stdin_file.fileno()
        self.stdout_file = self.createStdout()
        popen_args['stdout'] = self.stdout_file.fileno()
        if not RUNNING_WINDOWS:
            popen_args['preexec_fn'] = self.prepareProcess
        return popen_args

    def createStdin(self):
        if self.stdin:
            return None
        self.info("Stdin: %s" % devnull)
        return open(devnull, 'rb')

    def createStdout(self):
        # Check stdout type
        if self.stdout not in ('null', 'file'):
            raise ValueError('Invalid stdout type: %r' % self.stdout)

        # Ignore stdout?
        if self.stdout != "null":
            # Otherwise, create a "stdout" file as output
            filename = self.session().createFilename('stdout')
            self.send('process_stdout', self, filename)
        else:
            filename = devnull
        self.info("Stdout filename: %s" % filename)
        return open(filename, "wb")

    def createArguments(self):
        return self.cmdline.create()

    def detach(self):
        if not self.dbg_process:
            return
        self.debugger.detach(self.dbg_process)
        self.dbg_process = None

    def renameSession(self, status):
        if status < 0:
            signum = -status
            name = signalName(signum)
            name = name.lower()
        elif 0 < status:
            name = "exitcode%s" % status
        else:
            # nul exitcode: don't rename the session
            return
        self.send('session_rename', name)

    def processExited(self, status):
        if self.show_exit:
            displayProcessStatus(self, status, "Process %s" % self.process.pid)
            if not self.debugger.enabled:
                self.renameSession(status)
            self.send("process_exit", self, status)
        self.status = status
        if self.debugger.enabled:
            # Inform Popen() object that the process exited
            self.process.returncode = status
        self.clearProcess()
        self.detach()

    def closeStreams(self):
        if self.stdout_file:
            self.stdout_file.close()
            self.stdout_file = None
        if self.stdin_file:
            self.stdin_file.close()
            self.stdin_file = None

    def clearProcess(self):
        self.closeStreams()
        self.process = None

    def poll(self):
        """
        Get process exit status:
         - zero: process exited with code 0
         - a positive value: process exited with code (status)
         - a negative value: process killed by the signal (-status)
        """
        if not self.process:
            return self.status
        if self.debugger.enabled:
            if not self.dbg_process:
                self._attach()
            status = self.debugger.pollPID(self.process.pid)
            if status is None:
                return None
            # Message already displayed by the debugger
            # (and event "process_exit" sent)
            self.show_exit = False
        else:
            status = self.process.poll()
            if status is None:
                return None
        self.processExited(status)
        return status

    def live(self):
        if (not self.process) \
        or not (0 < self.timeout):
            return
        if time() - self.time0 < self.timeout:
            return
        self.warning("Timeout! (%.1f second)" % self.timeout)
        self.send('session_rename', 'timeout')
        self.timeout_reached = True
        self.terminate()

    def terminate(self):
        # Manual terminate, so don't show exit status
        self.show_exit = False

        # Check if process is still running or not
        if not self.process:
            return
        if self.poll() is not None:
            return

        # Kill the process and wait for its exit status
        self.warning("Terminate process %s" % self.process.pid)
        self._terminate()
        self.waitExit()

    def _terminate(self):
        if self.debugger.enabled:
            self.dbg_process.terminate(wait_exit=False)
        else:
            terminateProcess(self.process)

    def waitExit(self):
        # Get the process exit status to avoid creation of a zombi process
        start = time()
        timeout = 60.0
        next_msg = start + 1.5
        while True:
            # Timeout?
            diff = time() - start
            if timeout < diff:
                raise ValueError("Unable to kill process %s after %.1f seconds" % (
                    self.process.pid, diff))

            # Inform user about this loop
            if next_msg <= time():
                next_msg = time() + 5.0
                self.error("Wait until process %s death (since %.1f seconds)..."
                    % (self.process.pid, diff))

            # Is process terminated?
            status = self.poll()
            if status is not None:
                break

            if diff < 0.050:
                # During first 50 ms, try five times to get its status
                sleep(0.010)
            elif diff < 1.0:
                # 50 ms .. 1000 ms: retry four times
                sleep(0.250)
            else:
                # After one second, resend KILL signal each half second
                self._terminate()
                sleep(0.500)

    def deinit(self):
        if self.process:
            self.terminate()
            self.process = None
        self.detach()

    def setupX11(self):
        self.use_x11 = True
        self.application().initX11()
        self.env.copyX11()

    def getScore(self):
        return self.score

class ProjectProcess(CreateProcess):
    def on_session_start(self):
        self.createProcess()

