from errno import ENOENT
from os import devnull, getpgid, getpgrp, kill, killpg
from os.path import basename
from pwd import getpwuid
from signal import SIGKILL
from subprocess import STDOUT, Popen, SubprocessError
from time import sleep, time

from ptrace.signames import signalName

from fusil.process.cmdline import CommandLine
from fusil.process.env import Environment
from fusil.process.prepare import ChildError, prepareProcess
from fusil.process.replay_python import createReplayPythonScript
from fusil.process.tools import displayProcessStatus, locateProgram, splitCommand, target_is_asan
from fusil.project_agent import ProjectAgent

DEFAULT_TIMEOUT = 10.0


def killProcessGroup(pgid):
    """SIGKILL every process in group ``pgid``. Returns True if the group still existed.

    Refuses to signal our own process group: fusil would kill itself. That can only happen if
    the child's ``setsid()`` did not take effect, in which case ``process_group`` is never set
    (see ``CreateProcess.createProcess``) -- this is a second belt on the same braces.
    """
    if pgid is None or pgid == getpgrp():
        return False
    try:
        killpg(pgid, SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        return False  # group already gone (or not ours to signal)
    return True


def terminateProcess(process, pgid=None):
    """SIGKILL the child and, when its process group is known, every descendant with it.

    SIGKILLing the child alone leaks its grandchildren: they are reparented to init and
    survive for the lifetime of the fleet (see CreateProcess.terminate).
    """
    killProcessGroup(pgid)
    kill(process.pid, SIGKILL)


class ProcessError(Exception):
    # Exception raised by Fusil, by the CreateProcess class
    pass


class CreateProcess(ProjectAgent):
    def __init__(
        self,
        project,
        options,
        arguments=None,
        stdout="file",
        stdin=False,
        timeout=DEFAULT_TIMEOUT,
        name=None,
    ):
        if isinstance(arguments, str):
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
        # ASan/TSan targets reserve a huge virtual address space (TSan mmaps terabytes of
        # shadow memory); applying RLIMIT_AS would kill them on startup (this is why the
        # memory cap was historically disabled wholesale). Drop the cap for ASan builds
        # (auto-detected), for --tsan (whose command is `setarch -R <python> ...`, so the
        # program isn't arguments[0] to auto-detect), or when the user passes
        # --no-memory-limit; the external cgroup cap (e.g. the fleet's systemd MemoryMax)
        # is the real limit in that setup.
        program = arguments[0] if arguments else None
        if (
            getattr(options, "no_memory_limit", False)
            or getattr(options, "tsan", False)
            or target_is_asan(program)
        ):
            self.max_memory = 0
        self.max_user_process = config.process_max_user_process
        self.core_dump = config.process_core_dump
        self.stdout = stdout
        self.popen_args = {
            "stderr": STDOUT,
        }
        self.popen_args["close_fds"] = True
        self.stdin = stdin
        self.options = options

    def init(self):
        self.score = None
        self.process = None
        self.process_group = None
        self.timeout_reached = False
        self.status = None
        self.current_popen_args = None
        self.current_arguments = None
        self.show_exit = True
        self.wrote_replay = False
        self.stdout_file = self.options.stdout_path
        # Initialize stdin_file too: closeStreams() reads it, and it is only otherwise set
        # in createPopenArguments(). Without this, any poll()/terminate()/clearProcess() path
        # that reaches closeStreams() before a process was spawned raises AttributeError.
        self.stdin_file = None

    def prepareProcess(self):
        prepareProcess(self)

    def getWorkingDirectory(self):
        return self.session().directory.directory

    @staticmethod
    def checkArguments(arguments):
        """Validate process arguments: each must be a ``str``/``bytes`` free of NUL bytes.

        Raises ``ValueError`` on the first offending argument (wrong type or embedded NUL).
        Extracted from ``createProcess`` so the pure validation can be unit-tested directly;
        the behaviour is unchanged.
        """
        for index, argument in enumerate(arguments):
            if isinstance(argument, bytes):
                has_null = b"\0" in argument
            elif isinstance(argument, str):
                has_null = "\0" in argument
            else:
                raise ValueError(
                    "Process argument %s is not a byte or unicode string: (%s) %r"
                    % (index, type(argument).__name__, argument)
                )
            if has_null:
                raise ValueError("Process argument %s contains nul byte: %r" % (index, argument))

    def createProcess(self):
        arguments = self.createArguments()
        self.checkArguments(arguments)
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
            raise ProcessError(err) from err
        except SubprocessError as err:
            # Popen collapses any preexec_fn (child setup) failure into an opaque
            # "Exception occurred in preexec_fn." The child wrote the real cause to its
            # stderr -- which we redirected to the session's stdout file -- before dying;
            # read it back so the fusil log names the true failure instead of the opaque one.
            detail = self.readChildSetupError()
            message = "Child setup failed before exec (preexec_fn)"
            if detail:
                message += ":\n" + detail
            raise ProcessError(message) from err
        except OSError as err:
            if err.errno == ENOENT:
                raise ProcessError("Program doesn't exist: %s" % arguments[0]) from err
            else:
                raise
        pid = self.process.pid
        self.info("Process identifier: %s" % pid)
        # Remember the child's process group (created by start_new_session=True) so we can
        # sweep its descendants later, even once the child itself is gone. Read it now: after
        # the child is reaped, getpgid() no longer resolves.
        try:
            pgid = getpgid(pid)
        except OSError:
            pgid = None  # already gone; nothing to sweep
        self.process_group = pgid if pgid != getpgrp() else None
        self.closeStreams()
        self.send("process_create", self)

    def readChildSetupError(self, limit=8000):
        """Read back what the child wrote to its stdout (its dup'd stderr) before exec.

        On a preexec_fn failure exec never runs, so the session's stdout file holds only the
        child's setup diagnostics (the friendly permission/chdir messages plus the traceback
        written by ``prepare._report_preexec_failure``). Returns a trimmed string, or ``None``
        if nothing readable (e.g. stdout was /dev/null). Never raises -- it runs on an error
        path and must not mask the original failure.
        """
        path = getattr(self.stdout_file, "name", None)
        if not path or not isinstance(path, str):
            return None
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read(limit).strip()
        except OSError:
            return None
        return text or None

    def writeReplayScripts(self, arguments, popen_args):
        if self.wrote_replay:
            return
        self.wrote_replay = True
        createReplayPythonScript(self, arguments, popen_args)

    def createPopenArguments(self):
        popen_args = dict(self.popen_args)
        env = self.env.create()
        uid = self.project().config.process_uid
        if "HOME" in env and uid is not None:
            # Use the fuzzer user home directory
            env["HOME"] = getpwuid(uid).pw_dir
        popen_args["env"] = env
        self.stdin_file = self.createStdin()
        if self.stdin_file:
            popen_args["stdin"] = self.stdin_file.fileno()
        self.stdout_file = self.createStdout()
        popen_args["stdout"] = self.stdout_file.fileno()
        popen_args["preexec_fn"] = self.prepareProcess
        # Run the child in its own session/process group (setsid() before exec), so every
        # descendant it spawns shares one pgid we can sweep on teardown. Without this we can
        # only SIGKILL the direct child, and anything it forked (multiprocessing's forkserver
        # and resource_tracker, pool workers, ...) is orphaned to init and leaks. It also
        # detaches the child from our controlling terminal, so a Ctrl+C aimed at fusil no
        # longer races us to the child -- we kill it ourselves during teardown.
        popen_args["start_new_session"] = True
        return popen_args

    def createStdin(self):
        if self.stdin:
            return None
        self.info("Stdin: %s" % devnull)
        return open(devnull, "rb")

    def createStdout(self):
        # Check stdout type
        if self.stdout not in ("null", "file"):
            raise ValueError("Invalid stdout type: %r" % self.stdout)

        # Ignore stdout?
        if self.stdout != "null":
            # Otherwise, create a "stdout" file as output
            filename = (
                self.stdout_file if self.stdout_file else self.session().createFilename("stdout")
            )
            self.send("process_stdout", self, filename)
        else:
            filename = devnull
        self.info("Stdout filename: %s" % filename)
        return open(filename, "wb")

    def createArguments(self):
        return self.cmdline.create()

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
        self.send("session_rename", name)

    def processExited(self, status):
        if self.show_exit:
            displayProcessStatus(self, status, "Process %s" % self.process.pid)
            self.renameSession(status)
            self.send("process_exit", self, status)
        self.status = status
        self.clearProcess()

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
        status = self.process.poll()
        if status is None:
            return None
        self.processExited(status)
        return status

    def live(self):
        if (not self.process) or not (0 < self.timeout):
            return
        if time() - self.time0 < self.timeout:
            return
        self.warning("Timeout! (%.1f second)" % self.timeout)
        self.send("session_rename", "timeout")
        self.timeout_reached = True
        self.terminate()

    def terminate(self):
        # Manual terminate, so don't show exit status
        self.show_exit = False

        # Check if process is still running or not
        if not self.process:
            return
        if self.poll() is None:
            # Kill the process and wait for its exit status
            self.warning("Terminate process %s" % self.process.pid)
            self._terminate()
            self.waitExit()

        # Sweep whatever the child left behind. This must run even when the child already
        # exited on its own -- for a fuzzer that is the COMMON case (it crashed), and it is
        # exactly the case where nothing else kills its descendants: multiprocessing's
        # forkserver and resource_tracker are started on demand and only shut down via the
        # atexit handlers of a *clean* interpreter exit, so a crashed/SIGKILLed child strands
        # them. They are then reparented to init and survive for the whole run.
        self.reapProcessGroup()

    def reapProcessGroup(self):
        """SIGKILL any descendants of the child that outlived it (see terminate())."""
        pgid, self.process_group = self.process_group, None
        if killProcessGroup(pgid):
            self.info("Killed leftover descendants in process group %s" % pgid)

    def _terminate(self):
        terminateProcess(self.process, self.process_group)

    def waitExit(self):
        # Get the process exit status to avoid creation of a zombi process
        start = time()
        timeout = 60.0
        next_msg = start + 1.5
        while True:
            # Timeout?
            diff = time() - start
            if timeout < diff:
                raise ValueError(
                    "Unable to kill process %s after %.1f seconds" % (self.process.pid, diff)
                )

            # Inform user about this loop
            if next_msg <= time():
                next_msg = time() + 5.0
                self.error(
                    "Wait until process %s death (since %.1f seconds)..." % (self.process.pid, diff)
                )

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

    def getScore(self):
        return self.score


class ProjectProcess(CreateProcess):
    def on_session_start(self):
        self.createProcess()
