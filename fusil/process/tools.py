import re
from os import X_OK, access, devnull, getcwd, getenv, pathsep
from os.path import dirname, isabs, normpath
from os.path import join as path_join
from subprocess import STDOUT, Popen


from resource import (
    RLIMIT_AS,
    RLIMIT_CORE,
    RLIMIT_CPU,
    RLIMIT_NPROC,
    getrlimit,
    setrlimit,
)

try:
    from os import nice
except ImportError:
    # PyPy doesn't have os.nice()
    def nice(level):
        pass

def _setrlimit(key, value, change_hard):
    try:
        soft, hard = getrlimit(key)
        # Change soft limit
        if hard != -1:
            soft = min(value, hard)
        else:
            soft = value
        if change_hard:
            # Change hard limit
            hard = soft
    except ValueError:
        hard = -1
    setrlimit(key, (soft, hard))
    return soft


def limitMemory(nbytes, hard=False):
    return _setrlimit(RLIMIT_AS, nbytes, hard)


def limitUserProcess(nproc, hard=False):
    return _setrlimit(RLIMIT_NPROC, nproc, hard)


def allowCoreDump(hard=False):
    ret_code = None
    try:
        ret_code = _setrlimit(RLIMIT_CORE, -1, hard)
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
    return ret_code


def limitCpuTime(seconds, hard=False):
    # Round float to int
    if isinstance(seconds, float):
        seconds = int(seconds + 0.5)
    return _setrlimit(RLIMIT_CPU, seconds, hard)


def beNice(very_nice=False):
    if very_nice:
        value = 10
    else:
        value = 5
    nice(value)


def displayProcessStatus(logger, status, prefix="Process"):
    if status == 0:
        logger.info("%s exited normally" % prefix)
    elif status < 0:
        signum = -status
        logger.error("%s killed by signal %s" % (prefix, signum))
    else:
        logger.warning("%s exited with error code: %s" % (prefix, status))


def runCommand(
    logger, command, stdin=False, stdout=True, options=None, raise_error=True
):
    """
    Run specified command:
     - logger is an object with a info() method
     - command: a string or a list of strings (eg. 'uname' or ['gcc', 'printf.c'])
     - stdin: if value is False, use null device as stdin (default: no stdin)
     - stdout: if value is False, use null device as stdout and stderr
       (default: keep stdout)

    Raise RuntimeError on failure: if the exit code is not nul or if the
    process is killed by a signal. If raise_error=False, return the status and
    don't raise RuntimeError if status is not nul.
    """
    if isinstance(command, str):
        command_str = repr(command)
    else:
        command_str = " ".join(command)
        command_str = repr(command_str)
    logger.info("Run the command: %s" % command_str)
    if not options:
        options = {}
    if not stdin:
        stdin_file = open(devnull, "r")
        options["stdin"] = stdin_file
    else:
        stdin_file = None
    stdout_file = None
    if not stdout:
        stdout_file = open(devnull, "wb")
        options["stdout"] = stdout_file
        options["stderr"] = STDOUT
    elif stdout is not True:
        options["stdout"] = stdout
        options["stderr"] = STDOUT
    if ("close_fds" not in options):
        options["close_fds"] = True

    process = Popen(command, **options)
    status = process.wait()
    if stdin_file:
        stdin_file.close()
    if stdout_file:
        stdout_file.close()
    if not raise_error:
        return status
    if not status:
        return
    if status < 0:
        errmsg = "process killed by signal %s" % (-status)
    else:
        errmsg = "exit code %s" % status
    raise RuntimeError("Unable to run the command %s: %s" % (command_str, errmsg))


def locateProgram(program, use_none=False, raise_error=False):
    if isabs(program):
        # Absolute path: nothing to do
        return program
    if dirname(program):
        # ./test => $PWD/./test
        # ../python => $PWD/../python
        program = path_join(getcwd(), program)
        program = normpath(program)
        return program
    if use_none:
        default = None
    else:
        default = program
    paths = getenv("PATH")
    if not paths:
        if raise_error:
            raise ValueError("Unable to get PATH environment variable")
        return default
    for path in paths.split(pathsep):
        filename = path_join(path, program)
        if access(filename, X_OK):
            return filename
    if raise_error:
        raise ValueError("Unable to locate program %r in PATH" % program)
    return default


def splitCommand(command):
    r"""
    Split a command (string): create a command as a list of strings.

    >>> splitCommand("ls -l")
    ['ls', '-l']
    >>> splitCommand("python -c 'import sys; print sys.version'")
    ['python', '-c', 'import sys; print sys.version']
    >>> splitCommand("python -c 'import sys; print \"sys.version\"'")
    ['python', '-c', 'import sys; print "sys.version"']
    """
    if "\\" in command:
        raise SyntaxError("splitCommand() doesn't support antislash")
    arguments = []
    start = 0
    in_quote = None
    for match in re.finditer(r"""[ \t"']""", command):
        index = match.start()
        sep = command[index]
        write = False
        if in_quote == sep:
            write = True
            in_quote = None
        elif sep == " ":
            if not in_quote:
                write = True
        elif not in_quote:
            in_quote = sep
            start = index + 1
        if write:
            arguments.append(command[start:index])
            start = index + 1
    if in_quote:
        raise SyntaxError("Quote %r is not closed" % in_quote)
    if start < len(command):
        arguments.append(command[start:])
    return arguments
