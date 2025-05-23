import itertools
from os.path import normpath
from sys import executable, getfilesystemencoding
from sys import path as sys_path

from fusil.write_code import WriteCode
from fusil.xhost import xhostCommand


def formatValue(value):
    r"""
    >>> print formatValue('aaaaa')
    'a' * 5
    >>> print formatValue(u'xxxxx')
    u'x' * 5
    >>> print formatValue('ab\0')
    'ab\x00'
    """
    if 5 <= len(value):
        repeat = True
        first = None
        for item in value:
            if first:
                if first != item:
                    repeat = False
                    break
            else:
                first = item
    else:
        repeat = False
    if repeat:
        return repr(value[:1]) + " * %s" % len(value)
    else:
        return repr(value)


def formatPath(value, cwd, cwd_bytes):
    """
    >>> print formatPath('a<path>b', '<path>', u'<path>')
    'a' + cwd_bytes + 'b'
    >>> print formatPath('a<path>', '<path>', u'<path>')
    'a' + cwd_bytes
    >>> print formatPath(u'<path>b', '<path>', u'<path>')
    cwd + u'b'
    """
    result = []
    if isinstance(value, bytes):
        pattern = cwd_bytes
        replace = "cwd_bytes"
    else:
        pattern = cwd
        replace = "cwd"
    if value.startswith(pattern):
        result.append(replace)
        value = value[len(pattern) :]
    pos = value.find(pattern)
    if 0 <= pos:
        before = value[:pos]
        if before:
            result.append(formatValue(before))
        result.append(replace)
        value = value[pos + len(pattern) :]
    if value.endswith(pattern):
        value = value[: -len(pattern)]
        result.append(formatValue(value))
        result.append(replace)
        value = ""
    elif value:
        result.append(formatValue(value))
    return " + ".join(result)


class WriteReplayScript(WriteCode):
    def __init__(self):
        WriteCode.__init__(self)
        self.comment_column = 40

    def debug(self, level, format, *args):
        line = 'debug("%s"' % format
        if args:
            line += " % "
            if len(args) == 1:
                line += str(args[0])
            else:
                line += "(%s)" % ", ".join(args)
        line += ")"
        self.write(level, line)

    def writeFunction(self, name, callback, *args):
        self.write(0, "def %s:" % name)
        old = self.addLevel(1)
        callback(*args)
        self.restoreLevel(old)
        self.emptyLine()

    def pythonImports(self):
        self.write(0, "#!%s" % normpath(executable))
        self.write(0, "from os import chdir, getcwd, getuid, execvpe, environ")
        self.write(0, "from os.path import dirname, devnull")
        self.write(0, "from sys import stderr, exit, getfilesystemencoding")
        self.write(0, "from optparse import OptionParser")
        self.emptyLine()

    def setSysPath(self):
        self.write(0, "import sys")
        self.write(0, "sys.path = [")
        for path in sys_path:
            self.write(1, '"%s",' % path)
        self.write(1, "]")
        self.emptyLine()

    def limitResources(self):
        self.write(0, "if options.limit:")
        self.write(1, "return")
        self.emptyLine()

        self.write(0, "if options.gdb or options.valgrind or options.ptrace:")
        self.debug(1, "Don't limit resources when using --gdb, --valgrind or --ptrace")
        self.write(1, "return")
        self.emptyLine()

        self.write(
            0,
            "from fusil.process.tools import allowCoreDump, limitMemory, limitUserProcess, limitCpuTime",
        )
        self.emptyLine()

        self.write(0, "if allow_core_dump:")
        self.debug(1, "allow core dump")
        self.write(1, "allowCoreDump(hard=True)")
        self.emptyLine()

        self.write(0, "if max_user_process:")
        self.debug(1, "limit user process to %s", "max_user_process")
        self.write(1, "limitUserProcess(max_user_process)")
        self.emptyLine()

        self.write(0, "if 0 < max_memory:")
        self.debug(1, "limit memory to %s bytes", "max_memory")
        self.write(1, "limitMemory(max_memory, hard=True)")
        self.emptyLine()

        self.write(0, "if 0 < timeout:")
        self.debug(1, "limit CPU time to %s seconds", "timeout")
        self.write(1, "limitCpuTime(timeout)")

    def writePrint(self, level, message, arguments=None, file=None):
        message = '"%s"' % message
        if arguments:
            message += " %% (%s)" % arguments
        if file:
            code = "print (%s, file=%s)" % (message, file)
        else:
            code = "print (%s)" % message
        self.write(level, code)

    def safetyConfirmation(self):
        self.writePrint(
            0, "!!!WARNING!!! The fuzzer will run as user %s and group %s,", "uid, gid"
        )
        self.writePrint(
            0,
            "!!!WARNING!!! and may remove arbitrary files and kill arbitrary processes.",
        )
        self.writePrint(0, "")
        self.emptyLine()

        raw_input = "input"
        self.write(0, "try:")
        self.write(1, "answer = None")
        self.write(1, 'while answer not in ("yes", "no", ""):')
        self.write(2, "if answer:")
        self.write(3, """answer = %s('Please answer "yes" or "no": ')""" % raw_input)
        self.write(2, "else:")
        self.write(3, "answer = %s('Do you want to continue? (yes/NO) ')" % raw_input)
        self.write(2, "answer = answer.strip().lower()")
        self.write(1, "confirm = (answer == 'yes')")
        self.write(0, "except (KeyboardInterrupt, EOFError):")
        self.writePrint(1, "")
        self.write(1, "confirm = False")
        self.write(0, "if not confirm:")
        self.write(1, "exit(1)")

    def changeUserGroup(self, process, config):
        imports = ["setgid", "setuid", "getuid", "getgid"]
        if process.use_x11:
            imports.append("system")
        self.write(0, "from os import %s" % ", ".join(imports))
        self.emptyLine()

        # safety confirmation
        self.write(0, "if (uid is None) or (uid == 0):")
        self.write(1, "if uid is None:")
        self.write(2, "child_uid = getuid()")
        self.write(1, "else:")
        self.write(2, "child_uid = uid")
        self.write(1, "if gid is None:")
        self.write(2, "child_gid = getgid()")
        self.write(1, "else:")
        self.write(2, "child_gid = gid")
        self.write(1, "safetyConfirmation(child_uid, child_gid)")

        # xhost command
        if process.use_x11:
            command = xhostCommand(config.fusil_xhost_program, "%s")
            self.debug(0, "allow user %s to use the X11 server", "uid")
            self.write(0, 'system("%s" %% uid)' % " ".join(command))
            self.emptyLine()

        # setgid()
        self.write(0, "if gid is not None:")
        self.debug(1, "set group identifier to %s", "gid")
        self.write(1, "setgid(gid)")
        self.emptyLine()

        # setuid()
        self.write(0, "if uid is not None:")
        self.debug(1, "set user identifier to %s", "uid")
        self.write(1, "setuid(uid)")

    def writeDebugFunction(self):
        self.write(0, "if quiet:")
        self.write(1, "return")
        self.writePrint(0, "[Fusil] %s", "message", file="stderr")

    def parseOptions(self):
        self.write(0, "parser = OptionParser()")
        self.write(0, 'parser.add_option("-q", "--quiet",')
        self.write(
            1, 'help="Be quiet (don\'t write debug messages)", action="store_true")'
        )
        self.write(0, 'parser.add_option("-u", "--user",')
        self.write(1, 'help="Don\'t change user/group", action="store_true")')
        self.write(0, 'parser.add_option("-l", "--limit",')
        self.write(1, 'help="Don\'t set resource limits", action="store_true")')
        self.write(0, 'parser.add_option("-e", "--environ",')
        self.write(
            1,
            ' help="Copy environment variables (default: empty environment)", action="store_true")',
        )
        self.write(0, 'parser.add_option("--gdb",')
        self.write(1, ' help="Run command in gdb", action="store_true")')
        self.write(0, 'parser.add_option("--valgrind",')
        self.write(1, ' help="Run command in valgrind", action="store_true")')
        self.write(0, 'parser.add_option("--ptrace",')
        self.write(
            1, ' help="Run command in the python-ptrace debugger", action="store_true")'
        )
        self.write(0, "options, arguments = parser.parse_args()")
        self.write(0, "if arguments:")
        self.write(1, "parser.print_help()")
        self.write(1, "exit(1)")
        self.write(0, "return options")

    def writeGdbCommands(self):
        self.write(0, "filename = 'gdb.cmds'")
        self.debug(0, "Write gdb commands into: %s", "filename")
        self.write(0, "cmd = open(filename, 'w')")
        self.write(0, "for key in set(gdb_env) - set(env):")
        self.writePrint(1, "unset environment %s", "key", file="cmd")
        self.write(0, "for key, value in env.items():")
        self.writePrint(1, "set environment %s=%s", "key, value", file="cmd")

        self.write(0, "gdb_arguments = []")
        self.write(0, "for arg in arguments[1:]:")
        self.write(1, r"""arg = arg.replace('\\', r'\\')""")
        self.write(1, r"""arg = arg.replace('"', r'\\"')""")
        self.write(1, r"""arg = '"%s"' % arg""")
        self.write(1, "gdb_arguments.append(arg)")

        self.writePrint(0, "run %s", '" ".join(gdb_arguments)', file="cmd")
        self.write(0, "cmd.close()")
        self.write(0, "return filename")

    def runGdb(self):
        self.write(0, "from pwd import getpwuid")
        self.emptyLine()
        self.write(0, "uid = getuid()")
        self.write(0, "home = getpwuid(uid).pw_dir")
        self.write(0, "gdb_env = {'HOME': home}")
        self.write(0, "filename = writeGdbCommands(arguments, gdb_env, env)")
        self.emptyLine()
        self.write(0, "gdb_arguments = [")
        self.write(1, "gdb_program,")
        self.write(1, "arguments[0],")
        self.write(1, "'-x',")
        self.write(1, "filename,")
        self.write(0, "]")
        self.debug(
            0, "Execute %r in environment %r", "' '.join(gdb_arguments)", "gdb_env"
        )
        self.write(0, "execvpe(gdb_arguments[0], gdb_arguments, gdb_env)")

    def runCommand(self):
        self.write(0, "global null_stdin")
        self.emptyLine()

        self.write(0, "if options.environ:")
        self.write(1, "env = environ")
        self.write(1, "env.update(program_env)")
        self.write(0, "else:")
        self.write(1, "env = program_env")
        self.emptyLine()

        self.write(0, "for key, value in env.items():")
        self.debug(1, "set env %s = (%s bytes) %s", "key", "len(value)", "repr(value)")

        self.write(0, "if options.gdb:")
        self.write(1, "runGdb(gdb_program, arguments, env)")
        self.write(1, "return")
        self.emptyLine()

        self.write(0, "if options.valgrind:")
        self.write(1, "arguments = [valgrind_program, '--'] + arguments")
        self.write(0, "elif options.ptrace:")
        self.write(1, "from fusil.process.tools import locateProgram")
        self.write(1, "from sys import executable")
        self.emptyLine()
        self.write(1, "program = locateProgram(ptrace_program, raise_error=True)")
        self.write(1, "arguments = [executable, program, '--'] + arguments")
        self.write(1, "null_stdin = False")
        self.emptyLine()

        self.write(0, "if null_stdin:")
        self.debug(1, "Redirect stdin to %s", "devnull")
        self.write(1, "from os import dup2")
        self.write(1, "stdin = open(devnull, 'wb')")
        self.write(1, "dup2(stdin.fileno(), 0)")
        self.emptyLine()

        self.debug(0, "Execute %r", "' '.join(arguments)")
        self.write(0, "execvpe(arguments[0], arguments, env)")

    def writeMain(self):
        self.write(0, "global uid, gid, quiet")
        self.emptyLine()
        self.write(0, "options = parseOptions()")
        self.write(0, "quiet = options.quiet")
        self.write(0, "if options.user:")
        self.write(1, "uid = None")
        self.write(1, "gid = None")

        self.write(0, "try:")
        self.write(1, "changeUserGroup(uid, gid)")
        self.write(0, "except OSError as err:")
        self.writePrint(1, "Error on changing user/group: %s", "err")
        self.write(1, "if getuid() != 0:")
        self.writePrint(2, "=> Retry as root user!")
        self.write(1, "exit(1)")

        self.write(0, "limitResources(options)")
        self.debug(0, "current working directory: %s", "cwd")
        self.write(0, "runCommand(arguments, env, options)")

    def globalVariables(self, process, config, cwd, arguments, env):
        fs_charset = getfilesystemencoding()
        cwd_bytes = cwd.encode(fs_charset)

        need_cwd_bytes = False
        for value in itertools.chain(arguments, env.items()):
            if not isinstance(value, bytes):
                continue
            if cwd_bytes not in value:
                continue
            need_cwd_bytes = True
            break

        self.write(0, "chdir(dirname(__file__))")
        self.write(0, "cwd = getcwd()")
        if need_cwd_bytes:
            self.write(0, "cwd_bytes = cwd.encode(getfilesystemencoding())")
        self.emptyLine()

        self.write(0, "arguments = [")
        # Use relative PATH in arguments
        for arg in arguments:
            arg = formatPath(arg, cwd, cwd_bytes)
            self.write(1, "%s," % arg)
        self.write(0, "]")

        if env:
            self.write(0, "env = {")
            for name, value in env.items():
                value = formatPath(value, cwd, cwd_bytes)
                self.write(1, '"%s": %s,' % (name, value))
            self.write(0, "}")
        else:
            self.write(0, "env = {}")
        self.emptyLine()

        self.write(0, "null_stdin = %r" % bool(not process.stdin))
        self.write(0, "uid = %r" % config.process_uid)
        self.write(0, "gid = %r" % config.process_gid)
        self.write(0, "allow_core_dump = %r" % process.core_dump)
        if config.process_user and (0 < process.max_user_process):
            max_user_process = process.max_user_process
        else:
            max_user_process = None
        self.write(0, "max_user_process = %r" % max_user_process)
        self.write(0, "max_memory = %r   # bytes" % process.max_memory)
        if 0 < process.timeout:
            timeout = int(process.timeout)
        else:
            timeout = None
        self.write(0, "timeout = %r   # seconds" % timeout)
        self.write(0, "gdb_program = 'gdb'")
        self.write(0, "valgrind_program = 'valgrind'")
        self.write(0, "ptrace_program = 'gdb.py'")
        self.write(0, "quiet = False")
        self.emptyLine()

    def callMain(self):
        self.write(0, "if __name__ == '__main__':")
        self.write(1, "main()")
        self.emptyLine()

    def writeCode(self, process, arguments, popen_args):
        project = process.project()
        session = project.session
        config = project.config
        cwd = process.getWorkingDirectory()
        env = popen_args["env"]
        if not env:
            env = {}

        # Create the script file
        filename = session.createFilename("replay.py")
        self.createFile(filename, 0o755)
        self.pythonImports()
        self.globalVariables(process, config, cwd, arguments, env)
        self.setSysPath()
        self.writeFunction("debug(message)", self.writeDebugFunction)
        self.writeFunction("parseOptions()", self.parseOptions)
        self.writeFunction("safetyConfirmation(uid, gid)", self.safetyConfirmation)
        self.writeFunction(
            "changeUserGroup(uid, gid)", self.changeUserGroup, process, config
        )
        self.writeFunction("limitResources(options)", self.limitResources)
        self.writeFunction(
            "writeGdbCommands(arguments, gdb_env, env)", self.writeGdbCommands
        )
        self.writeFunction("runGdb(gdb_program, arguments, env)", self.runGdb)
        self.writeFunction(
            "runCommand(arguments, program_env, options)", self.runCommand
        )
        self.writeFunction("main()", self.writeMain)
        self.callMain()
        self.close()


def createReplayPythonScript(process, arguments, popen_args):
    writer = WriteReplayScript()
    writer.writeCode(process, arguments, popen_args)
