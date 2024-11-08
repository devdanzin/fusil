from fusil.python_tools import RUNNING_PYTHON3
from fusil.write_code import WriteCode
from fusil.xhost import xhostCommand
from os.path import normpath
from ptrace.six import itervalues, iteritems, binary_type, text_type
from sys import executable, getfilesystemencoding, path as sys_path
import itertools

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
        return repr(value[:1]) + ' * %s' % len(value)
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
    if isinstance(value, binary_type):
        pattern = cwd_bytes
        replace = u'cwd_bytes'
    else:
        pattern = cwd
        replace = u'cwd'
    if value.startswith(pattern):
        result.append(replace)
        value = value[len(pattern):]
    pos = value.find(pattern)
    if 0 <= pos:
        before = value[:pos]
        if before:
            result.append(formatValue(before))
        result.append(replace)
        value = value[pos+len(pattern):]
    if value.endswith(pattern):
        value = value[:-len(pattern)]
        result.append(formatValue(value))
        result.append(replace)
        value = ''
    elif value:
        result.append(formatValue(value))
    return u' + '.join(result)

class WriteReplayScript(WriteCode):
    def __init__(self):
        WriteCode.__init__(self)
        self.comment_column = 40

    def debug(self, level, format, *args):
        line = u'debug("%s"' % format
        if args:
            line += u' % '
            if len(args) == 1:
                line += text_type(args[0])
            else:
                line += u'(%s)' % ', '.join(args)
        line += ')'
        self.write(level, line)

    def writeFunction(self, name, callback, *args):
        self.write(0, u"def %s:" % name)
        old = self.addLevel(1)
        callback(*args)
        self.restoreLevel(old)
        self.emptyLine()

    def pythonImports(self):
        self.write(0, u"#!%s" % normpath(executable))
        self.write(0, u'from os import chdir, getcwd, getuid, execvpe, environ')
        self.write(0, u'from os.path import dirname, devnull')
        self.write(0, u'from sys import stderr, exit, getfilesystemencoding')
        self.write(0, u'from optparse import OptionParser')
        self.emptyLine()

    def setSysPath(self):
        self.write(0, u'import sys')
        self.write(0, u'sys.path = [')
        for path in sys_path:
            self.write(1, u'"%s",' % path)
        self.write(1, u']')
        self.emptyLine()

    def limitResources(self):
        self.write(0, 'if options.limit:')
        self.write(1, 'return')
        self.emptyLine()

        self.write(0, 'if options.gdb or options.valgrind or options.ptrace:')
        self.debug(1, "Don't limit resources when using --gdb, --valgrind or --ptrace")
        self.write(1, 'return')
        self.emptyLine()

        self.write(0, u'from fusil.process.tools import allowCoreDump, limitMemory, limitUserProcess, limitCpuTime')
        self.emptyLine()

        self.write(0, u'if allow_core_dump:')
        self.debug(1, "allow core dump")
        self.write(1, u'allowCoreDump(hard=True)')
        self.emptyLine()

        self.write(0, u'if max_user_process:')
        self.debug(1, "limit user process to %s", "max_user_process")
        self.write(1, u'limitUserProcess(max_user_process)')
        self.emptyLine()

        self.write(0, u'if 0 < max_memory:')
        self.debug(1, "limit memory to %s bytes", "max_memory")
        self.write(1, u'limitMemory(max_memory, hard=True)')
        self.emptyLine()

        self.write(0, u'if 0 < timeout:')
        self.debug(1, "limit CPU time to %s seconds", "timeout")
        self.write(1, u'limitCpuTime(timeout)')

    def writePrint(self, level, message, arguments=None, file=None):
        if RUNNING_PYTHON3:
            message = '"%s"' % message
        else:
            message = 'u"%s"' % message
        if arguments:
            message += " %% (%s)" % arguments
        if RUNNING_PYTHON3:
            if file:
                code = "print (%s, file=%s)" % (message, file)
            else:
                code = "print (%s)" % message
        else:
            if file:
                code = "print >>%s, %s" % (file, message)
            else:
                code = "print %s" % message
        self.write(level, code)

    def safetyConfirmation(self):
        self.writePrint(0, u'!!!WARNING!!! The fuzzer will run as user %s and group %s,',
            u'uid, gid')
        self.writePrint(0, u'!!!WARNING!!! and may remove arbitrary files and kill arbitrary processes.')
        self.writePrint(0, u'')
        self.emptyLine()

        if RUNNING_PYTHON3:
            raw_input = u'input'
        else:
            raw_input = u'raw_input'

        self.write(0, u'try:')
        self.write(1, u'answer = None')
        self.write(1, u'while answer not in ("yes", "no", ""):')
        self.write(2, u'if answer:')
        self.write(3, u'''answer = %s('Please answer "yes" or "no": ')''' % raw_input)
        self.write(2, u'else:')
        self.write(3, u"answer = %s('Do you want to continue? (yes/NO) ')" % raw_input)
        self.write(2, u'answer = answer.strip().lower()')
        self.write(1, u"confirm = (answer == 'yes')")
        self.write(0, u'except (KeyboardInterrupt, EOFError):')
        self.writePrint(1, u'')
        self.write(1, u'confirm = False')
        self.write(0, u'if not confirm:')
        self.write(1, u'exit(1)')

    def changeUserGroup(self, process, config):
        imports = ['setgid', 'setuid', 'getuid', 'getgid']
        if process.use_x11:
            imports.append('system')
        self.write(0, u'from os import %s' % ', '.join(imports))
        self.emptyLine()

        # safety confirmation
        self.write(0, u'if (uid is None) or (uid == 0):')
        self.write(1, u'if uid is None:')
        self.write(2, u'child_uid = getuid()')
        self.write(1, u'else:')
        self.write(2, u'child_uid = uid')
        self.write(1, u'if gid is None:')
        self.write(2, u'child_gid = getgid()')
        self.write(1, u'else:')
        self.write(2, u'child_gid = gid')
        self.write(1, u'safetyConfirmation(child_uid, child_gid)')

        # xhost command
        if process.use_x11:
            command = xhostCommand(config.fusil_xhost_program, '%s')
            self.debug(0, u"allow user %s to use the X11 server", "uid")
            self.write(0, u'system("%s" %% uid)' % ' '.join(command))
            self.emptyLine()

        # setgid()
        self.write(0, 'if gid is not None:')
        self.debug(1, 'set group identifier to %s', 'gid')
        self.write(1, u'setgid(gid)')
        self.emptyLine()

        # setuid()
        self.write(0, 'if uid is not None:')
        self.debug(1, 'set user identifier to %s', 'uid')
        self.write(1, u'setuid(uid)')

    def writeDebugFunction(self):
        self.write(0, u'if quiet:')
        self.write(1, u'return')
        self.writePrint(0, u'[Fusil] %s', u'message', file=u'stderr')

    def parseOptions(self):
        self.write(0, u'parser = OptionParser()')
        self.write(0, u'parser.add_option("-q", "--quiet",')
        self.write(1, u'help="Be quiet (don\'t write debug messages)", action="store_true")')
        self.write(0, u'parser.add_option("-u", "--user",')
        self.write(1, u'help="Don\'t change user/group", action="store_true")')
        self.write(0, u'parser.add_option("-l", "--limit",')
        self.write(1, u'help="Don\'t set resource limits", action="store_true")')
        self.write(0, u'parser.add_option("-e", "--environ",')
        self.write(1, u' help="Copy environment variables (default: empty environment)", action="store_true")')
        self.write(0, u'parser.add_option("--gdb",')
        self.write(1, u' help="Run command in gdb", action="store_true")')
        self.write(0, u'parser.add_option("--valgrind",')
        self.write(1, u' help="Run command in valgrind", action="store_true")')
        self.write(0, u'parser.add_option("--ptrace",')
        self.write(1, u' help="Run command in the python-ptrace debugger", action="store_true")')
        self.write(0, u'options, arguments = parser.parse_args()')
        self.write(0, u'if arguments:')
        self.write(1, u'parser.print_help()')
        self.write(1, u'exit(1)')
        self.write(0, u'return options')

    def writeGdbCommands(self):
        self.write(0, u"filename = 'gdb.cmds'")
        self.debug(0, u'Write gdb commands into: %s', u'filename')
        self.write(0, u"cmd = open(filename, 'w')")
        self.write(0, u'for key in set(gdb_env) - set(env):')
        self.writePrint(1, u'unset environment %s', u'key', file=u'cmd')
        self.write(0, u'for key, value in env.items():')
        self.writePrint(1, u'set environment %s=%s', u'key, value', file=u'cmd')

        self.write(0, u'gdb_arguments = []')
        self.write(0, u'for arg in arguments[1:]:')
        self.write(1, r'''arg = arg.replace('\\', r'\\')''')
        self.write(1, r'''arg = arg.replace('"', r'\\"')''')
        self.write(1, r'''arg = '"%s"' % arg''')
        self.write(1, u'gdb_arguments.append(arg)')

        self.writePrint(0, u'run %s', u'" ".join(gdb_arguments)', file=u'cmd')
        self.write(0, u'cmd.close()')
        self.write(0, u'return filename')

    def runGdb(self):
        self.write(0, u'from pwd import getpwuid')
        self.emptyLine()
        self.write(0, u'uid = getuid()')
        self.write(0, u'home = getpwuid(uid).pw_dir')
        self.write(0, u"gdb_env = {'HOME': home}")
        self.write(0, u'filename = writeGdbCommands(arguments, gdb_env, env)')
        self.emptyLine()
        self.write(0, u'gdb_arguments = [')
        self.write(1, u'gdb_program,')
        self.write(1, u'arguments[0],')
        self.write(1, u"'-x',")
        self.write(1, u'filename,')
        self.write(0, u']')
        self.debug(0, u'Execute %r in environment %r', u"' '.join(gdb_arguments)", u"gdb_env")
        self.write(0, u'execvpe(gdb_arguments[0], gdb_arguments, gdb_env)')

    def runCommand(self):
        self.write(0, u"global null_stdin")
        self.emptyLine()

        self.write(0, u'if options.environ:')
        self.write(1, u'env = environ')
        self.write(1, u'env.update(program_env)')
        self.write(0, u'else:')
        self.write(1, u'env = program_env')
        self.emptyLine()

        self.write(0, u'for key, value in env.items():')
        self.debug(1, u'set env %s = (%s bytes) %s', 'key', 'len(value)', 'repr(value)')

        self.write(0, u'if options.gdb:')
        self.write(1, u'runGdb(gdb_program, arguments, env)')
        self.write(1, u'return')
        self.emptyLine()

        self.write(0, u'if options.valgrind:')
        self.write(1, u"arguments = [valgrind_program, '--'] + arguments")
        self.write(0, u'elif options.ptrace:')
        self.write(1, u'from fusil.process.tools import locateProgram')
        self.write(1, u'from sys import executable')
        self.emptyLine()
        self.write(1, u'program = locateProgram(ptrace_program, raise_error=True)')
        self.write(1, u"arguments = [executable, program, '--'] + arguments")
        self.write(1, u"null_stdin = False")
        self.emptyLine()

        self.write(0, u'if null_stdin:')
        self.debug(1, u'Redirect stdin to %s', 'devnull')
        self.write(1, u'from os import dup2')
        self.write(1, u"stdin = open(devnull, 'wb')")
        self.write(1, u'dup2(stdin.fileno(), 0)')
        self.emptyLine()

        self.debug(0, u'Execute %r', u"' '.join(arguments)")
        self.write(0, u'execvpe(arguments[0], arguments, env)')

    def writeMain(self):
        self.write(0, 'global uid, gid, quiet')
        self.emptyLine()
        self.write(0, 'options = parseOptions()')
        self.write(0, 'quiet = options.quiet')
        self.write(0, 'if options.user:')
        self.write(1, 'uid = None')
        self.write(1, 'gid = None')

        self.write(0, u'try:')
        self.write(1, u'changeUserGroup(uid, gid)')
        if RUNNING_PYTHON3:
            self.write(0, 'except OSError as err:')
        else:
            self.write(0, u'except OSError, err:')
        self.writePrint(1, u'Error on changing user/group: %s', 'err')
        self.write(1, u'if getuid() != 0:')
        self.writePrint(2, u'=> Retry as root user!')
        self.write(1, u'exit(1)')

        self.write(0, 'limitResources(options)')
        self.debug(0, "current working directory: %s", "cwd")
        self.write(0, 'runCommand(arguments, env, options)')

    def globalVariables(self, process, config, cwd, arguments, env):
        fs_charset = getfilesystemencoding()
        cwd_bytes = cwd.encode(fs_charset)

        need_cwd_bytes = False
        for value in itertools.chain(arguments, itervalues(env)):
            if not isinstance(value, binary_type):
                continue
            if cwd_bytes not in value:
                continue
            need_cwd_bytes = True
            break

        self.write(0, u'chdir(dirname(__file__))')
        self.write(0, u'cwd = getcwd()')
        if need_cwd_bytes:
            self.write(0, 'cwd_bytes = cwd.encode(getfilesystemencoding())')
        self.emptyLine()

        self.write(0, u'arguments = [')
        # Use relative PATH in arguments
        for arg in arguments:
            arg = formatPath(arg, cwd, cwd_bytes)
            self.write(1, u'%s,' % arg)
        self.write(0, u']')

        if env:
            self.write(0, u'env = {')
            for name, value in iteritems(env):
                value = formatPath(value, cwd, cwd_bytes)
                self.write(1, u'"%s": %s,' % (name, value))
            self.write(0, u'}')
        else:
            self.write(0, u'env = {}')
        self.emptyLine()

        self.write(0, u'null_stdin = %r' % bool(not process.stdin))
        self.write(0, u'uid = %r' % config.process_uid)
        self.write(0, u'gid = %r' % config.process_gid)
        self.write(0, u'allow_core_dump = %r' % process.core_dump)
        if config.process_user and (0 < process.max_user_process):
            max_user_process = process.max_user_process
        else:
            max_user_process = None
        self.write(0, u'max_user_process = %r' % max_user_process)
        self.write(0, u'max_memory = %r   # bytes' % process.max_memory)
        if 0 < process.timeout:
            timeout = int(process.timeout)
        else:
            timeout = None
        self.write(0, u'timeout = %r   # seconds' % timeout)
        self.write(0, u"gdb_program = 'gdb'")
        self.write(0, u"valgrind_program = 'valgrind'")
        self.write(0, u"ptrace_program = 'gdb.py'")
        self.write(0, u'quiet = False')
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
        env = popen_args['env']
        if not env:
            env = {}

        # Create the script file
        filename = session.createFilename("replay.py")
        self.createFile(filename, 0o755)
        self.pythonImports()
        self.globalVariables(process, config, cwd, arguments, env)
        self.setSysPath()
        self.writeFunction('debug(message)', self.writeDebugFunction)
        self.writeFunction('parseOptions()', self.parseOptions)
        self.writeFunction('safetyConfirmation(uid, gid)', self.safetyConfirmation)
        self.writeFunction('changeUserGroup(uid, gid)', self.changeUserGroup, process, config)
        self.writeFunction('limitResources(options)', self.limitResources)
        self.writeFunction('writeGdbCommands(arguments, gdb_env, env)', self.writeGdbCommands)
        self.writeFunction('runGdb(gdb_program, arguments, env)', self.runGdb)
        self.writeFunction('runCommand(arguments, program_env, options)', self.runCommand)
        self.writeFunction('main()', self.writeMain)
        self.callMain()
        self.close()

def createReplayPythonScript(process, arguments, popen_args):
    writer = WriteReplayScript()
    writer.writeCode(process, arguments, popen_args)

