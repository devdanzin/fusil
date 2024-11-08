from fusil.bytes_generator import BytesGenerator
from fusil.process.tools import runCommand, locateProgram
from fusil.write_code import WriteCode
from os.path import basename
from ptrace.os_tools import RUNNING_WINDOWS
from ptrace.six import b, text_type, string_types, PY2
from random import choice, randint
from struct import pack

class CompilerError(Exception):
    pass

GCC_PROGRAM = None

MIN_INT32 = -2**31
MAX_INT32 = (2**21)-1

def encodeUTF32(text):
    data = []
    for character in text:
        data.append( pack('I', ord(character)) )
    return b('').join(data)

def quoteString(text):
    data = []
    for character in text:
        if character == '"':
            data.append('\\"')
        elif character == "\0":
            data.append('\\0')
        elif character == "\n":
            data.append('\\n')
        elif character == "\\":
            data.append('\\\\')
        elif 32 <= ord(character) <= 127:
            data.append(character)
        else:
            data.append("\\x%02X" % ord(character))
    return '"'+''.join(data)+'"'

def compileC(logger, c_filename, output_filename, options=None, debug=True, libraries=None):
    """
    Compile a C script.
    Raise CompilerError on failure.
    """
    global GCC_PROGRAM
    if not GCC_PROGRAM:
        if RUNNING_WINDOWS:
            program = u"gcc.exe"
        else:
            program = u"gcc"
        GCC_PROGRAM = locateProgram(program, raise_error=True)
    command = [GCC_PROGRAM,
        u"-o", output_filename,
        c_filename]
    if debug:
        command.extend((u"-Wall", u"-Wextra", u"-Werror"))
    if libraries:
        for library in libraries:
            command.append(u"-l%s" % library)
    if options:
        options = options.split()
        command.extend(options)
    try:
        runCommand(logger, command)
    except RuntimeError as err:
        raise CompilerError("Unable to compile %s: %s" % (basename(c_filename), err))

class FunctionC:
    def __init__(self, name, arguments=None, type="void"):
        self.name = text_type(name)
        if arguments:
            self.arguments = arguments
        else:
            self.arguments = tuple()
        self.type = type
        self.variables = []
        self.code = []
        self.footer = []

    def lines(self):
        yield (0, u"%s %s(%s) {" % (self.type, self.name, ", ".join(self.arguments)))

        for variable in self.variables:
            yield (1, variable + u';')
        if self.variables:
            yield None

        for code in self.code:
            if isinstance(code, string_types):
                yield (1, code)
            else:
                level, code = code
                yield (level+1, code)

        if self.footer:
            yield None
        for line in self.footer:
            yield (1, line)

        yield (0, u'}')

    def callFunction(self, name, arguments, result_variable=None):
        if result_variable:
            name = u'%s = %s(' % (result_variable, name)
        else:
            name = u'%s(' % name
        if arguments:
            self.code.append(name)
            last_index = len(arguments)-1
            for index, argument in enumerate(arguments):
                argument = text_type(argument)
                if index != last_index:
                    argument += u','
                self.code.append( (1, argument) )
            self.code.append(u');')
        else:
            self.code.append(name + u');')

    def add(self, instr):
        self.code.append(instr + u';')

    def __repr__(self):
        return '<FunctionC "%s %s()">' % (self.type, self.name)

class CodeC(WriteCode):
    def __init__(self):
        WriteCode.__init__(self)
        self.includes = []
        self.gnu_source = False
        self.functions = {}
        self.functions_list = []

    def addFunction(self, function):
        self.functions[function.name] = function
        self.functions_list.append(function)
        return function

    def addMain(self, with_argv=False, type=u'int', footer=u'return 0;'):
        if with_argv:
            arguments = (u'int argc', u'char **argv')
        else:
            arguments = None
        main = FunctionC(u'main', arguments, type)
        if footer:
            footer = text_type(footer)
            main.footer.append(footer)
        self.addFunction(main)
        return main

    def __getitem__(self, name):
        return self.functions[name]

    def writeCode(self):
        if self.gnu_source:
            self.write(0, u"#define _GNU_SOURCE")
        for include in self.includes:
            self.write(0, u"#include %s" % include)
        if self.includes:
            self.emptyLine()

        for function in self.functions_list:
            for line in function.lines():
                if line:
                    level, text = line
                    self.write(level, text)
                else:
                    self.emptyLine()
            self.emptyLine()

    def writeIntoFile(self, filename):
        self.createFile(filename)
        self.writeCode()
        self.close()

    def compile(self, logger, c_filename, program_filename, **kw):
        self.writeIntoFile(c_filename)
        compileC(logger, c_filename, program_filename, **kw)

class FuzzyFunctionC(FunctionC):
    def __init__(self, name, arguments=None, type="void", random_bytes=400):
        FunctionC.__init__(self, name, arguments, type)
        self.bytes_generator = BytesGenerator(random_bytes, random_bytes)
        self.buffer_count = 0
        self.special_int32 = (0x8000, 0xffff, 0x80000000)

    def createInt32(self):
        state = randint(1, 3)
        if state == 1:
            return choice(self.special_int32)
        elif state == 2:
            return (0xffffff00 | randint(0, 255))
        else:
            return randint(MIN_INT32, MAX_INT32)

    def createInt(self):
        return self.createInt32()

    def createRandomBytes(self):
        self.buffer_count += 1
        name = "buffer%s" % self.buffer_count

        value = self.bytes_generator.createValue()
        size = len(value)
        if PY2:
            value = ', '.join("0x%02x" % ord(item) for item in value)
        else:
            value = ', '.join("0x%02x" % item for item in value)
        self.variables.append("const char %s[] = {%s}" % (name, value))
        return (name, size)

