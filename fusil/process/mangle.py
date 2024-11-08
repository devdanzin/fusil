from fusil.process.create import CreateProcess
from fusil.file_tools import relativePath

class MangleProcess(CreateProcess):
    def __init__(self, project, arguments, mangle_pattern, use_relative_mangle=True, **kw):
        CreateProcess.__init__(self, project, arguments, **kw)
        self.orig_cmdline = self.cmdline.arguments
        self.mangle_pattern = mangle_pattern
        self.use_relative_mangle = use_relative_mangle

    def mangleCmdline(self, filenames):
        file_index = 0
        args = list(self.orig_cmdline)
        directory = self.getWorkingDirectory()
        for index, arg in enumerate(args):
            if self.mangle_pattern not in arg:
                continue
            filename = filenames[file_index]
            if self.use_relative_mangle:
                filename = relativePath(filename, directory)
            args[index] = arg.replace(self.mangle_pattern, filename)
            file_index += 1
        self.cmdline.arguments = args

    def on_mangle_filenames(self, filenames):
        self.mangleCmdline(filenames)
        self.createProcess()

