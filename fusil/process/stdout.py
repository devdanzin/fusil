from fusil.file_watch import FileWatch
from weakref import ref as weakref_ref

class WatchStdout(FileWatch):
    def __init__(self, process):
        FileWatch.__init__(self, process.project(), None, "watch:stdout")
        self.process = weakref_ref(process)

    def on_process_stdout(self, agent, filename):
        if agent != self.process():
            return
        input_file = open(filename, 'rb')
        self.setFileObject(input_file)

    def on_process_exit(self, agent, status):
        if agent != self.process():
            return
        self.live()
        self.close()

    def deinit(self):
        FileWatch.deinit(self)
        self.close()

