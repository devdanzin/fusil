from __future__ import with_statement

from array import array
from os import fstat
from random import choice
from stat import ST_SIZE

from fusil.project_agent import ProjectAgent
from fusil.six import string_types
from fusil.six.moves import range as xrange


class MangleAgent(ProjectAgent):
    def __init__(self, project, sources, nb_file=1):
        ProjectAgent.__init__(self, project, "mangle")
        if isinstance(sources, string_types):
            self.source_filenames = (sources,)
        else:
            # Remove duplicates
            self.source_filenames = tuple(set(sources))
        if 1 < len(self.source_filenames):
            self.error("Sources filenames: %s" % len(self.source_filenames))
        self.max_size = None # 10*1024*1024
        self.nb_file = nb_file

    def readData(self, filename, file_index):
        # Open file and read file size
        self.info("Load input file: %s" % filename)
        data = open(filename, 'rb')
        orig_filesize = fstat(data.fileno())[ST_SIZE]
        if not orig_filesize:
            raise ValueError("Input file (%s) is empty!" % filename)

        # Read bytes
        if self.max_size:
            data = data.read(self.max_size)
        else:
            data = data.read()

        # Display message if input is truncated
        if len(data) < orig_filesize:
            percent = len(data) * 100.0 / orig_filesize
            self.warning("Truncate file to %s bytes (%.2f%% of %s bytes)" \
                % (len(data), percent, orig_filesize))

        # Convert to Python array object
        return array('B', data)

    def writeData(self, filename, data):
        self.info("Generate file: %s" % filename)
        with open(filename, 'wb') as output:
            data.tofile(output)
        return filename

    def createFilename(self, filename, file_index):
        if 1 < self.nb_file:
            count = 1
        else:
            count = None
        return self.session().createFilename(filename, count=count)

    def mangle(self):
        filenames = []
        for file_index in xrange(self.nb_file):
            filename = choice(self.source_filenames)
            data = self.readData(filename, file_index)
            data = self.mangleData(data, file_index)
            filename = self.createFilename(filename, file_index)
            self.writeData(filename, data)
            filenames.append(filename)
        self.send('mangle_filenames', filenames)

    # --- Abstract methods ---

    def mangleData(self, data, file_index):
        # data: array of unsigned bytes, array('B', ...)
        raise NotImplementedError()

    def on_session_start(self):
        self.mangle()

