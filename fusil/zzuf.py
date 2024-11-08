from fusil.process.create import ProjectProcess
from os.path import exists

LIBRARY_PATHS = (
    # Linux
    '/usr/lib/zzuf/libzzuf.so',
    # BSD
    '/usr/local/lib/zzuf/libzzuf.so',
)
DEFAULT_RATIO = 0.004

class ZzufProcess(ProjectProcess):
    def __init__(self, project, arguments, library_path=None, **options):
        ProjectProcess.__init__(self, project, arguments, **options)

        # Options
        self.use_debug_file = True
        self.setRatio(DEFAULT_RATIO, DEFAULT_RATIO)

        # Locate libzzuf library
        if not library_path:
            for path in LIBRARY_PATHS:
                if not exists(path):
                    continue
                library_path = path
                break
            if not library_path:
                raise ValueError("Unable to find zzuf library (try %s)" % ', '.join(LIBRARY_PATHS))

        # Load zzuf using LD_PRELOAD
        self.env.set('LD_PRELOAD', library_path)

    def init(self):
        ProjectProcess.init(self)
        self.zzuf_file = None

    def closeStreams(self):
        ProjectProcess.closeStreams(self)
        if self.zzuf_file:
            self.zzuf_file.close()
            self.zzuf_file = None

    def createProcess(self):
        if self.use_debug_file:
            filename = self.session().createFilename('zzuf.dbg')
            self.zzuf_file = open(filename, 'w')
            self.env.set("ZZUF_DEBUG", str(self.zzuf_file.fileno()))
        ProjectProcess.createProcess(self)

    def on_aggressivity_value(self, value):
        ratio = value / 10.0
        self.min_ratio = ratio
        self.max_ratio = ratio
        self.error("Set zzuf ratio to: %.3f" % ratio)
        self.setRatio(self.min_ratio, self.max_ratio)

    def setRatio(self, min_ratio, max_ratio):
        self.min_ratio = min_ratio
        self.env.set('ZZUF_MINRATIO', str(self.min_ratio))
        self.max_ratio = max_ratio
        self.env.set('ZZUF_MAXRATIO', str(self.max_ratio))

