from fusil.project_agent import ProjectAgent
from fusil.file_watch import FileWatch
from os.path import exists, basename

FILENAMES = (
    # Linux: system logs
    'syslog',
    'messages',
    # Linux: kernel logs
    'dmesg',
    'kern.log',
    # Linux: authentication (PAM) logs
    'auth.log',
    # Linux: user logs
    'user.log',
    # FreeBSD: kernel logs
    'dmesg.today',
    # FreeBSD: user logs
    'userlog',
)

class Syslog(ProjectAgent):
    def __init__(self, project):
        ProjectAgent.__init__(self, project, "syslog")
        self.logs = []
        for filename in FILENAMES:
            agent = self.create(project, '/var/log/' + filename)
            if not agent:
                continue
            self.logs.append(agent)

    def create(self, project, filename):
        if exists(filename):
            return FileWatch(project, open(filename), 'syslog:%s' % basename(filename), start='end')
        else:
            self.warning("Skip (non existent) log file: %s" % filename)
            return None

    def __iter__(self):
        return iter(self.logs)

