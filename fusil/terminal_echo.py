from ptrace.terminal import enableEchoMode

from fusil.project_agent import ProjectAgent


class TerminalEcho(ProjectAgent):
    def __init__(self, project):
        ProjectAgent.__init__(self, project, "terminal")

    def deinit(self):
        if enableEchoMode():
            self.info("Terminal: restore echo mode to stdin")
