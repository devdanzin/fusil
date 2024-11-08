from fusil.mas.agent import Agent
from weakref import ref as weakref_ref
from fusil.score import scoreLogFunc

class ProjectAgent(Agent):
    def __init__(self, project, name, mta=None, application=None):
        if not mta:
            mta = project.mta()
        Agent.__init__(self, name, mta)
        self.project = weakref_ref(project)
        if not application:
            application = project.application()
        self.application = weakref_ref(application)
        if project is not self:
            self.score_weight = 1.0
            self.register()

    def session(self):
        project = self.project()
        if not project:
            return None
        return project.session

    def register(self):
        self.project().registerAgent(self)

    def unregister(self, destroy=True):
        project = self.project()
        if not project:
            return
        project.unregisterAgent(self, destroy)

    def scoreLogFunc(self):
        score = self.getScore()
        return scoreLogFunc(self, score)

    def getScore(self):
        # Score: floating number, -1.0 <= score <= 1.0
        #  1: bug found
        #  0: nothing special
        # -1: inputs rejected
        return None

