from weakref import ref as weakref_ref

from fusil.mas.agent import Agent


class ApplicationAgent(Agent):
    def __init__(self, name, application, mta):
        Agent.__init__(self, name, mta)
        self.application = weakref_ref(application)
        if application is not self:
            self.register()

    def register(self):
        self.application().registerAgent(self)

    def unregister(self, destroy=True):
        # The application weakref can already be dead at interpreter shutdown (AgentList.__del__
        # -> clear -> unregister), so guard it like ProjectAgent.unregister does for project().
        application = self.application()
        if application is not None:
            application.unregisterAgent(self, destroy)
