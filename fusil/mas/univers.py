from time import sleep
from fusil.mas.application_agent import ApplicationAgent

class Univers(ApplicationAgent):
    def __init__(self, application, mta, step_sleep):
        ApplicationAgent.__init__(self, "univers", application, mta)
        self.on_stop = None
        self.is_done = False
        self.step_sleep = step_sleep

    def executeAgent(self, agent):
        if not agent.is_active:
            return
        agent.readMailbox()
        agent.live()

    def execute(self, project):
        age = 0
        self.is_done = False
        while True:
            age += 1
            # Execute one univers step
            for agent in project.agents:
                self.executeAgent(agent)

            # Application is done? stop
            if self.is_done:
                return

            # Be nice with CPU: sleep some milliseconds
            sleep(self.step_sleep)

    def on_univers_stop(self):
        if self.on_stop:
            self.on_stop()
        self.is_done = True

