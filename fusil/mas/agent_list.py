from ptrace.error import PTRACE_ERRORS, writeError


class AgentList:
    def __init__(self):
        self.agents = []

    def append(self, agent):
        if agent in self:
            raise KeyError("Agent %r already registred")
        self.agents.append(agent)

    def _destroy(self, agent):
        try:
            agent.deactivate()
        except PTRACE_ERRORS as error:
            writeError(None, error, "Agent deinit error")
        agent.unregister(False)

    def remove(self, agent, destroy=True):
        if agent not in self:
            return
        self.agents.remove(agent)
        if destroy:
            self._destroy(agent)

    def clear(self):
        while self.agents:
            agent = self.agents.pop()
            self._destroy(agent)

    def __del__(self):
        self.clear()

    def __contains__(self, agent):
        return agent in self.agents

    def __iter__(self):
        return iter(self.agents)
