from weakref import ref as weakref_ref

class Mailbox:
    def __init__(self, agent, mta):
        self.messages = []
        self.agent = weakref_ref(agent)
        self.mta = weakref_ref(mta)
        self.events = agent.getEvents()
        for event in self.events:
            mta.registerMailingList(self, event)

    def unregister(self):
        mta = self.mta()
        if not mta:
            return
        for event in self.events:
            mta.unregisterMailingList(self, event)

    def clear(self):
        self.messages = []

    def deliver(self, message):
        agent = self.agent()
        if not agent:
            self.unregister()
            return
        if not agent.is_active:
            return
        self.messages.append(message)

    def popMessages(self):
        messages = self.messages
        self.messages = []
        return messages

    def __repr__(self):
        agent = self.agent()
        if agent:
            return "<Mailbox of %r>" % agent
        else:
            return "<Mailbox>"

