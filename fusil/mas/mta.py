from fusil.mas.application_agent import ApplicationAgent
from weakref import ref as weakref_ref

class MTA(ApplicationAgent):
    """
    Mail (message) transfer agent:

     - send(): store messages in a mailbox of message category
     - live(): deliver messages in agent mailboxes
    """
    def __init__(self, application):
        ApplicationAgent.__init__(self, "mta", application, None)
        self.setupMTA(self, application.logger)
        self.mailing_list = {}
        self.queue = []

    def hasMessage(self):
        return bool(self.queue)

    def clear(self):
        self.queue = []

    def registerMailingList(self, mailbox, event):
        mailbox_ref = weakref_ref(mailbox)
        if event not in self.mailing_list:
            self.mailing_list[event] = [mailbox_ref]
        elif mailbox_ref not in self.mailing_list[event]:
            self.mailing_list[event].append(mailbox_ref)

    def unregisterMailingList(self, mailbox, event):
        if event not in self.mailing_list:
            return
        if mailbox not in self.mailing_list[event]:
            return
        self.mailing_list[event].remove(mailbox)

    def deliver(self, message):
        self.queue.append(message)

    def live(self):
        # Delive messages to agents including myself
        for message in self.queue:
            if message.event not in self.mailing_list:
                continue
            mailing_list = self.mailing_list[message.event]
            broken_refs = []
            for mailbox_ref in mailing_list:
                mailbox = mailbox_ref()
                if mailbox is None:
                    broken_refs.append(mailbox_ref)
                    continue
                mailbox.deliver(message)
            # Remove broken references
            for mailbox_ref in broken_refs:
                mailing_list.remove(mailbox_ref)
        self.clear()

