from __future__ import print_function

from sys import stderr
from weakref import ref as weakref_ref

# from ptrace.error import PTRACE_ERRORS, writeError
from fusil.mas.agent_id import AgentID
from fusil.mas.mailbox import Mailbox
from fusil.mas.message import Message


class AgentError(Exception):
    pass


class Agent(object):
    def __init__(self, name, mta):
        self.agent_id = AgentID().generate()
        self.is_active = False
        self.name = name
        self.setupMTA(mta)

    def setupMTA(self, mta, logger=None):
        """
        Create the mailbox and store a weak reference the message transfert
        agent (MTA).
        """
        if mta:
            if logger:
                self.logger = logger
            else:
                self.logger = mta.logger
            self.mta = weakref_ref(mta)
            self.mailbox = Mailbox(self, mta)
        else:
            self.logger = None
            self.mta = None
            self.mailbox = None

    def __cmp__(self, other):
        return cmp(self.agent_id, other.agent_id)

    def __del__(self):
        try:
            if hasattr(self, "is_active"):
                self.deactivate()
            if hasattr(self, "mailbox") and self.mailbox:
                self.mailbox.unregister()
            self.destroy()
        except KeyboardInterrupt:
            self.error("Agent destruction interrupted!")
            self.send("application_interrupt")
        except Exception as error:
            print(self, error, "Agent destruction error", file=stderr)

    def destroy(self):
        """
        (Abstract method) Method called on agent destruction: cleanup data.
        """
        pass

    def getEvents(self):
        """
        List events which the agent listen on
        """
        events = set()
        for attrname in dir(self):
            if attrname.startswith("on_"):
                events.add(attrname[3:])
        return events

    def send(self, event, *arguments):
        """
        send(event, *arguments): send a message (event) to other agents
        """
        if not self.is_active:
            raise AgentError("Inactive agent are not allowed to send message!")
        message = Message(event, arguments)
        mta = self.mta()
        if mta is not None:
            mta.deliver(message)
        else:
            self.error("Unable to send %r: MTA is missing" % message)

    def readMailbox(self):
        """
        Read the mailbox: "execute" each message.
        Return the number of executed messages.
        """
        messages = self.mailbox.popMessages()
        for message in messages:
            message(self)
        return len(messages)

    def activate(self):
        """
        Enable an agent: call init() method if the agent was disabled.
        """
        if self.is_active:
            raise AgentError("%r is already activated!" % self)
        self.mailbox.clear()
        self.is_active = True
        self.init()

    def deactivate(self):
        """
        Disable an agent: call deinit() method if the agent was enabled.
        """
        if not self.is_active:
            return
        self.is_active = False
        self.deinit()

    def init(self):
        """
        Abstract method called by activate()
        """
        pass

    def live(self):
        """
        Abstract method called at each univers step.
        """
        pass

    def deinit(self):
        """
        Abstract method called by deactivate()
        """
        pass

    def _log(self, level, message):
        try:
            func = getattr(self.logger, level)
        except AttributeError:
            if level == "error":
                print("(no logger)", message, file=stderr)
            return
        func(message, sender=self)

    def debug(self, message):
        """
        Write a message to the log with DEBUG level
        """
        self._log("debug", message)

    def info(self, message):
        """
        Write a message to the log with INFO level
        """
        self._log("info", message)

    def warning(self, message):
        """
        Write a message to the log with WARNING level
        """
        self._log("warning", message)

    def error(self, message):
        """
        Write a message to the log with ERROR level
        """
        self._log("error", message)

    def __repr__(self):
        return "<%s id=%s, name=%r is_active=%s>" % (
            self.__class__.__name__,
            self.agent_id,
            self.name,
            self.is_active,
        )

    def __str__(self):
        return "<%s %r>" % (self.__class__.__name__, self.name)
