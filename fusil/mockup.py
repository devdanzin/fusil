"""
Classes mockup used for unit tests.
"""

from weakref import ref

class Logger:
    def __init__(self, show=False):
        self.show = show

    def debug(self, message, sender=None):
        self.display(message)

    def info(self, message, sender=None):
        self.display(message)

    def warning(self, message, sender=None):
        self.display(message)

    def error(self, message, sender=None):
        self.display(message)

    def display(self, message):
        if not self.show:
            return
        print(message)

class MTA:
    def __init__(self, logger=None):
        if not logger:
            logger = Logger()
        self.logger = logger

    def registerMailingList(self, mailbox, event):
        pass

    def deliver(self, message):
        pass

class Options:
    def __init__(self):
        self.debug = False

class Application:
    def __init__(self):
        self.options = Options()

    def initX11(self):
        pass

class Config:
    def __getattr__(self, name):
        return None

class Debugger:
    def tracePID(self, agent, pid):
        pass

class Project:
    def __init__(self, logger=None):
        self._mta = MTA(logger)
        self.mta = ref(self._mta)
        self._application = Application()
        self.application = ref(self._application)
        self.debugger = Debugger()
        self.config = Config()

    def registerAgent(self, agent):
        pass

    def unregisterAgent(self, agent):
        pass

