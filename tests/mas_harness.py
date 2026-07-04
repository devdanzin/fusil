"""Runtime-free scaffolding for testing fusil MAS agents.

Builds a real ``fusil.mas.mta.MTA`` backed by a stub Application, wrapped in a lightweight
fake Project, so ``ProjectAgent`` subclasses (``FileWatch``, ``WatchProcess`` ...) can be
constructed and driven without python-ptrace or the ``Univers`` loop. Mirrors the stub-app
approach in ``tests/test_mas.py``; shared here because many agent tests need the same setup.

Typical use::

    from tests.mas_harness import FakeProject

    project = FakeProject()
    agent = SomeProjectAgent(project, ...)
    agent.send = record            # optionally intercept emitted events
"""

from types import SimpleNamespace

from fusil.mas.mta import MTA


class StubLogger:
    """Records log calls so tests can assert on them; the MAS logger contract is
    ``method(message, sender=None)``."""

    def __init__(self):
        self.records: list[tuple[str, object]] = []

    def debug(self, message, sender=None):
        self.records.append(("debug", message))

    def info(self, message, sender=None):
        self.records.append(("info", message))

    def warning(self, message, sender=None):
        self.records.append(("warning", message))

    def error(self, message, sender=None):
        self.records.append(("error", message))


class StubApplication:
    """Weakref-able Application stand-in (ProjectAgent stores a weakref to it)."""

    def __init__(self, debug=False, **options):
        self.logger = StubLogger()
        self.options = SimpleNamespace(debug=debug, **options)

    def registerAgent(self, agent):
        pass

    def unregisterAgent(self, agent, destroy=True):
        pass


class FakeProject:
    """Minimal Project exposing the ``ProjectAgent.__init__`` contract (``mta()``,
    ``application()``, ``registerAgent()``) over a real MTA."""

    def __init__(self, debug=False, **options):
        self._application = StubApplication(debug=debug, **options)
        self._mta = MTA(self._application)
        self.registered: list[object] = []
        self.session = None

    def mta(self):
        return self._mta

    def application(self):
        return self._application

    def registerAgent(self, agent):
        self.registered.append(agent)

    def unregisterAgent(self, agent, destroy=True):
        pass
