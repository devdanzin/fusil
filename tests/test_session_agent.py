"""Unit tests for fusil.session_agent.SessionAgent.

SessionAgent is the ProjectAgent subclass every per-session agent derives from (Session
itself, SessionDirectory, ...). It differs from a plain ProjectAgent in three ways worth
pinning down: it resolves its MTA from either the given ``project`` or the ``session``; it
holds a *weakref* to its session (``session()`` returns ``None`` once the session is gone);
and its register/unregister wire the agent into BOTH the project and the session.

Runtime-free: a real MTA-backed FakeProject plus a tiny weakref-able FakeSession stand in
for the MAS, so no python-ptrace / Univers loop is needed. SessionAgent's ``__init__``
calls ``activate()`` (hence ``init()``), so a bare SessionAgent is fully live after
construction.
"""

import gc
import unittest

from fusil.session_agent import SessionAgent
from tests.mas_harness import FakeProject


class FakeSession:
    """Weakref-able Session stand-in exposing the SessionAgent contract.

    Provides ``mta()`` / ``project()`` (used by the no-``project`` construction path) and
    records ``registerAgent`` / ``unregisterAgent`` calls so tests can assert the wiring.
    """

    def __init__(self, project):
        self._project = project
        self.registered: list[object] = []
        self.unregistered: list[tuple[object, bool]] = []

    def mta(self):
        return self._project.mta()

    def project(self):
        return self._project

    def registerAgent(self, agent):
        self.registered.append(agent)

    def unregisterAgent(self, agent, destroy=True):
        self.unregistered.append((agent, destroy))


def _make(*, with_project=True, name="sa:test"):
    """Build a live SessionAgent plus its (project, session). ``with_project`` picks the
    two construction paths: explicit project vs. deriving it from the session."""
    project = FakeProject()
    session = FakeSession(project)
    if with_project:
        agent = SessionAgent(session, name, project=project)
    else:
        agent = SessionAgent(session, name)
    return agent, project, session


class TestConstruction(unittest.TestCase):
    def test_project_path_uses_project_mta(self):
        agent, project, session = _make(with_project=True)
        # When a project is passed, the MTA comes from project.mta().
        self.assertIs(agent.mta(), project.mta())
        self.assertIs(agent.project(), project)
        self.assertIs(agent.session(), session)

    def test_no_project_path_derives_from_session(self):
        agent, project, session = _make(with_project=False)
        # Without a project, both the MTA and the project are pulled off the session.
        self.assertIs(agent.mta(), session.mta())
        self.assertIs(agent.project(), project)
        self.assertIs(agent.session(), session)

    def test_active_after_construction(self):
        # __init__ calls activate(): a freshly built SessionAgent is already live.
        agent, _, _ = _make()
        self.assertTrue(agent.is_active)

    def test_name_stored(self):
        agent, _, _ = _make(name="sa:custom")
        self.assertEqual(agent.name, "sa:custom")

    def test_registers_with_both_project_and_session(self):
        # register() runs during construction and wires the agent into BOTH containers.
        agent, project, session = _make()
        self.assertIn(agent, project.registered)
        self.assertIn(agent, session.registered)


class TestSessionAccessor(unittest.TestCase):
    def test_session_returns_target(self):
        agent, _, session = _make()
        self.assertIs(agent.session(), session)

    def test_session_none_after_session_collected(self):
        # The agent holds only a weakref to its session, so once the session is dropped
        # session() reports None rather than keeping it alive.
        agent, _project, session = _make()
        self.assertIsNotNone(agent.session())
        del session
        gc.collect()
        self.assertIsNone(agent.session())


class TestRegisterUnregister(unittest.TestCase):
    @staticmethod
    def _recording_project_unregister(project):
        project.unregistered = []
        project.unregisterAgent = lambda agent, destroy=True: project.unregistered.append(
            (agent, destroy)
        )

    def test_unregister_hits_project_and_session(self):
        agent, project, session = _make()
        self._recording_project_unregister(project)
        agent.unregister()
        self.assertEqual(project.unregistered, [(agent, True)])
        self.assertEqual(session.unregistered, [(agent, True)])

    def test_unregister_destroy_flag_propagates(self):
        agent, project, session = _make()
        self._recording_project_unregister(project)
        agent.unregister(destroy=False)
        self.assertEqual(project.unregistered, [(agent, False)])
        self.assertEqual(session.unregistered, [(agent, False)])

    def test_unregister_with_dead_session_skips_session_branch(self):
        # A collected session (weakref -> None) must not raise: the project is still
        # unregistered and the session branch is simply skipped.
        agent, project, session = _make()
        self._recording_project_unregister(project)
        agent._session = lambda: None  # simulate a session that has been collected
        agent.unregister()  # must not raise
        self.assertEqual(project.unregistered, [(agent, True)])
        self.assertEqual(session.unregistered, [])  # session never touched


class TestLifecycle(unittest.TestCase):
    def test_deactivate_marks_inactive(self):
        agent, _, _ = _make()
        agent.deactivate()
        self.assertFalse(agent.is_active)

    def test_deactivate_is_idempotent(self):
        agent, _, _ = _make()
        agent.deactivate()
        agent.deactivate()  # second call is a no-op, must not raise
        self.assertFalse(agent.is_active)


if __name__ == "__main__":
    unittest.main()
