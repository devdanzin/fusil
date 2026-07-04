"""Unit tests for fusil.project.Project.

Project is the ProjectAgent that runs fuzzing sessions in a loop, owns the run directory and
the aggressivity scalar, and aggregates session scores. The *session-loop decision* methods
(on_session_done, on_project_session_destroy, on_project_stop, on_univers_stop) and the score
aggregation are already pinned by tests/test_session_lifecycle.py; this module complements it
by covering the rest: construction, agent registration, the createSession/destroySession
machinery, per-step live() timeout, initLog, summarize, and destroy().

Runtime-free: mostly bare instances (``Project.__new__``) with only the collaborators each
method touches stubbed; a few construction tests build a real Project against a fully faked
Application (with fusil.project.ProjectDirectory patched out so no run dir is created).
"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from fusil.project import Project


# --------------------------------------------------------------------------------------
# Bare-instance scaffolding.
# --------------------------------------------------------------------------------------
def _bare_project(**attrs):
    """A Project shell with logging stubbed and GC-time destroy() neutralized.

    ``_destroyed = True`` short-circuits Project.destroy (called from Agent.__del__ at GC) so a
    partially-built shell never runs its real teardown. Tests that exercise destroy() flip it
    back to False.
    """
    p = Project.__new__(Project)
    p._destroyed = True
    p.error = lambda *a, **k: None
    p.warning = lambda *a, **k: None
    p.info = lambda *a, **k: None
    for key, value in attrs.items():
        setattr(p, key, value)
    return p


class _FakeAgents:
    """Records append/remove; stands in for the AgentList Project.agents."""

    def __init__(self, contents=()):
        self.items = list(contents)
        self.removed = []
        self.cleared = 0

    def __contains__(self, agent):
        return agent in self.items

    def __iter__(self):
        return iter(self.items)

    def append(self, agent):
        self.items.append(agent)

    def remove(self, agent, destroy=True):
        self.removed.append((agent, destroy))
        if agent in self.items:
            self.items.remove(agent)

    def clear(self):
        self.cleared += 1


class _FakeAgent:
    """A project agent whose activate()/deactivate() are observable."""

    def __init__(self, active=False):
        self.is_active = active
        self.activated = 0
        self.deactivated = 0
        self.mailbox = SimpleNamespace(cleared=0)
        self.mailbox.clear = lambda: setattr(self.mailbox, "cleared", self.mailbox.cleared + 1)

    def activate(self):
        self.activated += 1
        self.is_active = True

    def deactivate(self):
        self.deactivated += 1
        self.is_active = False


# --------------------------------------------------------------------------------------
# registerAgent / unregisterAgent
# --------------------------------------------------------------------------------------
class TestAgentRegistration(unittest.TestCase):
    def test_register_appends(self):
        p = _bare_project(agents=_FakeAgents())
        agent = object()
        p.registerAgent(agent)
        self.assertIn(agent, p.agents)

    def test_unregister_absent_agent_is_noop(self):
        p = _bare_project(agents=_FakeAgents())
        p.unregisterAgent(object())
        self.assertEqual(p.agents.removed, [])

    def test_unregister_present_agent_removes_with_flag(self):
        agent = object()
        p = _bare_project(agents=_FakeAgents([agent]))
        p.unregisterAgent(agent, destroy=False)
        self.assertEqual(p.agents.removed, [(agent, False)])


# --------------------------------------------------------------------------------------
# init / deinit
# --------------------------------------------------------------------------------------
class TestInitDeinit(unittest.TestCase):
    def test_init_records_start_and_creates_first_session(self):
        calls = []
        p = _bare_project(createSession=lambda: calls.append("createSession"))
        p.init()
        self.assertIsInstance(p.project_start, float)
        self.assertEqual(calls, ["createSession"])

    def test_deinit_summarizes_when_sessions_ran(self):
        calls = []
        p = _bare_project(session_executed=3, summarize=lambda: calls.append("summarize"))
        p.deinit()
        self.assertEqual(calls, ["summarize"])

    def test_deinit_skips_summary_when_no_sessions(self):
        calls = []
        p = _bare_project(session_executed=0, summarize=lambda: calls.append("summarize"))
        p.deinit()
        self.assertEqual(calls, [])


# --------------------------------------------------------------------------------------
# live() -- per-step tick + optional session timeout
# --------------------------------------------------------------------------------------
def _live_project(**attrs):
    p = _bare_project(**attrs)
    p.sent = []
    p.send = lambda event, *args: p.sent.append((event, args))
    return p


class TestLive(unittest.TestCase):
    def test_step_increments_when_set(self):
        p = _live_project(step=0, session=None)
        p.live()
        self.assertEqual(p.step, 1)

    def test_step_stays_none(self):
        p = _live_project(step=None, session=None)
        p.live()
        self.assertIsNone(p.step)

    def test_no_session_returns_without_timeout_check(self):
        # No session: live() ticks the step then returns before any timeout logic.
        p = _live_project(step=5, session=None)
        p.live()
        self.assertEqual(p.step, 6)
        self.assertEqual(p.sent, [])

    def test_timeout_disabled_does_not_stop(self):
        p = _live_project(step=0, session=object(), use_timeout=False)
        p.live()
        self.assertEqual(p.sent, [])

    def test_timeout_not_reached_does_not_stop(self):
        import time

        p = _live_project(
            step=0,
            session=object(),
            use_timeout=True,
            session_timeout=100.0,
            session_start=time.time(),
        )
        p.live()
        self.assertEqual(p.sent, [])
        self.assertTrue(p.use_timeout)

    def test_timeout_reached_sends_session_stop_and_disarms(self):
        import time

        p = _live_project(
            step=0,
            session=object(),
            use_timeout=True,
            session_timeout=0.01,
            session_start=time.time() - 10,
        )
        p.live()
        self.assertEqual(p.sent, [("session_stop", ())])
        self.assertFalse(p.use_timeout)


# --------------------------------------------------------------------------------------
# summarize / createFilename
# --------------------------------------------------------------------------------------
class TestSummarize(unittest.TestCase):
    def _summary(self, **attrs):
        import time

        msgs = []
        p = _bare_project(project_start=time.time(), aggressivity=0.5, nb_success=2, **attrs)
        p.error = lambda message, *a, **k: msgs.append(message)
        p.summarize()
        return msgs

    def test_summary_includes_session_count_and_success(self):
        msgs = self._summary(session_executed=3, session_total_duration=1.5)
        joined = "\n".join(msgs)
        self.assertIn("3 sessions", joined)
        self.assertIn("Project done", joined)
        self.assertIn("Total: 2 success", joined)

    def test_summary_without_sessions_omits_session_line(self):
        msgs = self._summary(session_executed=0, session_total_duration=0)
        joined = "\n".join(msgs)
        self.assertNotIn("sessions in", joined)
        self.assertIn("Project done", joined)


class TestCreateFilename(unittest.TestCase):
    def test_delegates_to_directory_unique_filename(self):
        seen = []
        directory = SimpleNamespace(
            uniqueFilename=lambda name, count=None: seen.append((name, count)) or "/run/f"
        )
        p = _bare_project(directory=directory)
        result = p.createFilename("crash.txt", count=7)
        self.assertEqual(result, "/run/f")
        self.assertEqual(seen, [("crash.txt", 7)])


# --------------------------------------------------------------------------------------
# initLog
# --------------------------------------------------------------------------------------
class _FakeLogger:
    def __init__(self, filename=None):
        self.filename = filename
        self.file_handler = None
        self.unlinked = 0
        self.handler_calls = []

    def addFileHandler(self, filename, mode="w"):
        self.handler_calls.append((filename, mode))
        return ("handler", filename, mode)

    def unlinkFile(self):
        self.unlinked += 1


class TestInitLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _project_with_logger(self, logger):
        p = _bare_project()
        p.application = lambda: SimpleNamespace(logger=logger)
        dst = os.path.join(self.tmp, "project.log")
        p.createFilename = lambda name, count=None: dst
        return p, dst

    def test_append_branch_copies_existing_log(self):
        src = os.path.join(self.tmp, "fusil.log")
        with open(src, "w") as fh:
            fh.write("previous log\n")
        logger = _FakeLogger(filename=src)
        p, dst = self._project_with_logger(logger)

        p.initLog()

        self.assertTrue(os.path.exists(dst))
        with open(dst) as fh:
            self.assertEqual(fh.read(), "previous log\n")
        self.assertEqual(logger.unlinked, 1)
        self.assertEqual(logger.handler_calls, [(dst, "a")])
        self.assertEqual(logger.filename, dst)
        self.assertEqual(logger.file_handler, ("handler", dst, "a"))

    def test_write_branch_when_no_existing_log(self):
        logger = _FakeLogger(filename=None)
        p, dst = self._project_with_logger(logger)

        p.initLog()

        self.assertFalse(os.path.exists(dst))  # nothing copied
        self.assertEqual(logger.unlinked, 0)
        self.assertEqual(logger.handler_calls, [(dst, "w")])
        self.assertEqual(logger.filename, dst)


# --------------------------------------------------------------------------------------
# createSession
# --------------------------------------------------------------------------------------
def _session_project(**attrs):
    base = dict(
        system_calm=None,
        session_index=0,
        session_timeout=None,
        max_session=0,
        agents=[],
    )
    base.update(attrs)
    p = _bare_project(**base)
    p.sent = []
    p.send = lambda event, *args: p.sent.append((event, args))
    return p


class TestCreateSession(unittest.TestCase):
    def test_builds_session_and_emits_session_start(self):
        p = _session_project()
        with mock.patch("fusil.project.Session") as MockSession:
            p.createSession()
        MockSession.assert_called_once_with(p)
        self.assertIs(p.session, MockSession.return_value)
        self.assertEqual(p.step, 0)
        self.assertEqual(p.session_index, 1)
        self.assertIn(("session_start", ()), p.sent)

    def test_activates_only_inactive_agents(self):
        inactive = _FakeAgent(active=False)
        active = _FakeAgent(active=True)
        p = _session_project(agents=[inactive, active])
        with mock.patch("fusil.project.Session"):
            p.createSession()
        self.assertEqual(inactive.activated, 1)
        self.assertEqual(active.activated, 0)

    def test_waits_for_calm_system_when_configured(self):
        waited = []
        calm = SimpleNamespace(wait=lambda agent: waited.append(agent))
        p = _session_project(system_calm=calm)
        with mock.patch("fusil.project.Session"):
            p.createSession()
        self.assertEqual(waited, [p])

    def test_use_timeout_reflects_session_timeout(self):
        p = _session_project(session_timeout=5.0)
        with mock.patch("fusil.project.Session"):
            p.createSession()
        self.assertTrue(p.use_timeout)

    def test_use_timeout_false_without_timeout(self):
        p = _session_project(session_timeout=None)
        with mock.patch("fusil.project.Session"):
            p.createSession()
        self.assertFalse(p.use_timeout)

    def test_max_session_reports_progress_percent(self):
        msgs = []
        p = _session_project(max_session=10, session_index=0)
        p.error = lambda message, *a, **k: msgs.append(message)
        with mock.patch("fusil.project.Session"):
            p.createSession()
        self.assertTrue(any("10.0%" in m for m in msgs))


# --------------------------------------------------------------------------------------
# destroySession
# --------------------------------------------------------------------------------------
class TestDestroySession(unittest.TestCase):
    def _wire(self, exitcode=0):
        import time

        app_agent = _FakeAgent(active=True)
        proj_agent = _FakeAgent(active=True)
        application = SimpleNamespace(exitcode=exitcode, agents=[app_agent])
        session = SimpleNamespace(deactivated=0)
        session.deactivate = lambda: setattr(session, "deactivated", session.deactivated + 1)
        mta = SimpleNamespace(cleared=0)
        mta.clear = lambda: setattr(mta, "cleared", mta.cleared + 1)
        p = _bare_project(
            session=session,
            session_start=time.time(),
            session_executed=0,
            session_total_duration=0.0,
            agents=[app_agent, proj_agent],
        )
        p.application = lambda: application
        p.mta = lambda: mta
        return p, app_agent, proj_agent, session, mta

    def test_deactivates_session_and_project_agents_only(self):
        p, app_agent, proj_agent, session, mta = self._wire()
        p.destroySession()
        self.assertEqual(session.deactivated, 1)
        # proj_agent is not an application agent -> deactivated; app_agent is -> left alone.
        self.assertEqual(proj_agent.deactivated, 1)
        self.assertEqual(app_agent.deactivated, 0)
        self.assertEqual(app_agent.mailbox.cleared, 1)
        self.assertEqual(mta.cleared, 1)
        self.assertIsNone(p.step)
        self.assertIsNone(p.session)

    def test_counts_session_when_no_fusil_error(self):
        p, *_ = self._wire(exitcode=0)
        p.destroySession()
        self.assertEqual(p.session_executed, 1)

    def test_does_not_count_session_on_fusil_error(self):
        p, *_ = self._wire(exitcode=1)
        p.destroySession()
        self.assertEqual(p.session_executed, 0)


# --------------------------------------------------------------------------------------
# destroy
# --------------------------------------------------------------------------------------
class TestDestroy(unittest.TestCase):
    def _wire(self, keep):
        logger = _FakeLogger()
        directory = SimpleNamespace(rmtreed=0, directory="/run/x")
        directory.keepDirectory = lambda verbose=True: keep
        directory.rmtree = lambda: setattr(directory, "rmtreed", directory.rmtreed + 1)
        application = SimpleNamespace(agents=[object(), object()], logger=logger)
        p = _bare_project(agents=_FakeAgents(), directory=directory)
        p._destroyed = False
        p.application = lambda: application
        return p, directory, logger, application

    def test_keeps_directory_when_requested(self):
        p, directory, logger, application = self._wire(keep=True)
        p.destroy()
        self.assertEqual(directory.rmtreed, 0)
        self.assertEqual(logger.unlinked, 0)
        self.assertIsNone(p.directory)
        self.assertTrue(p._destroyed)
        # Application agents are detached (destroy=False) then the list is cleared.
        self.assertEqual([flag for _, flag in p.agents.removed], [False, False])
        self.assertEqual(p.agents.cleared, 1)

    def test_removes_directory_and_unlinks_log_when_not_kept(self):
        p, directory, logger, application = self._wire(keep=False)
        p.destroy()
        self.assertEqual(directory.rmtreed, 1)
        self.assertEqual(logger.unlinked, 1)
        self.assertIsNone(p.directory)

    def test_already_destroyed_is_noop(self):
        p, directory, logger, application = self._wire(keep=False)
        p._destroyed = True
        p.destroy()
        self.assertEqual(directory.rmtreed, 0)
        self.assertEqual(p.agents.cleared, 0)


# --------------------------------------------------------------------------------------
# Full construction (Project.__init__) against a faked Application.
# --------------------------------------------------------------------------------------
class _ConstructionLogger(_FakeLogger):
    """Adds the MAS logger contract so Agent._log() calls do not fall through to stderr."""

    def __init__(self, filename=None):
        super().__init__(filename=filename)
        self.messages = []

    def debug(self, message, sender=None):
        self.messages.append(("debug", message))

    def info(self, message, sender=None):
        self.messages.append(("info", message))

    def warning(self, message, sender=None):
        self.messages.append(("warning", message))

    def error(self, message, sender=None):
        self.messages.append(("error", message))


class _FakeApplication:
    NAME = "runtest"

    def __init__(self, **opts):
        from fusil.mas.mta import MTA

        self.logger = _ConstructionLogger()
        self.exitcode = 0
        self.agents = []
        self.config = SimpleNamespace(
            fusil_normal_calm_load=0.5,
            fusil_normal_calm_sleep=0.5,
            fusil_success_score=0.5,
            fusil_error_score=-0.5,
        )
        defaults = dict(
            fast=False, slow=True, sessions=0, success=1, aggressivity=None, only_generate=True
        )
        defaults.update(opts)
        self.options = SimpleNamespace(**defaults)
        self._mta = MTA(self)

    def mta(self):
        return self._mta

    def registerAgent(self, agent):
        pass

    def unregisterAgent(self, agent, destroy=True):
        pass


class _FakeProjectDirectory:
    """Filesystem-free stand-in patched over fusil.project.ProjectDirectory."""

    def __init__(self, project, base_dir=None):
        self.directory = "/fake/runtest"
        self.activated = 0

    def activate(self):
        self.activated += 1

    def uniqueFilename(self, name, count=None):
        return "/fake/runtest/" + name

    def keepDirectory(self, verbose=True):
        return True

    def rmtree(self):
        pass


class _AppAgentStub:
    """A pre-existing application agent (MTA/logger-like) handed to Project via
    application.agents; only needs the AgentList teardown contract."""

    def __init__(self):
        self.is_active = False

    def deactivate(self):
        pass

    def unregister(self, destroy=True):
        pass


class TestProjectConstruction(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("fusil.project.ProjectDirectory", _FakeProjectDirectory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _make(self, **opts):
        app = _FakeApplication(**opts)
        p = Project(app)
        # Neutralize GC-time destroy() (fake directory + weakref'd app make it unsafe).
        self.addCleanup(setattr, p, "_destroyed", True)
        return p, app

    def test_wires_config_and_option_derived_state(self):
        p, app = self._make()
        self.assertIs(p.config, app.config)
        self.assertEqual(p.max_session, 0)
        self.assertEqual(p.max_success, 1)
        self.assertEqual(p.success_score, 0.5)
        self.assertEqual(p.error_score, -0.5)
        self.assertEqual(p.nb_success, 0)
        self.assertEqual(p.session_index, 0)
        self.assertFalse(p._destroyed)

    def test_registers_self_and_activates_directory(self):
        p, app = self._make()
        self.assertIn(p, p.agents)
        self.assertEqual(p.directory.activated, 1)

    def test_registers_preexisting_application_agents(self):
        app = _FakeApplication()
        app_agent = _AppAgentStub()
        app.agents = [app_agent]
        p = Project(app)
        self.addCleanup(setattr, p, "_destroyed", True)
        self.assertIn(app_agent, p.agents)
        self.assertIn(p, p.agents)

    def test_initlog_installs_write_handler(self):
        p, app = self._make()
        self.assertEqual(app.logger.handler_calls, [("/fake/runtest/project.log", "w")])
        self.assertIsNotNone(app.logger.file_handler)

    def test_fast_option_disables_system_calm(self):
        p, app = self._make(fast=True)
        self.assertIsNone(p.system_calm)

    def test_slow_default_disables_system_calm(self):
        p, app = self._make(slow=True)
        self.assertIsNone(p.system_calm)

    def test_throttled_mode_creates_system_calm(self):
        # Neither --fast nor --slow -> load throttling on. Patch SystemCalm so no /proc read.
        with mock.patch("fusil.project.SystemCalm") as MockCalm:
            p, app = self._make(fast=False, slow=False)
        MockCalm.assert_called_once_with(0.5, 0.5)
        self.assertIs(p.system_calm, MockCalm.return_value)

    def test_aggressivity_none_defaults_to_floor(self):
        p, app = self._make(aggressivity=None)
        self.assertEqual(p.aggressivity, 0.01)

    def test_aggressivity_value_scaled_to_fraction(self):
        p, app = self._make(aggressivity=50)
        self.assertEqual(p.aggressivity, 0.5)
        self.assertTrue(any("aggressivity" in m.lower() for _, m in app.logger.messages))


if __name__ == "__main__":
    unittest.main()
