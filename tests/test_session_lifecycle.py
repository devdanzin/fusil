"""Safety-net tests for the session lifecycle + scoring control flow.

This is the coverage the complexity report (doc/complexity-reduction-report.md §3.1) says
must exist *before* a MAS -> direct-pipeline rewrite: the session keep/drop crash-dir
decision, the score aggregation, the stop-trigger threshold, and the per-session loop
control. They pin the *observable behaviour* so a rewrite that preserves it stays green
and one that breaks it fails.

The event graph these tests pin (one edge per test), happy path:

    Project.init -> createSession() ----------------------------> send "session_start"
    (each univers step) Session.live() -- score crosses band --> send "session_stop"
    Session.on_session_stop() -- computeScore(verbose) --------> send "session_done"(score)
    Project.on_session_done(score) ---------------------------> send "project_session_destroy"(score)
    Project.on_project_session_destroy(score):
        session.score = score
        destroySession()
        success?  -> nb_success++  -> max_success hit? -> send "univers_stop" (STOP)
        max_session hit?                                -> send "univers_stop" (STOP)
        otherwise                                       -> createSession()      (LOOP)

    Stop path:  Project.on_project_stop -> send "univers_stop"
                Project.on_univers_stop -> destroySession()

The crash dir is produced out-of-band by SessionDirectory.deinit ->
checkKeepDirectory() -> keepDirectory()/rmtree(), tested in test_session_directory.py.

Runtime-free: bare instances (``__new__``) with the collaborators each method touches
stubbed out -- no MTA loop, no python-ptrace, no filesystem.
"""

import unittest
from types import SimpleNamespace

from fusil.project import Project
from fusil.project_agent import ProjectAgent
from fusil.session import Session


class _ScoreAgent(ProjectAgent):
    """A ProjectAgent whose getScore() is fixed. Bypasses Agent.__init__ (no MTA needed);
    computeScore only reads __class__, is_active and getScore()."""

    def __init__(self, score, active=True):
        self._score = score
        self.is_active = active

    def getScore(self):
        return self._score


class _AppAgent:
    """A non-ProjectAgent (stands in for an application agent like MTA/logger): must be
    skipped by computeScore even though it exposes a getScore()."""

    is_active = True

    def getScore(self):
        return 1.0


def _session(agents, success_score=0.5, error_score=-0.5):
    s = Session.__new__(Session)
    s.project = lambda: SimpleNamespace(
        agents=agents, success_score=success_score, error_score=error_score
    )
    s.score = None
    s.info = lambda *a, **k: None
    return s


class TestComputeScore(unittest.TestCase):
    def test_sums_active_project_agents(self):
        s = _session([_ScoreAgent(0.3), _ScoreAgent(0.2)])
        self.assertAlmostEqual(s.computeScore(), 0.5)

    def test_skips_inactive_agents(self):
        s = _session([_ScoreAgent(0.3), _ScoreAgent(1.0, active=False)])
        self.assertAlmostEqual(s.computeScore(), 0.3)

    def test_skips_none_scores(self):
        s = _session([_ScoreAgent(0.4), _ScoreAgent(None)])
        self.assertAlmostEqual(s.computeScore(), 0.4)

    def test_skips_non_project_agents(self):
        # _AppAgent.getScore() == 1.0 but it is not a ProjectAgent, so it must not count.
        s = _session([_ScoreAgent(0.25), _AppAgent()])
        self.assertAlmostEqual(s.computeScore(), 0.25)

    def test_normalizes_each_score_before_summing(self):
        # 2.0 clamps to 1.0, -3.0 clamps to -1.0 -> net 0.0 (per-agent clamp, then sum).
        s = _session([_ScoreAgent(2.0), _ScoreAgent(-3.0)])
        self.assertAlmostEqual(s.computeScore(), 0.0)

    def test_rounds_each_score_to_two_dp(self):
        s = _session([_ScoreAgent(0.333)])
        self.assertAlmostEqual(s.computeScore(), 0.33)

    def test_no_agents_scores_zero(self):
        self.assertEqual(_session([]).computeScore(), 0)


class TestIsSuccess(unittest.TestCase):
    def test_none_score_is_not_success(self):
        s = _session([])
        s.score = None
        self.assertFalse(s.isSuccess())

    def test_score_at_threshold_is_success(self):
        s = _session([], success_score=0.5)
        s.score = 0.5
        self.assertTrue(s.isSuccess())

    def test_score_below_threshold_is_not_success(self):
        s = _session([], success_score=0.5)
        s.score = 0.49
        self.assertFalse(s.isSuccess())


def _live_session(score, *, stopped=False, success=0.5, error=-0.5):
    s = Session.__new__(Session)
    s.project = lambda: SimpleNamespace(success_score=success, error_score=error)
    s.stopped = stopped
    s.info = lambda *a, **k: None
    s.sent = []
    s.send = lambda event, *args: s.sent.append((event, args))
    s.computeScore = lambda verbose=False: score
    return s


class TestSessionLiveStopTrigger(unittest.TestCase):
    def test_neutral_score_does_not_stop(self):
        s = _live_session(0.0)
        s.live()
        self.assertEqual(s.sent, [])

    def test_success_threshold_triggers_stop(self):
        s = _live_session(0.6)
        s.live()
        self.assertEqual(s.sent, [("session_stop", ())])

    def test_error_threshold_triggers_stop(self):
        s = _live_session(-0.6)
        s.live()
        self.assertEqual(s.sent, [("session_stop", ())])

    def test_exact_success_threshold_triggers_stop(self):
        s = _live_session(0.5)
        s.live()
        self.assertEqual(s.sent, [("session_stop", ())])

    def test_already_stopped_is_noop(self):
        s = _live_session(0.9, stopped=True)
        s.live()
        self.assertEqual(s.sent, [])


class TestSessionOnStop(unittest.TestCase):
    def test_emits_session_done_with_score_and_sets_stopped(self):
        s = _live_session(0.0)  # live() not used here
        s.computeScore = lambda verbose=False: 0.7
        s.on_session_stop()
        self.assertTrue(s.stopped)
        self.assertEqual(s.sent, [("session_done", (0.7,))])

    def test_second_call_is_noop(self):
        s = _live_session(0.0)
        s.computeScore = lambda verbose=False: 0.7
        s.on_session_stop()
        s.sent.clear()
        s.on_session_stop()
        self.assertEqual(s.sent, [])


def _project(*, nb_success=0, max_success=0, max_session=0, session_index=1, success_score=0.5):
    p = Project.__new__(Project)
    # This bare stub is never fully constructed; mark it already-destroyed so Project.destroy
    # (called from Agent.__del__ at GC) short-circuits instead of running its full-init body.
    # Agent.__str__/__repr__ are getattr-robust, so no name/is_active/mailbox are needed.
    p._destroyed = True
    p.success_score = success_score
    p.error_score = -0.5
    p.nb_success = nb_success
    p.max_success = max_success
    p.max_session = max_session
    p.session_index = session_index
    p.session = SimpleNamespace(score=None)
    p.session_start = 0.0  # on_project_session_destroy only uses this for a log line
    p.error = lambda *a, **k: None
    p.warning = lambda *a, **k: None
    p.calls = []
    p.send = lambda event, *args: p.calls.append(("send", event, args))
    p.createSession = lambda: p.calls.append(("createSession",))
    p.destroySession = lambda: p.calls.append(("destroySession",))
    return p


def _events(p):
    return [c[1] for c in p.calls if c[0] == "send"]


class TestOnSessionDone(unittest.TestCase):
    def test_forwards_score_to_project_session_destroy(self):
        p = _project()
        p.on_session_done(0.42)
        self.assertEqual(p.calls, [("send", "project_session_destroy", (0.42,))])


class TestSessionLoopControl(unittest.TestCase):
    """Project.on_project_session_destroy: the per-session loop decision."""

    def test_records_score_and_always_destroys_session(self):
        p = _project()
        p.on_project_session_destroy(0.1)
        self.assertEqual(p.session.score, 0.1)
        self.assertIn(("destroySession",), p.calls)

    def test_success_increments_and_loops_when_unlimited(self):
        p = _project(max_success=0, max_session=0)
        p.on_project_session_destroy(0.6)
        self.assertEqual(p.nb_success, 1)
        self.assertIn(("createSession",), p.calls)
        self.assertNotIn("univers_stop", _events(p))

    def test_non_success_does_not_increment_but_loops(self):
        p = _project()
        p.on_project_session_destroy(0.1)
        self.assertEqual(p.nb_success, 0)
        self.assertIn(("createSession",), p.calls)

    def test_max_success_reached_stops(self):
        p = _project(max_success=1)
        p.on_project_session_destroy(0.6)
        self.assertEqual(p.nb_success, 1)
        self.assertIn("univers_stop", _events(p))
        self.assertNotIn(("createSession",), p.calls)

    def test_max_session_reached_stops(self):
        p = _project(max_session=1, session_index=1)
        p.on_project_session_destroy(0.1)  # not a success
        self.assertIn("univers_stop", _events(p))
        self.assertNotIn(("createSession",), p.calls)

    def test_success_under_cap_then_max_session_stops(self):
        # success (nb 1 < max_success 2, no stop) but session cap hit -> stop, no loop.
        p = _project(max_success=2, max_session=1, session_index=1)
        p.on_project_session_destroy(0.6)
        self.assertEqual(p.nb_success, 1)
        self.assertIn("univers_stop", _events(p))
        self.assertNotIn(("createSession",), p.calls)


class TestStopPath(unittest.TestCase):
    def test_project_stop_requests_univers_stop(self):
        p = _project()
        p.on_project_stop()
        self.assertEqual(_events(p), ["univers_stop"])

    def test_univers_stop_destroys_active_session(self):
        p = _project()
        p.on_univers_stop()
        self.assertIn(("destroySession",), p.calls)

    def test_univers_stop_without_session_is_noop(self):
        p = _project()
        p.session = None
        p.on_univers_stop()
        self.assertEqual(p.calls, [])


if __name__ == "__main__":
    unittest.main()
