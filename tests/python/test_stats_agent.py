"""Wiring tests for StatsAgent (fusil/python/stats_agent.py).

Skip-guarded like test_oom_dedup_wiring: importing StatsAgent pulls the runtime stack
(ProjectAgent / fusil.python), absent on some boxes. We avoid constructing the full MAS by
building a bare instance via object.__new__ and driving its on_* handlers directly with
SimpleNamespace fakes -- exactly the "test the contract, not the machinery" approach.
"""

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

try:
    from fusil.python.session_stats import SessionStats
    from fusil.python.stats_agent import StatsAgent

    HAVE = True
except Exception:  # noqa: BLE001 -- runtime stack (python-ptrace) may be absent
    HAVE = False


@unittest.skipUnless(HAVE, "requires the fusil runtime stack (python-ptrace)")
class TestStatsAgentWiring(unittest.TestCase):
    def _agent(self, tmp, module="json"):
        """A StatsAgent wired to fakes, without running ProjectAgent.__init__/the MAS."""
        agent = object.__new__(StatsAgent)
        agent.source = SimpleNamespace(module_name=module)
        agent.stats = SessionStats(started_at=0.0, clock=lambda: 1.0)
        agent._rename_parts = []
        agent._path = None
        agent._last_flush = 0.0
        fake_project = SimpleNamespace(
            success_score=0.5,
            createFilename=lambda name: os.path.join(tmp, name),
        )
        agent.project = lambda: fake_project
        agent.error = lambda *a, **k: None
        return agent

    def test_score_neutral(self):
        # StatsAgent must NOT influence scoring -> inherits ProjectAgent.getScore() == None.
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp)
            self.assertIsNone(agent.getScore())

    def test_crash_counted_per_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, module="json")
            agent.on_session_start()
            agent.on_session_rename("json")
            agent.on_session_rename("sigsegv")
            agent.on_session_done(0.75)  # >= success_score -> crash
            self.assertEqual(agent.stats.sessions, 1)
            self.assertEqual(agent.stats.crashes, 1)
            self.assertEqual(agent.stats.modules["json"]["crashes"], 1)

    def test_non_crash_not_counted_as_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, module="json")
            agent.on_session_start()
            agent.on_session_done(0.0)  # below success_score
            self.assertEqual(agent.stats.crashes, 0)
            self.assertEqual(agent.stats.modules["json"]["hits"], 1)

    def test_timeout_and_cpu_load_via_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, module="slowmod")
            agent.on_session_start()
            agent.on_session_rename("slowmod")
            agent.on_session_rename("timeout")
            agent.on_session_done(0.0)  # timeouts score 0 by default -> must be seen via rename
            self.assertEqual(agent.stats.timeouts, 1)

            agent.on_session_start()  # resets rename parts
            agent.on_session_rename("cpu_load")
            agent.on_session_done(0.0)
            self.assertEqual(agent.stats.cpu_load_kills, 1)

    def test_flush_writes_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._agent(tmp, module="json")
            agent.on_session_start()
            agent.on_session_done(0.0)
            agent._maybe_flush(force=True)
            path = os.path.join(tmp, "fusil_stats.json")
            self.assertTrue(os.path.exists(path))
            self.assertEqual(SessionStats.load(path)["sessions"], 1)


if __name__ == "__main__":
    unittest.main()
