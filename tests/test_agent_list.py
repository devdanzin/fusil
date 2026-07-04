"""Unit tests for fusil.mas.agent_list.AgentList — the registry of active agents.

AgentList is the collection the MTA/Project use to hold agents; remove/clear also drive each
agent's deactivate()/unregister() teardown and must swallow ptrace errors during deinit.
Runtime-free: exercised with tiny fake agents (no real MAS). python-ptrace is imported by the
module, so the suite skips cleanly where it is unavailable.
"""

import unittest

try:
    from ptrace.error import PTRACE_ERRORS

    from fusil.mas.agent_list import AgentList

    HAVE_PTRACE = True
except Exception:  # pragma: no cover - env without python-ptrace
    HAVE_PTRACE = False


class FakeAgent:
    def __init__(self, deactivate_error=None):
        self.deactivated = 0
        self.unregistered = []
        self._deactivate_error = deactivate_error

    def deactivate(self):
        self.deactivated += 1
        if self._deactivate_error is not None:
            raise self._deactivate_error

    def unregister(self, destroy=True):
        self.unregistered.append(destroy)


@unittest.skipUnless(HAVE_PTRACE, "python-ptrace not importable")
class TestAgentList(unittest.TestCase):
    def test_append_and_membership(self):
        lst = AgentList()
        a = FakeAgent()
        lst.append(a)
        self.assertIn(a, lst)
        self.assertEqual(list(lst), [a])

    def test_append_duplicate_raises(self):
        lst = AgentList()
        a = FakeAgent()
        lst.append(a)
        with self.assertRaises(KeyError):
            lst.append(a)

    def test_remove_destroys_by_default(self):
        lst = AgentList()
        a = FakeAgent()
        lst.append(a)
        lst.remove(a)
        self.assertNotIn(a, lst)
        self.assertEqual(a.deactivated, 1)
        self.assertEqual(a.unregistered, [False])  # _destroy calls unregister(False)

    def test_remove_without_destroy_leaves_agent_untouched(self):
        lst = AgentList()
        a = FakeAgent()
        lst.append(a)
        lst.remove(a, destroy=False)
        self.assertNotIn(a, lst)
        self.assertEqual(a.deactivated, 0)
        self.assertEqual(a.unregistered, [])

    def test_remove_non_member_is_noop(self):
        lst = AgentList()
        a = FakeAgent()
        lst.remove(a)  # not present -> silently ignored
        self.assertEqual(a.deactivated, 0)

    def test_clear_destroys_all(self):
        lst = AgentList()
        agents = [FakeAgent() for _ in range(3)]
        for a in agents:
            lst.append(a)
        lst.clear()
        self.assertEqual(list(lst), [])
        for a in agents:
            self.assertEqual(a.deactivated, 1)
            self.assertEqual(a.unregistered, [False])

    def test_destroy_swallows_ptrace_errors(self):
        # A ptrace error during deactivate() must not abort teardown; unregister still runs.
        # PTRACE_ERRORS may be a single exception class or a tuple of them, depending on the
        # python-ptrace version.
        exc_type = PTRACE_ERRORS if isinstance(PTRACE_ERRORS, type) else PTRACE_ERRORS[0]
        a = FakeAgent(deactivate_error=exc_type("boom"))
        lst = AgentList()
        lst.append(a)
        lst.remove(a)  # must not raise
        self.assertNotIn(a, lst)
        self.assertEqual(a.unregistered, [False])


if __name__ == "__main__":
    unittest.main()
