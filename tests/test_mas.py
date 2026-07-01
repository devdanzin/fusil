"""Unit tests for the multi-agent-system (MAS) message bus.

The whole fuzzer is built on this substrate, yet it had no tests. Runtime-free: a real
MTA is driven with a stub application (no python-ptrace, no Univers loop), and tiny Agent
subclasses stand in for real agents.
"""

import gc
import unittest
from types import SimpleNamespace

from fusil.mas.agent import Agent, AgentError
from fusil.mas.agent_id import AgentID
from fusil.mas.message import Message
from fusil.mas.mta import MTA
from fusil.mas.univers import Univers


class _StubLogger:
    def debug(self, *a, **k):
        pass

    def info(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


class _StubApp:
    """Weakref-able stand-in for Application (MTA stores a weakref to it)."""

    def __init__(self):
        self.logger = _StubLogger()

    def registerAgent(self, agent):
        pass

    def unregisterAgent(self, agent, destroy=True):
        pass


def _make_mta():
    """A real MTA backed by a stub application (kept alive by the caller via the return)."""
    app = _StubApp()
    return MTA(app), app


class Recorder(Agent):
    """Agent that records the arguments of every `ping` event it receives."""

    def __init__(self, name, mta):
        super().__init__(name, mta)
        self.received = []

    def on_ping(self, *args):
        self.received.append(args)


class Mute(Agent):
    """Agent with no event handlers (subscribes to nothing)."""


class TestAgentID(unittest.TestCase):
    def test_singleton(self):
        self.assertIs(AgentID(), AgentID())

    def test_generate_is_monotonic(self):
        a = AgentID().generate()
        b = AgentID().generate()
        self.assertEqual(b, a + 1)


class TestGetEvents(unittest.TestCase):
    def test_collects_on_prefixed_methods(self):
        mta, _app = _make_mta()
        rec = Recorder("r", mta)
        self.assertIn("ping", rec.getEvents())

    def test_no_handlers_means_no_events(self):
        mta, _app = _make_mta()
        self.assertEqual(Mute("m", mta).getEvents(), set())


class TestMessageDispatch(unittest.TestCase):
    def test_calls_matching_handler(self):
        mta, _app = _make_mta()
        rec = Recorder("r", mta)
        Message("ping", (1, 2))(rec)
        self.assertEqual(rec.received, [(1, 2)])

    def test_unknown_event_is_noop(self):
        mta, _app = _make_mta()
        rec = Recorder("r", mta)
        Message("nonexistent_event", ())(rec)  # must not raise
        self.assertEqual(rec.received, [])


class TestSend(unittest.TestCase):
    def test_inactive_agent_cannot_send(self):
        mta, _app = _make_mta()
        rec = Recorder("r", mta)
        with self.assertRaises(AgentError):
            rec.send("ping")


class TestDelivery(unittest.TestCase):
    def test_subscriber_receives_after_live_and_readmailbox(self):
        mta, _app = _make_mta()
        sender = Recorder("s", mta)
        sender.activate()
        receiver = Recorder("r", mta)
        receiver.activate()
        sender.send("ping", 42)
        mta.live()  # MTA delivers queued messages into subscriber mailboxes
        receiver.readMailbox()  # mailbox -> on_ping
        self.assertIn((42,), receiver.received)

    def test_non_subscriber_does_not_receive(self):
        mta, _app = _make_mta()
        sender = Recorder("s", mta)
        sender.activate()
        mute = Mute("m", mta)
        mute.activate()
        sender.send("ping", 1)
        mta.live()
        # Mute has no mailbox subscription for 'ping' and no on_ping handler.
        self.assertEqual(mute.readMailbox(), 0)

    def test_inactive_subscriber_drops_message(self):
        mta, _app = _make_mta()
        sender = Recorder("s", mta)
        sender.activate()
        receiver = Recorder("r", mta)  # NOT activated
        sender.send("ping", 1)
        mta.live()
        self.assertEqual(receiver.mailbox.popMessages(), [])

    def test_dead_mailbox_is_pruned_on_live(self):
        mta, _app = _make_mta()
        sender = Recorder("s", mta)
        sender.activate()
        transient = Recorder("t", mta)
        transient.activate()
        self.assertEqual(len(mta.mailing_list["ping"]), 2)  # both Recorders subscribe to ping
        del transient
        gc.collect()
        sender.send("ping")
        mta.live()  # encounters the dead weakref and prunes it
        self.assertEqual(len(mta.mailing_list["ping"]), 1)


class Lifecycle(Agent):
    """Records init/deinit so activate/deactivate transitions can be asserted."""

    def __init__(self, name, mta):
        super().__init__(name, mta)
        self.events = []

    def init(self):
        self.events.append("init")

    def deinit(self):
        self.events.append("deinit")


class TestAgentLifecycle(unittest.TestCase):
    def test_activate_calls_init_and_sets_active(self):
        mta, _app = _make_mta()
        a = Lifecycle("a", mta)
        self.assertFalse(a.is_active)
        a.activate()
        self.assertTrue(a.is_active)
        self.assertEqual(a.events, ["init"])

    def test_double_activate_raises(self):
        mta, _app = _make_mta()
        a = Lifecycle("a", mta)
        a.activate()
        with self.assertRaises(AgentError):
            a.activate()

    def test_deactivate_calls_deinit_and_clears_active(self):
        mta, _app = _make_mta()
        a = Lifecycle("a", mta)
        a.activate()
        a.events.clear()
        a.deactivate()
        self.assertFalse(a.is_active)
        self.assertEqual(a.events, ["deinit"])

    def test_deactivate_when_inactive_is_noop(self):
        mta, _app = _make_mta()
        a = Lifecycle("a", mta)
        a.deactivate()  # never activated
        self.assertEqual(a.events, [])


class StepAgent(Agent):
    """Records the order of readMailbox/live calls a univers step makes."""

    def __init__(self, name, mta):
        super().__init__(name, mta)
        self.steps = []

    def readMailbox(self):
        self.steps.append("read")
        return 0

    def live(self):
        self.steps.append("live")


class TestUnivers(unittest.TestCase):
    def test_execute_agent_skips_inactive(self):
        mta, app = _make_mta()
        u = Univers(app, mta, 0)
        a = StepAgent("a", mta)  # not activated
        u.executeAgent(a)
        self.assertEqual(a.steps, [])

    def test_execute_agent_reads_then_lives(self):
        mta, app = _make_mta()
        u = Univers(app, mta, 0)
        a = StepAgent("a", mta)
        a.activate()
        u.executeAgent(a)
        self.assertEqual(a.steps, ["read", "live"])

    def test_execute_stops_when_is_done(self):
        # A step loop that never sets is_done would hang; Stopper.live sets it on the
        # first pass, so execute() must run one step and return.
        mta, app = _make_mta()
        u = Univers(app, mta, 0)

        class Stopper(Agent):
            def live(self):
                u.is_done = True

        s = Stopper("s", mta)
        s.activate()
        project = SimpleNamespace(agents=[s])
        u.execute(project)  # must return, not hang
        self.assertTrue(u.is_done)


class TestEventTrace(unittest.TestCase):
    """The opt-in MTA.trace instrumentation (refactor-safety aid): records the full
    (event, args) sequence flowing through the bus, in send order."""

    def test_trace_is_off_by_default(self):
        mta, _app = _make_mta()
        self.assertIsNone(mta.trace)
        sender = Recorder("s", mta)
        sender.activate()
        sender.send("ping", 1)  # must not raise / must not record
        self.assertIsNone(mta.trace)

    def test_trace_records_events_in_send_order(self):
        mta, _app = _make_mta()
        mta.trace = []
        sender = Recorder("s", mta)
        sender.activate()
        sender.send("ping", 1)
        sender.send("ping", 2, 3)
        sender.send("pong")
        self.assertEqual(
            mta.trace,
            [("ping", (1,)), ("ping", (2, 3)), ("pong", ())],
        )

    def test_trace_records_even_without_subscribers(self):
        # deliver() is the choke point: an event with no subscriber is still recorded
        # (it is queued and then dropped by live()), so the trace reflects intent to send.
        mta, _app = _make_mta()
        mta.trace = []
        sender = Recorder("s", mta)
        sender.activate()
        sender.send("no_subscriber_event", 42)
        self.assertEqual(mta.trace, [("no_subscriber_event", (42,))])


if __name__ == "__main__":
    unittest.main()
