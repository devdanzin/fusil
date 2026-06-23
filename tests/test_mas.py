"""Unit tests for the multi-agent-system (MAS) message bus.

The whole fuzzer is built on this substrate, yet it had no tests. Runtime-free: a real
MTA is driven with a stub application (no python-ptrace, no Univers loop), and tiny Agent
subclasses stand in for real agents.
"""

import gc
import unittest

from fusil.mas.agent import Agent, AgentError
from fusil.mas.agent_id import AgentID
from fusil.mas.message import Message
from fusil.mas.mta import MTA


class _StubLogger:
    def debug(self, *a, **k): pass
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass


class _StubApp:
    """Weakref-able stand-in for Application (MTA stores a weakref to it)."""

    def __init__(self):
        self.logger = _StubLogger()

    def registerAgent(self, agent): pass

    def unregisterAgent(self, agent, destroy=True): pass


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


if __name__ == "__main__":
    unittest.main()
