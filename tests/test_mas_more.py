"""Complementary unit tests for the MAS message bus.

``tests/test_mas.py`` covers the happy paths of Agent/MTA/Univers and the trace hook.
This file targets the remaining branches of the three modules the harness leans on:

* ``fusil.mas.agent`` -- ``__del__`` error/KeyboardInterrupt handling, ``send`` with a
  dead MTA, the ``_log`` helper (including the missing-logger fallbacks), ``live``/``__str__``.
* ``fusil.mas.mailbox`` -- ``unregister`` with a dead MTA, ``deliver`` to a collected
  agent, and ``__repr__`` for live/dead agents.
* ``fusil.mas.application_agent`` -- ``unregister`` (live and dead application).

Runtime-free: a real MTA is driven with a recording-logger stub app; ``__del__`` is invoked
explicitly (deterministic, no reliance on gc timing) except where a collected weakref is the
thing under test.
"""

import gc
import io
import unittest
from unittest import mock

from fusil.mas.agent import Agent
from fusil.mas.application_agent import ApplicationAgent
from fusil.mas.message import Message
from fusil.mas.mta import MTA


class _RecordingLogger:
    """Records (level, message) so tests can assert what an agent logged."""

    def __init__(self):
        self.records = []

    def debug(self, message, sender=None):
        self.records.append(("debug", message))

    def info(self, message, sender=None):
        self.records.append(("info", message))

    def warning(self, message, sender=None):
        self.records.append(("warning", message))

    def error(self, message, sender=None):
        self.records.append(("error", message))


class _App:
    """Weakref-able Application stand-in with a recording logger."""

    def __init__(self):
        self.logger = _RecordingLogger()
        self.registered = []
        self.unregistered = []

    def registerAgent(self, agent):
        self.registered.append(agent)

    def unregisterAgent(self, agent, destroy=True):
        self.unregistered.append((agent, destroy))


def _make_mta():
    app = _App()
    return MTA(app), app


class _Pinger(Agent):
    """Agent that subscribes to the ``ping`` event (so its mailbox registers)."""

    def on_ping(self, *args):
        pass


# -- Agent.__del__ error handling -------------------------------------------------------


class _KIActive(Agent):
    """Stays 'active' through teardown (deactivate is a no-op) and raises KeyboardInterrupt
    from destroy(), so __del__ takes the active -> send('application_interrupt') branch."""

    def deactivate(self):
        pass

    def destroy(self):
        raise KeyboardInterrupt


class _KIActiveSendRaises(_KIActive):
    """Like _KIActive but send() itself raises, exercising the inner ``except`` guard."""

    def send(self, event, *arguments):
        raise RuntimeError("send failed")


class _KIInactive(Agent):
    """Inactive agent that raises KeyboardInterrupt from destroy(): __del__ takes the
    'else' (print) branch."""

    def destroy(self):
        raise KeyboardInterrupt


class _BoomDestroy(Agent):
    """destroy() raises a plain exception: __del__ takes the generic ``except`` branch."""

    def destroy(self):
        raise ValueError("boom")


class TestAgentDel(unittest.TestCase):
    @staticmethod
    def _quiet(agent):
        # __del__ runs again when the object is really collected (unpatched stderr); make
        # that second pass a silent no-op so it does not spam the test output.
        agent.destroy = lambda: None
        agent.is_active = False

    def test_del_keyboardinterrupt_active_sends_interrupt(self):
        mta, _app = _make_mta()
        mta.trace = []
        a = _KIActive("a", mta)
        a.is_active = True  # kept True because deactivate() is overridden to no-op
        a.__del__()
        self.assertIn(("application_interrupt", ()), mta.trace)
        self._quiet(a)

    def test_del_keyboardinterrupt_active_send_error_swallowed(self):
        mta, _app = _make_mta()
        a = _KIActiveSendRaises("a", mta)
        a.is_active = True
        # send() raising must not let anything escape __del__.
        a.__del__()
        self._quiet(a)

    def test_del_keyboardinterrupt_inactive_prints(self):
        mta, _app = _make_mta()
        a = _KIInactive("a", mta)  # never activated -> is_active False
        buf = io.StringIO()
        # agent.py binds `stderr` at import (from sys import stderr), so patch it there.
        with mock.patch("fusil.mas.agent.stderr", buf):
            a.__del__()
        self.assertIn("KeyboardInterrupt during agent destruction", buf.getvalue())
        self._quiet(a)

    def test_del_generic_exception_prints(self):
        mta, _app = _make_mta()
        a = _BoomDestroy("a", mta)
        buf = io.StringIO()
        with mock.patch("fusil.mas.agent.stderr", buf):
            a.__del__()
        self.assertIn("Agent destruction error", buf.getvalue())
        self._quiet(a)


# -- Agent.send / _log / live / __str__ -------------------------------------------------


class TestAgentSend(unittest.TestCase):
    def test_send_with_dead_mta_logs_error(self):
        mta, app = _make_mta()
        a = _Pinger("a", mta)
        a.activate()
        a.mta = lambda: None  # simulate a collected MTA weakref
        a.send("ping", 1)  # must not raise; logs instead
        self.assertTrue(
            any(level == "error" and "MTA is missing" in msg for level, msg in app.logger.records)
        )


class TestAgentLogging(unittest.TestCase):
    def test_log_methods_forward_to_logger(self):
        mta, app = _make_mta()
        a = Agent("a", mta)
        a.debug("d")
        a.info("i")
        a.warning("w")
        a.error("e")
        self.assertEqual(
            app.logger.records,
            [("debug", "d"), ("info", "i"), ("warning", "w"), ("error", "e")],
        )

    def test_log_missing_logger_method_non_error_is_silent(self):
        mta, _app = _make_mta()
        a = Agent("a", mta)
        a.logger = object()  # has no debug()
        buf = io.StringIO()
        with mock.patch("fusil.mas.agent.stderr", buf):
            a.debug("x")  # AttributeError -> silent return
        self.assertEqual(buf.getvalue(), "")

    def test_log_missing_logger_method_error_prints_fallback(self):
        mta, _app = _make_mta()
        a = Agent("a", mta)
        a.logger = object()  # has no error()
        buf = io.StringIO()
        with mock.patch("fusil.mas.agent.stderr", buf):
            a.error("boom")
        out = buf.getvalue()
        self.assertIn("(no logger)", out)
        self.assertIn("boom", out)


class TestAgentMisc(unittest.TestCase):
    def test_base_live_is_noop(self):
        mta, _app = _make_mta()
        self.assertIsNone(Agent("a", mta).live())

    def test_str_includes_name(self):
        mta, _app = _make_mta()
        self.assertEqual(str(Agent("widget", mta)), "<Agent 'widget'>")

    def test_str_on_partially_constructed_agent(self):
        # __del__'s handler stringifies self; __str__ must survive a missing name.
        a = Agent.__new__(Agent)
        self.assertEqual(str(a), "<Agent '?'>")


# -- Mailbox ----------------------------------------------------------------------------


class TestMailbox(unittest.TestCase):
    def test_unregister_with_dead_mta_returns_early(self):
        app = _App()
        mta = MTA(app)
        agent = _Pinger("p", mta)
        mailbox = agent.mailbox
        # app.registered retains a strong ref to the MTA, so drop app too.
        del agent, mta, app
        gc.collect()
        self.assertIsNone(mailbox.mta())
        # No MTA to talk to: unregister() must return without error.
        mailbox.unregister()

    def test_deliver_to_dead_agent_unregisters_and_drops(self):
        mta, _app = _make_mta()
        agent = _Pinger("p", mta)
        mailbox = agent.mailbox
        self.assertIn("ping", mailbox.events)
        del agent
        gc.collect()
        self.assertIsNone(mailbox.agent())
        mailbox.deliver(Message("ping", (1,)))
        self.assertEqual(mailbox.messages, [])

    def test_deliver_to_inactive_agent_drops(self):
        mta, _app = _make_mta()
        agent = _Pinger("p", mta)  # constructed but not activated
        agent.mailbox.deliver(Message("ping", (1,)))
        self.assertEqual(agent.mailbox.messages, [])

    def test_repr_with_live_agent(self):
        mta, _app = _make_mta()
        agent = _Pinger("p", mta)
        self.assertIn("Mailbox of", repr(agent.mailbox))

    def test_repr_with_dead_agent(self):
        mta, _app = _make_mta()
        agent = _Pinger("p", mta)
        mailbox = agent.mailbox
        del agent
        gc.collect()
        self.assertEqual(repr(mailbox), "<Mailbox>")


# -- ApplicationAgent -------------------------------------------------------------------


class TestApplicationAgent(unittest.TestCase):
    def test_construction_registers_with_application(self):
        app = _App()
        mta = MTA(app)
        aa = ApplicationAgent("aa", app, mta)
        self.assertIn(aa, app.registered)

    def test_unregister_calls_application(self):
        app = _App()
        mta = MTA(app)
        aa = ApplicationAgent("aa", app, mta)
        aa.unregister()
        self.assertEqual(app.unregistered[-1], (aa, True))

    def test_unregister_passes_destroy_flag(self):
        app = _App()
        mta = MTA(app)
        aa = ApplicationAgent("aa", app, mta)
        aa.unregister(destroy=False)
        self.assertEqual(app.unregistered[-1], (aa, False))

    def test_unregister_with_dead_application_is_noop(self):
        app = _App()
        mta = MTA(app)
        aa = ApplicationAgent("aa", app, mta)
        aa.application = lambda: None  # simulate a collected application weakref
        aa.unregister()
        self.assertEqual(app.unregistered, [])


if __name__ == "__main__":
    unittest.main()
