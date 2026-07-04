"""Unit tests for fusil.mas.mta.MTA mailing-list (un)registration.

``registerMailingList`` stores *weakrefs* to mailboxes; ``unregisterMailingList`` must remove
the matching weakref immediately. A prior bug compared the raw mailbox object against the
stored weakrefs (which never matched), so an unregistered-but-still-alive mailbox lingered in
the mailing list until it was GC'd and lazily pruned by ``live()``. Runtime-free.
"""

import unittest

try:
    from fusil.mas.mta import MTA
    from tests.mas_harness import StubApplication

    HAVE_MTA = True
except Exception:  # pragma: no cover - env without the runtime stack
    HAVE_MTA = False


class _Mailbox:
    """A minimal weakref-able stand-in for fusil.mas.mailbox.Mailbox."""


def _mta():
    return MTA(StubApplication())


@unittest.skipUnless(HAVE_MTA, "fusil MAS stack not importable")
class TestMailingList(unittest.TestCase):
    def test_register_stores_a_weakref(self):
        mta = _mta()
        mb = _Mailbox()
        mta.registerMailingList(mb, "foo")
        (ref,) = mta.mailing_list["foo"]
        self.assertIs(ref(), mb)

    def test_register_is_idempotent(self):
        mta = _mta()
        mb = _Mailbox()
        mta.registerMailingList(mb, "foo")
        mta.registerMailingList(mb, "foo")
        self.assertEqual(len(mta.mailing_list["foo"]), 1)

    def test_unregister_removes_immediately(self):
        # The bug: this used to leave the entry in place (raw object != stored weakref).
        mta = _mta()
        mb = _Mailbox()
        mta.registerMailingList(mb, "foo")
        mta.unregisterMailingList(mb, "foo")
        self.assertEqual(mta.mailing_list["foo"], [])

    def test_unregister_unknown_event_is_noop(self):
        _mta().unregisterMailingList(_Mailbox(), "never-registered")

    def test_unregister_other_mailbox_leaves_registration(self):
        mta = _mta()
        registered = _Mailbox()
        mta.registerMailingList(registered, "foo")
        mta.unregisterMailingList(_Mailbox(), "foo")  # a *different* mailbox
        self.assertEqual(len(mta.mailing_list["foo"]), 1)


if __name__ == "__main__":
    unittest.main()
