"""Unit tests for fusil.unsafe.permissionHelp — the "how to fix a permission error" hint.

The helper composes a human-readable suggestion out of two conditions: not being root
(``getuid() != 0`` -> "retry as root") and not having passed ``--unsafe``
(-> "use --unsafe option"). It returns None when neither applies. ``getuid`` is mocked so
the tests are deterministic regardless of who runs them (and never need real privileges).
"""

import unittest
from types import SimpleNamespace
from unittest import mock


def _options(unsafe):
    return SimpleNamespace(unsafe=unsafe)


class TestPermissionHelp(unittest.TestCase):
    def _help(self, uid, unsafe):
        with mock.patch("fusil.unsafe.getuid", return_value=uid):
            from fusil.unsafe import permissionHelp

            return permissionHelp(_options(unsafe))

    def test_non_root_and_not_unsafe_suggests_both(self):
        self.assertEqual(
            self._help(uid=1000, unsafe=False),
            "retry as root or use --unsafe option",
        )

    def test_non_root_but_unsafe_suggests_only_root(self):
        self.assertEqual(self._help(uid=1000, unsafe=True), "retry as root")

    def test_root_but_not_unsafe_suggests_only_unsafe(self):
        self.assertEqual(self._help(uid=0, unsafe=False), "use --unsafe option")

    def test_root_and_unsafe_returns_none(self):
        self.assertIsNone(self._help(uid=0, unsafe=True))


if __name__ == "__main__":
    unittest.main()
