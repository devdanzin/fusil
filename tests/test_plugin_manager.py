"""Unit tests for the PluginManager registration API (Phase A additions).

Covers the newer hooks a plugin needs to express deep, per-type fuzzing:
instance dispatchers, class handlers, and the blacklist/whitelist name filters.
Runtime-free (no python-ptrace / subprocess); imports only fusil.plugin_manager.
"""

import unittest

from fusil.plugin_manager import PluginManager


class TestInstanceDispatchers(unittest.TestCase):
    def test_register_and_get(self):
        m = PluginManager()
        self.assertEqual(m.get_instance_dispatchers(), [])

        def d(writer, prefix, target, hint, depth):
            return None

        m.add_instance_dispatcher(d)
        self.assertEqual(m.get_instance_dispatchers(), [d])

    def test_order_preserved(self):
        m = PluginManager()
        funcs = [lambda *a: None for _ in range(3)]
        for f in funcs:
            m.add_instance_dispatcher(f)
        self.assertEqual(m.get_instance_dispatchers(), funcs)


class TestClassHandlers(unittest.TestCase):
    def test_register_and_get(self):
        m = PluginManager()
        self.assertEqual(m.get_class_handlers(), [])

        def h(writer, name, typ, var, prefix):
            return False

        m.add_class_handler(h)
        self.assertEqual(m.get_class_handlers(), [h])


class TestBlacklistWhitelist(unittest.TestCase):
    def test_exact_blacklist_is_kind_scoped(self):
        m = PluginManager()
        m.add_blacklist_entry("method", "_rehash")
        self.assertTrue(m.is_blacklisted("method", "_rehash"))
        self.assertFalse(m.is_blacklisted("method", "other"))
        # kind-scoped: a 'method' entry does not match a 'class' query
        self.assertFalse(m.is_blacklisted("class", "_rehash"))

    def test_glob_blacklist(self):
        m = PluginManager()
        m.add_blacklist_entry("class", "*Test", pattern_type="glob")
        self.assertTrue(m.is_blacklisted("class", "FooTest"))
        self.assertTrue(m.is_blacklisted("class", "Test"))
        self.assertFalse(m.is_blacklisted("class", "TestCase"))  # trailing chars
        self.assertFalse(m.is_blacklisted("class", "Foo"))

    def test_whitelist(self):
        m = PluginManager()
        m.add_whitelist_entry("method", "__del__")
        self.assertTrue(m.is_whitelisted("method", "__del__"))
        self.assertFalse(m.is_whitelisted("method", "__init__"))

    def test_empty_manager_matches_nothing(self):
        m = PluginManager()
        self.assertFalse(m.is_blacklisted("method", "anything"))
        self.assertFalse(m.is_whitelisted("method", "anything"))


class TestSuppressionEntries(unittest.TestCase):
    def test_register_and_get_pairs(self):
        m = PluginManager()
        m.add_suppression_entry(r"dictobject\.c:205", reason="known FT assert")
        m.add_suppression_entry("segfault")  # reason defaults to None
        self.assertEqual(
            m.get_suppression_entries(),
            [(r"dictobject\.c:205", "known FT assert"), ("segfault", None)],
        )

    def test_empty_manager_has_no_entries(self):
        self.assertEqual(PluginManager().get_suppression_entries(), [])


class TestStdoutIgnoreRegexes(unittest.TestCase):
    def test_register_and_get(self):
        m = PluginManager()
        m.add_stdout_ignore_regex("Exception from weird subclass")
        m.add_stdout_ignore_regex("C-API level error simulation")
        self.assertEqual(
            m.get_stdout_ignore_regexes(),
            ["Exception from weird subclass", "C-API level error simulation"],
        )

    def test_empty_manager_has_no_ignores(self):
        self.assertEqual(PluginManager().get_stdout_ignore_regexes(), [])

    def test_getter_returns_a_copy(self):
        m = PluginManager()
        m.add_stdout_ignore_regex("foo")
        got = m.get_stdout_ignore_regexes()
        got.append("bar")
        self.assertEqual(m.get_stdout_ignore_regexes(), ["foo"])


if __name__ == "__main__":
    unittest.main()
