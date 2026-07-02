"""Structural-invariant tests for fusil.python.blacklists.

This is a pure-data module that's edited fairly often; these tests are a cheap regression
net against malformed entries and accidental deletion of important blacklist items.
"""

import unittest

from fusil.python import blacklists as bl


class TestContainerShapes(unittest.TestCase):
    def test_flat_blacklists_are_string_sets(self):
        for name in ("MODULE_BLACKLIST", "OBJECT_BLACKLIST", "METHOD_BLACKLIST", "BUILTINS"):
            container = getattr(bl, name)
            self.assertIsInstance(container, set, name)
            self.assertTrue(all(isinstance(x, str) for x in container), name)

    def test_blacklist_is_dict_of_string_sets(self):
        self.assertIsInstance(bl.BLACKLIST, dict)
        for key, value in bl.BLACKLIST.items():
            self.assertIsInstance(key, str, key)
            self.assertIsInstance(value, set, key)
            self.assertTrue(all(isinstance(x, str) for x in value), key)

    def test_module_class_keys_have_nonempty_parts(self):
        # Keys of the form "module:Class" must have both parts non-empty (guards typos like
        # a stray leading-underscore module name).
        for key in bl.BLACKLIST:
            if ":" in key:
                module, _, klass = key.partition(":")
                self.assertTrue(module and klass, f"malformed module:class key {key!r}")


class TestKnownEntriesPresent(unittest.TestCase):
    """Pin a few high-value entries so accidental deletion is caught."""

    def test_sys_trace_hooks_blacklisted(self):
        self.assertEqual(
            bl.BLACKLIST["sys"] & {"settrace", "setprofile"}, {"settrace", "setprofile"}
        )

    def test_resource_setrlimit_blacklisted(self):
        self.assertIn("setrlimit", bl.BLACKLIST["resource"])

    def test_builtins_set_test_c_api_blacklisted(self):
        self.assertIn("test_c_api", bl.BLACKLIST["builtins:set"])

    def test_builtins_pow_round(self):
        self.assertEqual(bl.BUILTINS, {"pow", "round"})

    def test_module_completer_blacklisted(self):
        # It auto-imports arbitrary modules for REPL completion (side effects: antigravity
        # opens a browser); must not be fuzzed. See blacklists.py comment.
        self.assertIn("_pyrepl._module_completer", bl.MODULE_BLACKLIST)


if __name__ == "__main__":
    unittest.main()
