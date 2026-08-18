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

    def test_testmultiphase_state_func_blacklisted_but_module_is_not(self):
        # It raises SystemError by design (PyState_AddModule on a module with slots) on every
        # interpreter. Blacklist the one function, not the module -- the rest is real
        # multi-phase-init/cpyext surface.
        self.assertIn("call_state_registration_func", bl.BLACKLIST["_testmultiphase"])
        self.assertNotIn("_testmultiphase", bl.MODULE_BLACKLIST)
        for keep in ("foo", "Example", "Str"):
            self.assertNotIn(keep, bl.BLACKLIST["_testmultiphase"])

    def test_default_int_handler_blacklisted(self):
        # It raises KeyboardInterrupt, a BaseException, which escapes the generated script's
        # `except Exception` handlers and kills the session outright (the #192 class).
        for module in ("signal", "_signal"):
            self.assertIn("default_int_handler", bl.BLACKLIST[module], module)

    def test_pypy_self_harming_helpers_blacklisted(self):
        # These attack the fuzzer or the host, not the target. attach_gdb was caught live on
        # a PyPy 3.11 fleet: it runs gdb inside the session and gdb's banner scores on the
        # "bug" word, manufacturing a crash. remote_exec injects code into an arbitrary pid.
        self.assertLessEqual(
            {"attach_gdb", "remote_exec", "set_code_callback", "_internal_crash"},
            bl.BLACKLIST["__pypy__"],
        )

    def test_pypy_blacklist_stays_narrow(self):
        # __pypy__ is PyPy-only surface with no CPython counterpart -- the reason to fuzz PyPy
        # at all. Only the self-harming helpers belong here, never the interesting internals.
        for keep in ("newdict", "strategy", "internal_repr", "intop", "move_to_end"):
            self.assertNotIn(keep, bl.BLACKLIST["__pypy__"])

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
