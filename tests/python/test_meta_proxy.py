"""A target object must not be able to impersonate fusil's metadata proxy.

The proxy used to be recognised by ``getattr(obj, "_fusil_is_meta", False)``. Any object with a
catch-all ``__getattr__`` answers that truthily, and CPython 3.16 ships one --
``traceback._ShutdownTheme``, the stand-in used when ``_colorize`` cannot be imported during
late shutdown:

    class _ShutdownTheme:
        def __getattr__(self, _): return self

Generation therefore took the metadata branch on it and called ``_fusil_raw_methods()``, which
returns the theme again and is not callable. The ``TypeError`` escaped into the MAS and killed
the whole fusil process rather than the session: **15 of 29 runs in one fleet**, about half the
wall clock, and it happened with ``--discover-in-target`` off, where no proxy can exist at all.
"""

import unittest

from fusil.python.arg_numbers import class_arg_number, get_arg_number
from fusil.python.meta_proxy import _MetaProxy, is_meta_proxy


class CatchAllGetattr:
    """The shape that caused it -- traceback._ShutdownTheme, reduced."""

    def __getattr__(self, _):
        return self


class HostileMeta(type):
    """A metaclass with the same catch-all, which is why the check is not on ``type(obj)``.

    fusil injects hostile metaclasses deliberately (the metaclass bombs), so a check that
    merely moved the lookup from the instance to its type would still be forgeable.
    """

    def __getattr__(cls, _):
        return cls


class HostileType(metaclass=HostileMeta):
    pass


class MetaProxyIdentificationTests(unittest.TestCase):
    def test_a_real_proxy_is_recognised(self):
        self.assertTrue(is_meta_proxy(_MetaProxy("f", {"arity": [1, 2]})))

    def test_catch_all_getattr_cannot_impersonate_a_proxy(self):
        theme = CatchAllGetattr()
        # The old check: truthy, which is the whole bug.
        self.assertTrue(getattr(theme, "_fusil_is_meta", False))
        self.assertFalse(is_meta_proxy(theme))

    def test_hostile_metaclass_cannot_impersonate_a_proxy(self):
        self.assertTrue(getattr(HostileType, "_fusil_is_meta", False))
        self.assertFalse(is_meta_proxy(HostileType))

    def test_ordinary_objects_are_not_proxies(self):
        for value in (1, "s", [], object(), int, None):
            with self.subTest(value=value):
                self.assertFalse(is_meta_proxy(value))


class ArityPathSurvivesACatchAllGetattrTests(unittest.TestCase):
    """The arity helpers consult the same flag, so they had the same hole."""

    def test_get_arg_number_does_not_read_forged_arity(self):
        # Previously: _fusil_is_meta truthy -> _fusil_arity is the theme itself -> `ar[0]`
        # raises. It must fall through to the ordinary path and return a usable range.
        lo, hi = get_arg_number(CatchAllGetattr(), "some_func", 0)
        self.assertIsInstance(lo, int)
        self.assertIsInstance(hi, int)
        self.assertLessEqual(lo, hi)

    def test_class_arg_number_does_not_read_forged_ctor_arity(self):
        nb = class_arg_number("NotInTheTable", CatchAllGetattr())
        self.assertIsInstance(nb, int)
        self.assertGreaterEqual(nb, 0)

    def test_a_real_proxy_still_drives_both_helpers(self):
        self.assertEqual(get_arg_number(_MetaProxy("f", {"arity": [2, 2]}), "f", 0), (2, 2))
        proxy = _MetaProxy("C", {"ctor_arity": [1, 1]})
        self.assertEqual(class_arg_number("C_not_in_table", proxy), 1)


if __name__ == "__main__":
    unittest.main()
