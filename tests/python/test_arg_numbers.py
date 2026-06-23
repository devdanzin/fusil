"""Unit tests for fusil.python.arg_numbers (argument-count detection).

Pins the docstring-prototype parser (its doctests never ran in the suite) and the
get_arg_number / class_arg_number fallback tiers. Runtime-free.
"""

import unittest
from random import seed

from fusil.python.arg_numbers import (
    MAX_ARG,
    class_arg_number,
    get_arg_number,
    parseDocumentation,
    parsePrototype,
)


class TestParsePrototype(unittest.TestCase):
    def test_optional_single(self):
        self.assertEqual(parsePrototype("test([x])"), ((), None, ("x",), {}))

    def test_positional_and_default(self):
        self.assertEqual(
            parsePrototype("dump(obj, file, protocol=0)"),
            (("obj", "file"), None, ("protocol",), {"protocol": "0"}),
        )

    def test_nested_optionals(self):
        self.assertEqual(
            parsePrototype("decompress(string[, wbits[, bufsize]])"),
            (("string",), None, ("wbits", "bufsize"), {}),
        )

    def test_vararg(self):
        self.assertEqual(parsePrototype("get_referents(*objs)"), ((), "*objs", (), {}))

    def test_no_prototype_returns_none(self):
        self.assertIsNone(parsePrototype("nothing"))

    def test_empty_or_non_string(self):
        self.assertIsNone(parsePrototype(""))
        self.assertIsNone(parsePrototype(None))
        self.assertIsNone(parsePrototype(123))

    def test_ellipsis_args_returns_none(self):
        self.assertIsNone(parsePrototype("foo(...)"))


class TestParseDocumentation(unittest.TestCase):
    def test_min_max_counts(self):
        # two required + one optional => (2, 3)
        self.assertEqual(parseDocumentation("setitimer(which, seconds[, interval])", 5), (2, 3))

    def test_vararg_adds_max_var_arg(self):
        # zero required + *objs => (0, 0 + max_var_arg)
        self.assertEqual(parseDocumentation("get_referents(*objs)", 5), (0, 5))

    def test_unparseable_returns_none(self):
        self.assertIsNone(parseDocumentation("not a prototype", 5))


class TestGetArgNumber(unittest.TestCase):
    def test_tier1_known_int(self):
        # __len__ is a known 0-arg method.
        self.assertEqual(get_arg_number(None, "__len__", 99), (0, 0))

    def test_tier1_known_tuple(self):
        # 'open' is mapped to a (min, max) tuple.
        self.assertEqual(get_arg_number(None, "open", 99), (1, 8))

    def test_tier2_introspection(self):
        def sample(a, b, c=1):
            pass

        # not in the known map => fall to getfullargspec: 3 args, 1 default => (2, 3)
        self.assertEqual(get_arg_number(sample, "sample_not_in_map", 0), (2, 3))

    def test_tier4_default_when_unintrospectable(self):
        # A non-callable with no docstring: getfullargspec raises TypeError and there is no
        # prototype to parse, so we fall through to (min_arg, MAX_ARG).
        class Uninspectable:
            __doc__ = None

        self.assertEqual(get_arg_number(Uninspectable(), "uninspectable_xyz", 3), (3, MAX_ARG))


class TestClassArgNumber(unittest.TestCase):
    def setUp(self):
        seed(0)

    def test_known_class_range(self):
        # int is mapped to (0, 2).
        for _ in range(20):
            self.assertIn(class_arg_number("int", int), (0, 1, 2))

    def test_introspected_class_range(self):
        class C:
            def __init__(self, a, b=1):
                pass

        # args (excl self) = 2, defaults = 1 => randint(1, 2)
        for _ in range(20):
            self.assertIn(class_arg_number("C_not_in_map", C), (1, 2))


if __name__ == "__main__":
    unittest.main()
