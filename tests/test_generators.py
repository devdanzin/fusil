"""Unit tests for the byte/string value generators (fusil.bytes_generator,
fusil.unicode_generator). Invariant-style (length and charset bounds) with a seeded RNG
for determinism. Runtime-free.
"""

import unittest
from random import seed

from fusil.bytes_generator import (
    BytesGenerator,
    LengthGenerator,
    createBytesSet,
)
from fusil.unicode_generator import (
    IntegerGenerator,
    IntegerRangeGenerator,
    UnixPathGenerator,
    UnsignedGenerator,
)


class TestBytesGenerator(unittest.TestCase):
    def setUp(self):
        seed(99)

    def test_length_and_membership(self):
        charset = createBytesSet(ord("a"), ord("z"))
        gen = BytesGenerator(3, 8, charset)
        for _ in range(50):
            val = gen.createValue()
            self.assertIsInstance(val, bytes)
            self.assertTrue(3 <= len(val) <= 8)
            self.assertTrue(all(b in charset for b in val))

    def test_explicit_length(self):
        self.assertEqual(len(BytesGenerator(1, 100).createValue(length=10)), 10)

    def test_single_element_set_repeats(self):
        gen = BytesGenerator(5, 5, {ord("A")})
        self.assertEqual(gen.createValue(), b"AAAAA")

    def test_length_generator_is_all_A(self):
        # LengthGenerator uses the single-byte set b"A".
        self.assertEqual(LengthGenerator(4, 4).createValue(), b"AAAA")


class TestUnsignedGenerator(unittest.TestCase):
    def setUp(self):
        seed(7)

    def test_digits_only_and_no_leading_zero(self):
        gen = UnsignedGenerator(max_length=12, min_length=2)
        for _ in range(50):
            val = gen.createValue()
            self.assertTrue(val.isdigit())
            self.assertNotEqual(val[0], "0", "multi-digit unsigned must not start with 0")


class TestIntegerGenerator(unittest.TestCase):
    def setUp(self):
        seed(7)

    def test_parses_as_int(self):
        gen = IntegerGenerator(max_length=10)
        for _ in range(50):
            val = gen.createValue()
            int(val)  # must not raise (optional leading '-' + digits)


class TestIntegerRangeGenerator(unittest.TestCase):
    def test_within_range(self):
        seed(1)
        gen = IntegerRangeGenerator(-5, 5)
        for _ in range(50):
            self.assertTrue(-5 <= int(gen.createValue()) <= 5)


class TestUnixPathGenerator(unittest.TestCase):
    def setUp(self):
        seed(123)

    def test_absolute_starts_with_slash(self):
        gen = UnixPathGenerator(max_length=40, absolute=True)
        for _ in range(20):
            self.assertTrue(gen.createValue().startswith("/"))

    def test_only_allowed_characters(self):
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_./")
        gen = UnixPathGenerator(max_length=60)
        for _ in range(20):
            self.assertTrue(set(gen.createValue()) <= allowed)


if __name__ == "__main__":
    unittest.main()
