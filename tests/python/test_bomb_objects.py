"""Tests for the exception-bomb object family (fusil/python/samples/bomb_objects.py).

Bombs are the protocol-level analogue of --oom-fuzz: a dunder that raises (randomly delayed)
to hit unguarded-error-path bugs in C code. These pin the delay/raise semantics, the
SuperBomb "every dunder is a landmine" contract, and the generator wiring.
"""

import ast
import os
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))  # repo root -> import fusil.*
sys.path.insert(0, os.path.join(SCRIPT_DIR, ".."))  # tests/ -> import python._test_options

import fusil.python.tricky_weird as tricky_weird
from fusil.python.samples import bomb_objects as B


class TestDelaySemantics(unittest.TestCase):
    def test_fires_after_exact_delay(self):
        # delay N: succeed N times, raise on call N+1.
        b = B.HashBomb()
        b._delay, b._calls = 2, 0
        self.assertEqual(hash(b), 42)  # call 1
        self.assertEqual(hash(b), 42)  # call 2
        with self.assertRaises(MemoryError):
            hash(b)  # call 3 > delay 2

    def test_delay_zero_fires_on_first_use(self):
        b = B.HashBomb(max_delay=0)  # randint(0, 0) == 0
        with self.assertRaises(MemoryError):
            hash(b)

    def test_targeted_bombs_default_to_memoryerror(self):
        # The targeted family raises MemoryError (the high-value unguarded-error-path target).
        with self.assertRaises(MemoryError):
            B.IndexBomb(max_delay=0).__index__()
        with self.assertRaises(MemoryError):
            B.LenBomb(max_delay=0).__len__()
        with self.assertRaises(MemoryError):
            B.ReprBomb(max_delay=0).__repr__()
        with self.assertRaises(MemoryError):
            B.EqBomb(max_delay=0).__eq__(object())


class TestSpecialBombs(unittest.TestCase):
    def test_eqbomb_is_hashable(self):
        self.assertEqual(hash(B.EqBomb()), 0)  # hashable so it reaches dict/set eq checks

    def test_lyinglen_over_reports(self):
        ll = B.LyingLen()
        self.assertEqual(len(ll), 1_000_000)
        self.assertEqual(list(ll), [1, 2, 3])  # but yields few

    def test_failing_iterator_raises_during_iteration(self):
        with self.assertRaises(BaseException):
            list(B.FailingIterator(max_items=2))


class TestSuperBomb(unittest.TestCase):
    def test_constructs_cleanly(self):
        B.SuperBomb()  # __init__ must work despite every other slot being armed

    def test_every_listed_dunder_raises(self):
        for name in B._SUPERBOMB_DUNDERS:
            sb = B.SuperBomb(max_delay=0)  # fire on first use
            slot = getattr(type(sb), name)
            with self.assertRaises(BaseException, msg=f"{name} did not raise"):
                slot(sb)

    def test_raises_varied_exceptions(self):
        seen = set()
        for _ in range(300):
            sb = B.SuperBomb(max_delay=0)
            try:
                sb.__hash__()
            except BaseException as exc:  # noqa: BLE001
                seen.add(type(exc))
        self.assertGreater(len(seen), 3, f"expected variety, saw {seen}")

    def test_respects_delay(self):
        sb = B.SuperBomb()
        object.__setattr__(sb, "_bomb_delay", 2)
        object.__setattr__(sb, "_bomb_calls", {})
        sb.__hash__()  # call 1 (no raise)
        sb.__hash__()  # call 2 (no raise)
        with self.assertRaises(BaseException):
            sb.__hash__()  # call 3 > delay 2


class TestGeneratorWiring(unittest.TestCase):
    def test_all_class_names_construct_with_no_args(self):
        for name in B.BOMB_CLASS_NAMES:
            getattr(B, name)()  # must construct; generator emits `Name()`

    def test_tricky_weird_exposes_names_and_source(self):
        self.assertEqual(tricky_weird.bomb_object_names, B.BOMB_CLASS_NAMES)
        # source text embedded into generated scripts must define every advertised class
        for name in B.BOMB_CLASS_NAMES:
            self.assertIn(f"class {name}", tricky_weird.bomb_objects)

    def test_source_has_no_oom_marker_tokens(self):
        # bomb source is embedded verbatim; it must not trip the OOM-artifact assertions in
        # non-OOM generated scripts (test_oom_fuzz).
        for marker in ("oom_call", "set_nomemory", "_OOM_AVAILABLE", "remove_mem_hooks"):
            self.assertNotIn(marker, tricky_weird.bomb_objects)

    def test_gen_bomb_object_emits_valid_constructor(self):
        from python._test_options import make_test_options

        from fusil.python.argument_generator import ArgumentGenerator

        arg_gen = ArgumentGenerator(make_test_options(no_numpy=True, no_tstrings=True), [""])
        for _ in range(30):
            (expr,) = arg_gen.genBombObject()
            self.assertTrue(expr.endswith("()"))
            self.assertIn(expr[:-2], B.BOMB_CLASS_NAMES)
            ast.parse(expr)  # valid Python expression


if __name__ == "__main__":
    unittest.main()
