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
        # Force a concrete exception via exc=: with the default (a random pick from the bomb
        # pool) StopIteration is ~8% likely, and `raise StopIteration` in a plain iterator's
        # __next__ ends list() CLEANLY (no exception escapes) -- a real ~8% flake this asserts
        # away by pinning a non-terminating exception.
        with self.assertRaises(ValueError):
            list(B.FailingIterator(max_items=2, exc=ValueError))


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


class TestBombExceptionPool(unittest.TestCase):
    def test_pool_contains_only_exception_subclasses(self):
        # BaseException-only types (KeyboardInterrupt/SystemExit/GeneratorExit) escape the
        # generated `except Exception` handlers and abort the whole session (SIGINT / nonzero
        # exit) as a false crash instead of exercising error handling. The pool must stay
        # Exception-only.
        offenders = [exc.__name__ for exc in B._BOMB_EXCEPTIONS if not issubclass(exc, Exception)]
        self.assertEqual(offenders, [], f"BaseException-only bomb exceptions: {offenders}")

    def test_bomb_exc_never_returns_baseexception_only(self):
        drawn = {B._bomb_exc() for _ in range(2000)}
        self.assertTrue(all(issubclass(e, Exception) for e in drawn))


class TestFileBombs(unittest.TestCase):
    def test_read_bomb_delays_then_raises(self):
        rb = B.ReadBomb()
        rb._delay, rb._calls = 1, 0
        self.assertEqual(rb.read(), b"")  # call 1
        with self.assertRaises(MemoryError):
            rb.read()  # call 2 > delay 1

    def test_wrong_type_file_returns_non_buffer(self):
        self.assertNotIsInstance(B.WrongTypeFile().read(), (bytes, str))

    def test_fileno_bomb_raises_but_read_works(self):
        fb = B.FilenoBomb()
        self.assertEqual(fb.read(), b"")
        with self.assertRaises(BaseException):
            fb.fileno()


class TestMetaclassBombs(unittest.TestCase):
    def test_hidden_name_type_hides_identity_attrs(self):
        self.assertIsInstance(B.HiddenNameType, type)  # it is a class, passed as-is
        for attr in ("__name__", "__qualname__", "__module__"):
            with self.assertRaises(BaseException, msg=attr):
                getattr(B.HiddenNameType, attr)

    def test_descriptor_bomb_get_raises(self):
        db = B.DescriptorBomb()
        for attr in ("value", "name", "read", "__wrapped__"):
            with self.assertRaises(BaseException, msg=attr):
                getattr(db, attr)

    def test_stateful_hash_type_arms_after_use(self):
        # A fresh subclass so its hash state is independent of other tests / the shared class.
        T = B._StatefulHashMeta("T", (), {})
        T._bomb_hash_state = [0, 2]  # succeed twice, then raise
        self.assertEqual(hash(T), 0)
        self.assertEqual(hash(T), 0)
        with self.assertRaises(BaseException):
            hash(T)


class TestRandomShadowing(unittest.TestCase):
    """Regression for the fleet bug (2026-07-02): the generated script's boilerplate emits
    ``from random import choice, randint, random``, which rebinds the bare name ``random`` to
    the random() *function*, shadowing the module. The embedded bomb source must reach
    randint/choice via its private ``_bomb_random`` alias -- otherwise ``IndexBomb()`` etc.
    die with ``AttributeError: 'builtin_function_or_method' object has no attribute 'randint'``.
    """

    def test_bombs_construct_with_random_name_shadowed(self):
        # Mirror the generated boilerplate: `random` is now the function, not the module.
        from random import choice, randint, random

        ns = {"choice": choice, "randint": randint, "random": random}
        # Precondition that made the old code fail: the shadowing `random` has no randint.
        self.assertFalse(hasattr(ns["random"], "randint"))
        # exec the source exactly as embedded into generated scripts. This also defines the
        # type bombs, whose metaclasses call _bomb_random.randint at class-creation time.
        exec(tricky_weird.bomb_objects, ns)
        for name in B.BOMB_CLASS_NAMES:
            ns[name]()  # must construct despite the shadow (regression: AttributeError)
        for name in B.BOMB_TYPE_NAMES:
            self.assertIsInstance(ns[name], type)


class TestGeneratorWiring(unittest.TestCase):
    def test_all_class_names_construct_with_no_args(self):
        for name in B.BOMB_CLASS_NAMES:
            getattr(B, name)()  # must construct; generator emits `Name()`

    def test_type_bombs_are_types(self):
        for name in B.BOMB_TYPE_NAMES:
            self.assertIsInstance(getattr(B, name), type)

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

    def test_gen_bomb_object_emits_instances_and_types(self):
        from python._test_options import make_test_options

        from fusil.python.argument_generator import ArgumentGenerator

        arg_gen = ArgumentGenerator(make_test_options(no_numpy=True, no_tstrings=True), [""])
        saw_instance = saw_type = False
        for _ in range(200):
            (expr,) = arg_gen.genBombObject()
            ast.parse(expr)  # valid Python expression
            if expr.endswith("()"):
                self.assertIn(expr[:-2], B.BOMB_CLASS_NAMES)  # instance bomb: Name()
                saw_instance = True
            else:
                self.assertIn(expr, B.BOMB_TYPE_NAMES)  # type bomb: bare Name
                saw_type = True
        self.assertTrue(saw_instance and saw_type)


class TestReentrantMutationBombs(unittest.TestCase):
    """The reentrant-mutation family MUTATES the container mid-callback (reentrancy / UAF
    class) rather than raising -- distinct from the exception bombs above."""

    def test_clear_parent_clears_container_on_compare_callback(self):
        # delay 0 -> the first comparison callback clears the container holding the element.
        lst = [1, 2, 3]
        cp = B._ClearParent(lst, max_delay=0)
        lst.append(cp)
        self.assertEqual(len(lst), 4)
        _ = cp == 99  # a compare callback (what a C compare loop invokes)
        self.assertEqual(len(lst), 0)  # parent cleared from inside the dunder

    def test_clear_parent_respects_delay(self):
        lst = [1]
        cp = B._ClearParent(lst)
        cp._delay, cp._calls = 2, 0
        lst.append(cp)
        hash(cp)  # call 1
        hash(cp)  # call 2
        self.assertGreater(len(lst), 0)  # not yet
        hash(cp)  # call 3 > delay 2 -> clears
        self.assertEqual(len(lst), 0)

    def test_clear_parent_fires_from_multiple_slots(self):
        for trigger in (
            lambda c: c == 1,
            lambda c: c < 1,
            lambda c: hash(c),
            lambda c: c.__index__(),
        ):
            lst = [0, 1]
            cp = B._ClearParent(lst, max_delay=0)
            lst.append(cp)
            trigger(cp)
            self.assertEqual(len(lst), 0)

    def test_reentrant_list_is_prearmed_and_benign_until_compared(self):
        rl = B.ReentrantClearList()
        self.assertIsInstance(rl, list)
        self.assertGreater(len(rl), 0)
        # repr / len must NOT trigger the clear (no compare/hash/index of the seeded element)
        _ = repr(rl)
        _ = len(rl)
        self.assertGreater(len(rl), 0)
        # exactly one seeded self-clearing element
        self.assertEqual(sum(isinstance(x, B._ClearParent) for x in rl), 1)

    def test_reentrant_dict_is_prearmed_dict(self):
        rd = B.ReentrantClearDict()
        self.assertIsInstance(rd, dict)
        self.assertIn("_fusil_pull", rd)
        self.assertIsInstance(rd["_fusil_pull"], B._ClearParent)

    def test_mutating_iterable_lies_about_length(self):
        # __length_hint__ draws from a set that includes negative and large values (presize
        # crash vectors), while iteration yields a different, real count.
        hints = {B.MutatingIterable().__length_hint__() for _ in range(200)}
        self.assertTrue(any(h < 0 for h in hints))  # negative hint present
        self.assertTrue(any(h >= (1 << 16) for h in hints))  # large over-report present
        self.assertTrue(all(h <= (1 << 20) for h in hints))  # but never a guaranteed-OOM presize
        # materializing works regardless of the (lying) hint and yields the real, different count
        mi = B.MutatingIterable()
        mi._hint = 1 << 20  # exercise the large-presize path deterministically
        self.assertIsInstance(list(mi), list)

    def test_reentrant_bombs_registered(self):
        for name in ("ReentrantClearList", "ReentrantClearDict", "MutatingIterable"):
            self.assertIn(name, B.BOMB_CLASS_NAMES)


class TestStatefulLyingBombs(unittest.TestCase):
    """The stateful/lying family: a slot succeeds but returns an inconsistent answer across
    calls (grows / changes / flips type), rather than raising or mutating a container."""

    def test_growing_len_underreports_then_grows(self):
        gl = B.GrowingLen()
        first = len(gl)
        second = len(gl)
        self.assertGreater(second, first)  # first read small (presize), then grows
        # __getitem__ / __iter__ yield up to the grown count (past a buffer sized from `first`)
        self.assertEqual(len(list(iter(gl))), second)
        self.assertEqual(gl[0], 0)
        with self.assertRaises(IndexError):
            gl[second]

    def test_mutating_hash_stable_then_changes(self):
        mh = B.MutatingHash()
        mh._delay, mh._calls = 2, 0
        h1 = hash(mh)  # call 1
        h2 = hash(mh)  # call 2 -- still stable, so it can be stored as a key
        self.assertEqual(h1, h2)
        # after the delay the hash starts changing (violating hash-constancy while keyed)
        later = {hash(mh) for _ in range(20)}
        self.assertTrue(any(h != h1 for h in later))
        # equal only to itself, so a dict lookup with a changed hash misses its own key
        self.assertTrue(mh == mh)
        self.assertFalse(mh == B.MutatingHash())

    def test_type_flip_iterator_flips_off_first_type(self):
        # a consistent run of ints, then an incompatible type mid-stream
        seen = set()
        for _ in range(50):
            kinds = [type(v).__name__ for v in B.TypeFlipIterator()]
            self.assertEqual(kinds[0], "int")  # starts consistent
            seen.update(kinds)
        self.assertTrue(seen - {"int"})  # at least one non-int flip type appears
        # feeding a C reducer a run of ints then a str raises (caught by the harness), not hangs
        with self.assertRaises(TypeError):
            max(_all_ints_then_str())

    def test_stateful_lying_bombs_registered(self):
        for name in ("GrowingLen", "MutatingHash", "TypeFlipIterator"):
            self.assertIn(name, B.BOMB_CLASS_NAMES)


def _all_ints_then_str():
    # a deterministic type-flip stream for the reducer assertion above
    yield 1
    yield 2
    yield "x"


if __name__ == "__main__":
    unittest.main()
