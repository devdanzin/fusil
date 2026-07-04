"""Unit tests for fusil.process.env — the child-process environment builder.

``fusil.process.env`` decides what environment a fuzzed child process is spawned with:
the ``EnvironmentVariable`` family generates variable *values* (fixed strings, random
integers, random byte strings, fixed-length filler…), the ``Environment`` agent collects
those plus a whitelist of variables to *copy* from the parent, and ``augment_asan_options``
fills in the AddressSanitizer flags the crash-dedup pipeline relies on (``handle_abort=1``
so an abort prints a symbolized backtrace to stdout). A mistake here silently changes what
every fuzzed child inherits — a wrong ASAN_OPTIONS breaks crash-site resolution, and a
stray nul byte in a value is rejected outright — so the value generators, the copy/set
bookkeeping, and the ASan-option merge all deserve direct coverage. It previously sat at
~33%.

The ``Environment`` agent is a ``ProjectAgent``; it is driven here with the real-MTA
``FakeProject`` harness (as ``tests/test_file_watch.py`` does) and a ``SimpleNamespace``
stand-in for the spawning process. No child process is actually launched. Runtime-free.
"""

import os
import random
import unittest
from types import SimpleNamespace
from unittest import mock

from fusil.process.env import (
    Environment,
    EnvironmentVariable,
    EnvVarInteger,
    EnvVarIntegerRange,
    EnvVarLength,
    EnvVarRandom,
    EnvVarValue,
    augment_asan_options,
)
from tests.mas_harness import FakeProject

DEFAULT_COPIES = [
    "PYTHON_GIL",
    "PYTHON_JIT",
    "LSAN_OPTIONS",
    "ASAN_OPTIONS",
    "PYTHON_LLTRACE",
    "PYTHON_OPT_DEBUG_4",
]


def _make_env():
    """Build an ``Environment`` over a real-MTA FakeProject and a fake spawning process."""
    project = FakeProject()
    process = SimpleNamespace(project=lambda: project, name="proc")
    return Environment(process), project


class TestAugmentAsanOptions(unittest.TestCase):
    def test_none_fills_both_defaults(self):
        self.assertEqual(augment_asan_options(None), "handle_abort=1:abort_on_error=1")

    def test_empty_string_fills_both_defaults(self):
        self.assertEqual(augment_asan_options(""), "handle_abort=1:abort_on_error=1")

    def test_preserves_unrelated_option_and_appends_defaults(self):
        self.assertEqual(
            augment_asan_options("detect_leaks=1"),
            "detect_leaks=1:handle_abort=1:abort_on_error=1",
        )

    def test_existing_handle_abort_value_is_not_overwritten(self):
        # A caller-provided handle_abort=0 must survive; only the missing key is added.
        self.assertEqual(
            augment_asan_options("handle_abort=0"),
            "handle_abort=0:abort_on_error=1",
        )

    def test_both_present_returns_unchanged(self):
        val = "handle_abort=1:abort_on_error=1"
        self.assertEqual(augment_asan_options(val), val)

    def test_both_present_with_custom_values_preserved_in_order(self):
        val = "abort_on_error=0:handle_abort=5"
        self.assertEqual(augment_asan_options(val), val)

    def test_empty_segments_are_filtered_out(self):
        self.assertEqual(
            augment_asan_options(":::detect_leaks=1:::"),
            "detect_leaks=1:handle_abort=1:abort_on_error=1",
        )

    def test_bare_key_without_value_counts_as_present(self):
        # Key detection splits on '=', so a valueless "handle_abort" is still "present".
        self.assertEqual(
            augment_asan_options("handle_abort"),
            "handle_abort:abort_on_error=1",
        )

    def test_idempotent(self):
        once = augment_asan_options("detect_leaks=1")
        self.assertEqual(augment_asan_options(once), once)


class TestEnvironmentVariableBase(unittest.TestCase):
    def test_default_counts(self):
        var = EnvironmentVariable("X")
        self.assertEqual(var.min_count, 1)
        self.assertEqual(var.max_count, 1)

    def test_custom_max_count_stored(self):
        self.assertEqual(EnvironmentVariable("X", max_count=7).max_count, 7)

    def test_has_name_scalar(self):
        var = EnvironmentVariable("FOO")
        self.assertTrue(var.hasName("FOO"))
        self.assertFalse(var.hasName("BAR"))

    def test_has_name_list_membership(self):
        var = EnvironmentVariable(["A", "B"])
        self.assertTrue(var.hasName("A"))
        self.assertTrue(var.hasName("B"))
        self.assertFalse(var.hasName("C"))

    def test_create_name_scalar_returns_name(self):
        self.assertEqual(EnvironmentVariable("X").createName(), "X")

    def test_create_name_list_returns_member(self):
        var = EnvironmentVariable(("A", "B", "C"))
        for _ in range(25):
            self.assertIn(var.createName(), ("A", "B", "C"))

    def test_create_value_is_abstract(self):
        with self.assertRaises(NotImplementedError):
            EnvironmentVariable("X").createValue()

    def test_create_iterates_into_abstract_create_value(self):
        # create() is a generator; the NotImplementedError only fires when iterated.
        with self.assertRaises(NotImplementedError):
            list(EnvironmentVariable("X").create())


class TestEnvironmentVariableCreate(unittest.TestCase):
    """The generic create() count/name logic, exercised via the concrete EnvVarValue."""

    def test_scalar_yields_single_pair(self):
        self.assertEqual(list(EnvVarValue("N", "v").create()), [("N", "v")])

    def test_list_name_is_capped_by_default_max_count_one(self):
        var = EnvVarValue(["A", "B", "C"], "v")  # max_count defaults to 1
        pairs = list(var.create())
        self.assertEqual(len(pairs), 1)
        name, value = pairs[0]
        self.assertIn(name, ("A", "B", "C"))
        self.assertEqual(value, "v")

    def test_list_name_with_max_count_allows_multiple(self):
        random.seed(1234)
        var = EnvVarValue(["A", "B", "C"], "v", max_count=3)
        lengths = set()
        for _ in range(50):
            pairs = list(var.create())
            lengths.add(len(pairs))
            for name, value in pairs:
                self.assertIn(name, ("A", "B", "C"))
                self.assertEqual(value, "v")
        self.assertTrue(lengths <= {1, 2, 3})
        self.assertGreaterEqual(min(lengths), 1)

    def test_falsy_max_count_means_no_cap_on_list_length(self):
        # max_count=0 is falsy, so the min() cap is skipped and the full name-list
        # length becomes the ceiling: count is drawn from [1, len(name)].
        random.seed(99)
        var = EnvVarValue(["A", "B"], "v", max_count=0)
        lengths = {len(list(var.create())) for _ in range(50)}
        self.assertTrue(lengths <= {1, 2})
        self.assertIn(2, lengths)


class TestEnvVarValue(unittest.TestCase):
    def test_default_value_is_empty_string(self):
        self.assertEqual(EnvVarValue("N").createValue(), "")

    def test_custom_value_returned_verbatim(self):
        self.assertEqual(EnvVarValue("N", "hello").createValue(), "hello")

    def test_is_environment_variable(self):
        self.assertIsInstance(EnvVarValue("N"), EnvironmentVariable)


class TestEnvVarInteger(unittest.TestCase):
    def test_value_is_parseable_integer_string(self):
        random.seed(0)
        var = EnvVarInteger("N")
        for _ in range(50):
            value = var.createValue()
            self.assertIsInstance(value, str)
            int(value)  # must parse (may be negative)


class TestEnvVarIntegerRange(unittest.TestCase):
    def test_value_within_bounds(self):
        var = EnvVarIntegerRange("N", 10, 20)
        for _ in range(100):
            self.assertTrue(10 <= int(var.createValue()) <= 20)

    def test_single_value_range_is_deterministic(self):
        self.assertEqual(EnvVarIntegerRange("N", 5, 5).createValue(), "5")

    def test_bounds_are_stored(self):
        var = EnvVarIntegerRange("N", 1, 2)
        self.assertEqual((var.min, var.max), (1, 2))


class TestEnvVarLength(unittest.TestCase):
    def test_fixed_length_is_filler_bytes(self):
        self.assertEqual(EnvVarLength("N", max_length=5, min_length=5).createValue(), b"AAAAA")

    def test_zero_length_is_empty_bytes(self):
        self.assertEqual(EnvVarLength("N", max_length=0).createValue(), b"")

    def test_length_within_range_and_only_filler(self):
        var = EnvVarLength("N", max_length=8, min_length=2)
        for _ in range(50):
            value = var.createValue()
            self.assertIsInstance(value, bytes)
            self.assertTrue(2 <= len(value) <= 8)
            self.assertEqual(set(value), {ord("A")})


class TestEnvVarRandom(unittest.TestCase):
    def test_value_is_bytes_of_expected_length(self):
        value = EnvVarRandom("N", min_length=4, max_length=4).createValue()
        self.assertIsInstance(value, bytes)
        self.assertEqual(len(value), 4)

    def test_single_element_byte_set_is_deterministic(self):
        var = EnvVarRandom("N", min_length=20, max_length=20, bytes_set={ord("x")})
        self.assertEqual(var.createValue(), b"x" * 20)

    def test_default_byte_set_excludes_nul(self):
        # The default ASCII0 set is 1..255, so a random value never contains a nul byte
        # (which Environment.create() would otherwise reject).
        value = EnvVarRandom("N", min_length=200, max_length=200).createValue()
        self.assertNotIn(0, value)


class TestEnvironmentSetup(unittest.TestCase):
    def test_name_is_derived_from_process(self):
        env, _ = _make_env()
        self.assertEqual(env.name, "proc:env")

    def test_registers_with_project(self):
        env, project = _make_env()
        self.assertIn(env, project.registered)

    def test_default_copies_and_empty_variables(self):
        env, _ = _make_env()
        self.assertEqual(env.copies, DEFAULT_COPIES)
        self.assertEqual(env.variables, [])

    def test_clear_empties_copies_and_variables(self):
        env, _ = _make_env()
        env.add(EnvVarValue("X", "1"))
        env.clear()
        self.assertEqual(env.copies, [])
        self.assertEqual(env.variables, [])

    def test_add_appends_variable(self):
        env, _ = _make_env()
        var = EnvVarValue("X", "1")
        env.add(var)
        self.assertIn(var, env.variables)

    def test_copy_appends_new_name(self):
        env, _ = _make_env()
        env.copy("BRAND_NEW")
        self.assertIn("BRAND_NEW", env.copies)

    def test_copy_is_idempotent(self):
        env, _ = _make_env()
        before = list(env.copies)
        env.copy("PYTHON_GIL")  # already a default
        self.assertEqual(env.copies, before)


class TestEnvironmentSetAndGetItem(unittest.TestCase):
    def test_set_creates_and_registers_env_var_value(self):
        env, _ = _make_env()
        var = env.set("FOO", "bar")
        self.assertIsInstance(var, EnvVarValue)
        self.assertIs(env["FOO"], var)
        self.assertEqual(var.value, "bar")

    def test_set_existing_updates_value_in_place(self):
        env, _ = _make_env()
        first = env.set("FOO", "bar")
        second = env.set("FOO", "baz")
        self.assertIs(first, second)  # same EnvVarValue object, reused
        self.assertEqual(first.value, "baz")  # ...but its value is updated ("set" sets)

    def test_set_over_incompatible_type_raises(self):
        env, _ = _make_env()
        env.add(EnvVarInteger("N"))  # not an EnvVarValue
        with self.assertRaises(TypeError):
            env.set("N", "x")

    def test_getitem_missing_raises_key_error(self):
        env, _ = _make_env()
        with self.assertRaises(KeyError):
            env["NOPE"]

    def test_getitem_rejects_list_name(self):
        env, _ = _make_env()
        with self.assertRaises(TypeError):
            env[["A", "B"]]

    def test_getitem_matches_list_named_variable(self):
        env, _ = _make_env()
        var = EnvVarValue(["A", "B"], "1")
        env.add(var)
        self.assertIs(env["A"], var)
        self.assertIs(env["B"], var)


class TestEnvironmentCreate(unittest.TestCase):
    def test_empty_environment_yields_only_asan_options(self):
        env, _ = _make_env()
        with mock.patch.dict(os.environ, {}, clear=True):
            result = env.create()
        self.assertEqual(result, {"ASAN_OPTIONS": "handle_abort=1:abort_on_error=1"})

    def test_present_copy_names_are_copied_from_parent(self):
        env, _ = _make_env()
        with mock.patch.dict(os.environ, {"PYTHON_GIL": "0", "PYTHON_JIT": "1"}, clear=True):
            result = env.create()
        self.assertEqual(result["PYTHON_GIL"], "0")
        self.assertEqual(result["PYTHON_JIT"], "1")

    def test_absent_copy_names_are_skipped(self):
        env, _ = _make_env()
        env.copy("SOME_ABSENT_VAR_XYZ")
        with mock.patch.dict(os.environ, {}, clear=True):
            result = env.create()
        self.assertNotIn("SOME_ABSENT_VAR_XYZ", result)

    def test_copied_asan_options_are_augmented(self):
        env, _ = _make_env()
        with mock.patch.dict(os.environ, {"ASAN_OPTIONS": "detect_leaks=1"}, clear=True):
            result = env.create()
        self.assertEqual(result["ASAN_OPTIONS"], "detect_leaks=1:handle_abort=1:abort_on_error=1")

    def test_generated_variable_is_included(self):
        env, _ = _make_env()
        env.set("FOO", "bar")
        with mock.patch.dict(os.environ, {}, clear=True):
            result = env.create()
        self.assertEqual(result["FOO"], "bar")

    def test_nul_byte_in_value_is_rejected(self):
        env, _ = _make_env()
        env.set("BAD", "a\0b")
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                env.create()

    def test_create_logs_variables_and_final_environment(self):
        env, project = _make_env()
        env.set("FOO", "bar")
        with mock.patch.dict(os.environ, {}, clear=True):
            env.create()
        messages = [m for level, m in project.application().logger.records if level == "info"]
        self.assertTrue(any("Create environment variable FOO" in m for m in messages))
        self.assertTrue(any("Environment:" in m for m in messages))

    def test_bytes_valued_variable_currently_raises_type_error(self):
        # Documents current coupling (see testability note): create()'s `"\0" in value`
        # nul-byte guard assumes str values, so a bytes-producing variable
        # (EnvVarRandom / EnvVarLength) raises TypeError instead of being emitted.
        env, _ = _make_env()
        env.add(EnvVarRandom("R", min_length=3, max_length=3))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(TypeError):
                env.create()


if __name__ == "__main__":
    unittest.main()
