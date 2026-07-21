"""Tests for target-subprocess module discovery (``--discover-in-target``).

Three angles:
- the stdlib-only introspection script emits the expected JSON shape (run under this interpreter);
- generation from that metadata needs NO live module (``WritePythonCode(module=None, ...)``);
- parity: for a module importable in both, subprocess metadata yields the SAME fuzzable name
  lists as live introspection -- the guard against the two discovery paths drifting apart.
"""

import ast
import os
import random
import sys
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))

from fusil.python.blacklists import MODULE_BLACKLIST
from fusil.python.list_all_modules import ListAllModules
from fusil.python.target_introspect import (
    _DISCOVERY_SRC,
    _ENUMERATE_SRC,
    enumerate_packages,
    introspect_module,
)
from fusil.python.write_python_code import WritePythonCode

# Introspect using THIS interpreter (it can import `json`); no separate target needed for the unit.
PYEXE = sys.executable


class _Options:
    """Fully-pinned options the generator reads (mirrors test_golden_output._Options)."""

    functions_number = 3
    classes_number = 1
    objects_number = 1
    methods_number = 2
    deep_dive = False
    gc_aggressive = False
    fuzz_exceptions = False
    test_private = False
    no_numpy = True
    no_tstrings = True
    external_references = True
    no_threads = True
    no_async = True
    oom_fuzz = False
    oom_max_start = 50
    oom_calls = 3
    oom_classes = 0
    oom_methods = 0
    oom_verbose = False
    oom_seq = False
    oom_seq_len = 3
    oom_window = 1
    oom_foreign = False
    oom_foreign_pythonmalloc = False
    tsan = False


class _Parent:
    def __init__(self):
        self.options = _Options()
        self.filenames = ["/tmp/fuzz_fixture"]

    def warning(self, *a, **k):
        pass


def _generate(module, module_name, member_metadata):
    parent = _Parent()
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            parent, path, module, module_name,
            threads=False, _async=False, plugin_manager=None,
            member_metadata=member_metadata,
        )  # fmt: skip
        random.seed(1234)
        writer.generate_fuzzing_script()
        with open(path) as fh:
            return writer, fh.read()
    finally:
        os.unlink(path)


class TestDiscoveryScript(unittest.TestCase):
    def test_script_emits_expected_shape_for_json(self):
        data = introspect_module(PYEXE, "json")
        self.assertIsNotNone(data)
        self.assertTrue(data["ok"])
        by_kind = {}
        for m in data["members"]:
            by_kind.setdefault(m["kind"], {})[m["name"]] = m
        # functions with arity ranges
        self.assertIn("dumps", by_kind["function"])
        self.assertEqual(by_kind["function"]["dumps"]["arity"], [1, 1])
        # a class carries ctor arity + a method set + the exception flag
        enc = by_kind["class"]["JSONEncoder"]
        self.assertIsInstance(enc["ctor_arity"], list)
        self.assertTrue(any(mm["name"] == "encode" for mm in enc["methods"]))
        self.assertTrue(by_kind["class"]["JSONDecodeError"]["is_exception"])
        self.assertFalse(enc["is_exception"])

    def test_failed_import_returns_none(self):
        self.assertIsNone(introspect_module(PYEXE, "no_such_module_zzz_1234"))

    def test_script_is_valid_python(self):
        ast.parse(_DISCOVERY_SRC)


class TestGenerationFromMetadata(unittest.TestCase):
    def test_generation_needs_no_live_module(self):
        # The payoff: build a valid fuzzing script from metadata alone, module=None (the runner
        # never imported the target).
        meta = introspect_module(PYEXE, "json")
        writer, src = _generate(None, "json", meta)
        ast.parse(src)  # valid Python
        self.assertTrue(writer._meta_mode)
        self.assertTrue(writer.module_functions or writer.module_classes)
        # a fabricated single-class module drives instantiation + method calls with no live object
        fake = {
            "module": "fakeext",
            "ok": True,
            "members": [
                {"name": "Widget", "kind": "class", "is_exception": False,
                 "ctor_arity": [0, 2], "ctor_doc": None,
                 "methods": [{"name": "poke", "arity": [1, 2], "doc": None}]},
                {"name": "do_it", "kind": "function", "arity": None, "doc": None},  # C-builtin-like
            ],
        }  # fmt: skip
        _writer2, src2 = _generate(None, "fakeext", fake)
        ast.parse(src2)
        self.assertIn("Widget", src2)


class TestParity(unittest.TestCase):
    def _live_lists(self, module):
        parent = _Parent()
        fd, path = tempfile.mkstemp(suffix=".py")
        os.close(fd)
        try:
            w = WritePythonCode(parent, path, module, module.__name__,
                                threads=False, _async=False, plugin_manager=None)  # fmt: skip
            return (sorted(w.module_functions), sorted(w.module_classes), sorted(w.module_objects))
        finally:
            os.unlink(path)

    def test_live_vs_subprocess_name_lists_match(self):
        import json as jsonmod

        live = self._live_lists(jsonmod)
        meta = introspect_module(PYEXE, "json")
        w, _ = _generate(None, "json", meta)
        got = (sorted(w.module_functions), sorted(w.module_classes), sorted(w.module_objects))
        self.assertEqual(live, got)


class TestPackageEnumeration(unittest.TestCase):
    def test_enumerate_script_is_valid_python(self):
        ast.parse(_ENUMERATE_SRC)

    def test_empty_and_bad_packages(self):
        self.assertEqual(enumerate_packages(PYEXE, [])["submodules"], [])
        # a single-file module (no __path__) yields no submodules; a missing package is skipped
        data = enumerate_packages(PYEXE, ["bisect", "no_such_pkg_zzz"])
        self.assertTrue(data["ok"])
        self.assertEqual(data["submodules"], [])

    def test_enumeration_matches_runner_walk(self):
        # Parity: subprocess enumeration + the SHARED keep_walked_module filter yields the same
        # submodule set as the runner-side ListAllModules.discover_modules walk.
        import email

        lm = ListAllModules(None, False, True, MODULE_BLACKLIST, False, verbose=False)
        live = {name for _f, name, _p in lm.discover_modules(list(email.__path__), "email.")}
        data = enumerate_packages(PYEXE, ["email"])
        meta = {
            s["name"]
            for s in data["submodules"]
            if lm.keep_walked_module(
                s["name"],
                s["ispkg"],
                s.get("origin"),
                s.get("search_path", ""),
                "",
                s.get("package"),
            )
        }
        self.assertTrue(live)  # sanity: email has submodules
        self.assertEqual(live, meta)


if __name__ == "__main__":
    unittest.main()
