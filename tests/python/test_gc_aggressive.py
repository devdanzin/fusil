"""Tests for --gc-aggressive: emit gc.set_threshold(1, 1, 1) at the top of the script."""

import ast
import os
import sys
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", ".."))  # repo root
sys.path.insert(0, os.path.join(SCRIPT_DIR, ".."))  # tests/ -> python._test_options

import json as _target

from python._test_options import make_test_options

from fusil.python.write_python_code import WritePythonCode


class _Parent:
    def __init__(self, options):
        self.options = options
        self.filenames = ["/bin/sh"]

    def warning(self, *a, **k):
        pass


def _generate(gc_aggressive):
    options = make_test_options(
        no_numpy=True, no_tstrings=True, gc_aggressive=gc_aggressive, functions_number=2
    )
    fd, path = tempfile.mkstemp(suffix="_gc.py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            _Parent(options), path, _target, "json", threads=False, _async=False
        )
        writer.generate_fuzzing_script()
        with open(path) as fh:
            return fh.read()
    finally:
        os.unlink(path)


class TestGcAggressive(unittest.TestCase):
    def test_emitted_when_on(self):
        src = _generate(gc_aggressive=True)
        ast.parse(src)
        self.assertIn("gc.set_threshold(1, 1, 1)", src)
        self.assertIn("import gc", src)

    def test_absent_when_off(self):
        src = _generate(gc_aggressive=False)
        ast.parse(src)
        self.assertNotIn("gc.set_threshold(1, 1, 1)", src)

    def test_guarded_so_a_non_cpython_target_survives_the_prelude(self):
        """`gc.set_threshold` is CPython-only, and the prelude runs on the TARGET.

        Unguarded, it raises AttributeError at module level on PyPy -- before a single target
        call -- so every session dies in the prelude scoring 0. That failure is silent: the
        sessions look clean rather than broken. One 43 368-session PyPy fleet produced zero
        crashes, zero timeouts and 0.3-second sessions entirely for this reason.
        """
        src = _generate(gc_aggressive=True)
        tree = ast.parse(src)

        call = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "set_threshold"
            ):
                call = node
                break
        self.assertIsNotNone(call, "gc.set_threshold was not emitted")

        # It must sit inside a try/except that catches AttributeError.
        guarded = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            if not any(n is call for n in ast.walk(node)):
                continue
            for handler in node.handlers:
                names = []
                if isinstance(handler.type, ast.Name):
                    names = [handler.type.id]
                elif isinstance(handler.type, ast.Tuple):
                    names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
                elif handler.type is None:
                    names = ["AttributeError"]  # bare except catches it
                if "AttributeError" in names or "Exception" in names:
                    guarded = True
        self.assertTrue(
            guarded,
            "gc.set_threshold must be wrapped in try/except AttributeError: it is CPython-only "
            "and the prelude runs on the target interpreter",
        )

    def test_the_emitted_guard_actually_survives_a_gc_without_set_threshold(self):
        """Exec the emitted snippet against a gc module that lacks the attribute."""
        src = _generate(gc_aggressive=True)
        start = src.index("import gc")
        snippet = src[start : src.index("\n\n", start)]

        import types

        fake_gc = types.ModuleType("gc")  # no set_threshold, like PyPy's
        real = sys.modules.get("gc")
        sys.modules["gc"] = fake_gc
        try:
            exec(compile(snippet, "<emitted>", "exec"), {})
        finally:
            if real is not None:
                sys.modules["gc"] = real


if __name__ == "__main__":
    unittest.main()
