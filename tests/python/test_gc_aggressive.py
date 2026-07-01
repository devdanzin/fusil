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


if __name__ == "__main__":
    unittest.main()
