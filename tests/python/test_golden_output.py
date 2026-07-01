"""Golden-output tests for the code generator.

``WritePythonCode`` is a pure function of (RNG seed, options, target module), so we can
pin all three and snapshot the generated ``source.py``. This is the safety net for
refactors of the generator's construction style (e.g. the indentation API -> ``with
self.indent():`` migration): a behaviour-preserving change must leave the output
byte-identical.

Determinism is engineered, not assumed:
- a fixed ``random.seed`` before each generation,
- a fully-pinned options object (concrete values -- no MagicMock, whose repr embeds a
  non-deterministic id that would leak into output),
- a fake target module with a fixed, public-only surface (``test_private=False`` makes the
  generator skip all dunders, so method introspection doesn't drift across Python versions),
- ``no_numpy``/``no_tstrings`` so output doesn't depend on whether numpy/h5py are installed.

To regenerate the committed snapshot after an *intentional* generator change:
    python -m tests.python.test_golden_output --update
"""

import ast
import os
import pathlib
import random
import sys
import tempfile
import types
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)

from fusil.python.write_python_code import WritePythonCode

GOLDEN_DIR = pathlib.Path(SCRIPT_DIR) / "golden"
GOLDEN_FILE = GOLDEN_DIR / "fakemod_seed1234.py"
SEED = 1234


class _Options:
    """A fully-pinned options stand-in (every attribute the generator reads)."""

    functions_number = 3
    classes_number = 1
    objects_number = 0
    methods_number = 2
    deep_dive = False
    gc_aggressive = False
    fuzz_exceptions = False
    test_private = False
    no_numpy = True
    no_tstrings = True
    external_references = True
    oom_fuzz = False
    oom_max_start = 50
    oom_calls = 3
    oom_classes = 0
    oom_methods = 0
    oom_verbose = False
    oom_seq = False
    oom_seq_len = 3
    oom_window = 1


class _Parent:
    """Minimal stand-in for the PythonSource parent the writer reads from."""

    def __init__(self):
        self.options = _Options()
        self.filenames = ["/tmp/fuzz_fixture"]

    def warning(self, *args, **kwargs):
        pass


def _fake_module():
    """A target module with a fixed, public-only surface (version-stable introspection)."""
    module = types.ModuleType("fakemod")

    def func_a(x=0):
        return x

    def func_b(a, b):
        return a + b

    class Widget:
        def method_one(self):
            return 1

        def method_two(self, n):
            return n

    module.func_a = func_a
    module.func_b = func_b
    module.Widget = Widget
    module.CONST = 42  # trivial type -> skipped by the member filter
    return module


def generate(seed=SEED):
    """Generate the fuzzing script for the fake module; deterministic for a given seed."""
    random.seed(seed)
    parent = _Parent()
    fd, path = tempfile.mkstemp(suffix="_golden.py")
    os.close(fd)
    try:
        writer = WritePythonCode(
            parent,
            path,
            _fake_module(),
            "fakemod",
            threads=False,
            _async=False,
            plugin_manager=None,
        )
        writer.generate_fuzzing_script()
        return pathlib.Path(path).read_text(encoding="utf-8")
    finally:
        os.unlink(path)


# The exact block emitted by the class-instantiation method under refactor
# (_fuzz_one_class). Version-independent (pure generator text + the fake class name), so it
# guards the indentation-API -> context-manager conversion on every interpreter, not just
# the canonical one the full snapshot is pinned to.
EXPECTED_CLASS_INSTANTIATION_BLOCK = """\
instance_c1_widget = None # Initialize instance variable
try:
    instance_c1_widget = callFunc('c1_init', 'Widget',
      )
except Exception as e_instantiate:
    instance_c1_widget = None
    print("[c1] Failed to instantiate Widget: {e_instantiate.__class__.__name__} {e_instantiate}", file=stderr)
    instance_c1_widget = None
"""


class TestGoldenOutput(unittest.TestCase):
    def test_generation_is_deterministic_and_valid(self):
        """Same seed -> byte-identical output, and the output is valid Python."""
        first = generate()
        second = generate()
        self.assertEqual(first, second, "generation is not deterministic for a fixed seed")
        ast.parse(first)

    def test_class_instantiation_block_unchanged(self):
        """The class-instantiation block (the refactored method) is emitted verbatim."""
        out = generate()
        self.assertIn(EXPECTED_CLASS_INSTANTIATION_BLOCK, out)

    @unittest.skipUnless(
        sys.version_info[:2] >= (3, 14),
        "full-script snapshot is pinned to the canonical interpreter (>=3.14); the "
        "determinism + block tests cover earlier versions",
    )
    def test_full_script_matches_snapshot(self):
        """The whole generated script matches the committed golden snapshot."""
        self.assertTrue(
            GOLDEN_FILE.is_file(),
            f"missing golden snapshot {GOLDEN_FILE}; regenerate with --update",
        )
        expected = GOLDEN_FILE.read_text(encoding="utf-8")
        self.assertEqual(
            generate(),
            expected,
            "generated output drifted from the golden snapshot; if intentional, "
            "regenerate with: python -m tests.python.test_golden_output --update",
        )


def _update_snapshot():
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    GOLDEN_FILE.write_text(generate(), encoding="utf-8")
    print(f"wrote {GOLDEN_FILE}")


if __name__ == "__main__":
    if "--update" in sys.argv:
        _update_snapshot()
    else:
        unittest.main()
