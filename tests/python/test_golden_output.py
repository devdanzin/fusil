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
    no_faulthandler = False  # the real default: the golden covers the emitted block
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
    oom_foreign = False
    oom_foreign_pythonmalloc = False
    tsan = False


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


class SkipTrivialTypeTests(unittest.TestCase):
    """The emitted ``skip_trivial_type`` must refuse to dive into cffi objects.

    ``--blacklist`` excludes ``_cffi_backend`` / ``_rawffi`` / ``ctypes`` by MODULE NAME, but
    PyPy's stdlib hands out live cffi objects as module ATTRIBUTES -- ``resource.ffi``,
    ``_ssl.ffi``, ``_sqlite3._ffi``, ``_lzma.ffi``, ``_tkinter.tkffi`` and their matching
    ``.lib`` -- so the int-as-pointer surface was reachable regardless. Four consecutive PyPy
    fleets kept dirs from it.

    The function is emitted as SOURCE into every generated script, so testing the snapshot
    text alone would not catch a logic error in it. Exec the emitted definition and exercise
    it, matching on the type's defining module rather than on the attribute name.
    """

    def _emitted_skip_trivial_type(self):
        source = generate()
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "skip_trivial_type":
                namespace = {}
                # TRIVIAL_TYPES is assigned just above the def in the same emitted block.
                for prior in tree.body:
                    if (
                        isinstance(prior, ast.Assign)
                        and getattr(prior.targets[0], "id", "") == "TRIVIAL_TYPES"
                    ):
                        exec(compile(ast.Module([prior], []), "<emitted>", "exec"), namespace)
                exec(compile(ast.Module([node], []), "<emitted>", "exec"), namespace)
                return namespace["skip_trivial_type"]
        self.fail("skip_trivial_type was not emitted")

    def test_cffi_objects_are_skipped_and_ordinary_objects_are_not(self):
        skip = self._emitted_skip_trivial_type()

        class _FakeFFI:
            pass

        # cffi types report _cffi_backend as their defining module; that is the signal, not
        # the attribute name the object happens to be bound to.
        _FakeFFI.__module__ = "_cffi_backend"
        self.assertTrue(skip(_FakeFFI()))

        class _OrdinaryTarget:
            pass

        self.assertFalse(skip(_OrdinaryTarget()))

    def test_trivial_types_are_still_skipped(self):
        skip = self._emitted_skip_trivial_type()
        for value in (1, "s", 1.0, True, b"b", (), [], {}, set(), None):
            with self.subTest(value=value):
                self.assertTrue(skip(value))

    def test_an_attribute_merely_NAMED_ffi_is_not_skipped(self):
        """Name-based matching would collide with legitimate targets; this is type-based."""
        skip = self._emitted_skip_trivial_type()

        class ffi:  # noqa: N801 - deliberately named like the cffi attribute
            pass

        self.assertFalse(skip(ffi()))


class SelfNoiseVocabularyTests(unittest.TestCase):
    """Emitted COMMENTS must not contain fusil's own crash vocabulary.

    ``pydoc.getdoc`` falls back to ``inspect.getcomments()`` for an object with no
    docstring, so the comment block immediately above an undocumented class in a spliced
    sample file is printed verbatim by ``help(obj)``. A fuzz session that calls
    ``help()`` -- ``_sitebuiltins._Helper.__call__`` is a normal fuzz target -- therefore
    echoes those comments into stdout, where ``WatchStdout`` matches them and manufactures
    a crash. One PyPy fleet kept a ``_sitebuiltins-segfault`` dir this way, scored 100% on
    fusil's own word ``segfault`` inside a ``tricky_objects.py`` comment.

    Only comment lines are checked: the scored words also occur in real emitted CODE
    (``SystemError`` in the bomb exception list, ``AssertionError`` in a class statement),
    which ``inspect.getcomments`` never reaches.
    """

    # The 1.0-scoring words from Fuzzer.setupProject's WatchStdout configuration. The
    # sub-1.0 words ("bug", "fatal", "oops") are not listed: they cannot score a session
    # on their own and appear unavoidably in explanatory prose.
    CRASH_WORDS = (
        "assertion",
        "critical",
        "panic",
        "panicked",
        "glibc detected",
        "segfault",
        "segmentation fault",
        "addresssanitizer",
    )

    def test_emitted_comments_are_free_of_crash_words(self):
        offenders = []
        for lineno, line in enumerate(generate().splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue
            lowered = stripped.lower()
            for word in self.CRASH_WORDS:
                if word in lowered:
                    offenders.append((lineno, word, stripped[:100]))
                    break
        self.assertEqual(
            offenders,
            [],
            "generated comments contain crash vocabulary that help() would echo into "
            "stdout, scoring the session as a false crash; reword them:\n"
            + "\n".join("  line %d [%s] %s" % o for o in offenders),
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
