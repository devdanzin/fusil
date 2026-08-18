"""Generated-script compatibility with pre-3.13 *targets* (PyPy 3.11, CPython 3.11/3.12).

fusil's own floor is 3.13 (``requires-python``), but that constrains the **runner**. The
generated ``source.py`` is executed by ``--python``, which is routinely an older or
alternative interpreter -- PyPy 3.11 is a whole fuzzing target of its own. Two 3.13+/3.12+
constructs used to leak into the emitted script and abort *every* session before any
fuzzing happened, which is invisible from the outside: the run looks clean because nothing
crashed, when in fact nothing ran.

Both regressions are cheap to make and expensive to notice, so they are locked in here.
"""

import os
import pathlib
import re
import sys
import types
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = pathlib.Path(SCRIPT_DIR).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

SAMPLES = PROJECT_ROOT / "fusil" / "python" / "samples"
GOLDEN = PROJECT_ROOT / "tests" / "python" / "golden" / "fakemod_seed1234.py"

# `f"{x!r }"` -- a space between the conversion and the closing brace -- is PEP 701 syntax,
# accepted only by 3.12+. On a 3.11 target it is a SyntaxError, so the script never parses.
CONVERSION_THEN_SPACE = re.compile(r"![rsa]\s+\}")


class TestPreludeSurvivesOldTarget(unittest.TestCase):
    """The tricky-objects prelude must import on a target without 3.13+ attributes."""

    def test_tricky_objects_runs_without_types_CapsuleType(self):
        # types.CapsuleType is 3.13+. PyPy 3.11 (and CPython <3.13) do not have it; an
        # unguarded read raises AttributeError at line ~280 of every generated script,
        # killing the session during the prelude -- before a single call is fuzzed.
        source = (SAMPLES / "tricky_objects.py").read_text()

        shim = types.ModuleType("types")
        for name in dir(types):
            if name != "CapsuleType":
                setattr(shim, name, getattr(types, name))
        self.assertFalse(hasattr(shim, "CapsuleType"))

        namespace = {"__name__": "tricky_objects_under_old_target"}
        real_types = sys.modules["types"]
        sys.modules["types"] = shim
        try:
            exec(compile(source, "tricky_objects.py", "exec"), namespace)
        finally:
            sys.modules["types"] = real_types

        # The module already guards optional attributes this way (see tricky_genericalias),
        # and the `if tricky_capsule:` use site below it expects a falsy value.
        self.assertIsNone(namespace["tricky_capsule"])


class TestNoPEP701InEmittedCode(unittest.TestCase):
    """Emitters must not produce f-strings only a 3.12+ target can parse."""

    def test_emitters_do_not_write_a_space_after_a_conversion(self):
        offenders = []
        for path in sorted((PROJECT_ROOT / "fusil").rglob("*.py")):
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if CONVERSION_THEN_SPACE.search(line):
                    offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{lineno}: {line.strip()}")
        self.assertEqual(
            offenders,
            [],
            "these emit `{expr!r }` into the generated script, which is a SyntaxError on a "
            "3.11 target (PyPy 3.11); write `{expr!r}` instead:\n" + "\n".join(offenders),
        )

    def test_golden_snapshot_parses_as_pre_312_source(self):
        # The committed snapshot is the closest thing to a real emitted script that the
        # suite can check without spawning an interpreter.
        self.assertIsNone(CONVERSION_THEN_SPACE.search(GOLDEN.read_text()))


if __name__ == "__main__":
    unittest.main()
