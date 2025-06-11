import unittest
import sys
import os
import ast

# --- Test Setup: Path Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    from fusil.python.values import INTERESTING, BUFFER_OBJECTS, SURROGATES
    VALUES_AVAILABLE = True
except ImportError as e:
    print(f"Could not import values module, skipping tests: {e}", file=sys.stderr)
    INTERESTING, BUFFER_OBJECTS, SURROGATES = None, None, None
    VALUES_AVAILABLE = False


@unittest.skipIf(not VALUES_AVAILABLE, "Could not import values module, skipping tests.")
class TestValues(unittest.TestCase):
    """
    Test suite for the values.py module.

    Verifies that the constant lists of interesting values and buffer
    objects are correctly defined and syntactically valid.
    """

    def test_interesting_values_list(self):
        """
        Verifies the INTERESTING list of boundary values and their syntax.
        """
        self.assertIsInstance(INTERESTING, tuple)
        self.assertGreater(len(INTERESTING), 0)

        # Check for the presence of a few key boundary values
        self.assertIn("0", INTERESTING)
        self.assertIn('float("-inf")', INTERESTING)
        self.assertIn("-2 ** 31", INTERESTING)
        self.assertIn("sys.maxsize", INTERESTING)

        # NEW: Verify that every single item in the list is valid Python syntax
        for i, expr in enumerate(INTERESTING):
            with self.subTest(i=i, expr=expr):
                try:
                    ast.parse(expr)
                except SyntaxError as e:
                    self.fail(f"INTERESTING contains an invalid expression: '{expr}'. Error: {e}")

    def test_buffer_objects_list(self):
        """
        Verifies the BUFFER_OBJECTS list of buffer-like expressions.
        """
        self.assertIsInstance(BUFFER_OBJECTS, tuple)
        self.assertGreater(len(BUFFER_OBJECTS), 0)

        # Check for a representative example
        self.assertIn('bytearray(b"test")', BUFFER_OBJECTS)

        # Ensure every expression in the list is syntactically valid
        for i, expr in enumerate(BUFFER_OBJECTS):
            with self.subTest(i=i, expr=expr):
                try:
                    ast.parse(expr)
                except SyntaxError as e:
                    self.fail(f"BUFFER_OBJECTS contains an invalid expression: '{expr}'. Error: {e}")

    def test_surrogates_constant(self):
        """
        Verifies the SURROGATES constant for Unicode surrogates.
        """
        self.assertIsInstance(SURROGATES, tuple)
        self.assertGreater(len(SURROGATES), 0)
        # Verify that all surrogates are strings and are not valid ASCII
        for i, expr in enumerate(SURROGATES):
            with self.subTest(i=i, expr=expr):
                self.assertIsInstance(expr, str)
                evaluated = eval(expr)
                self.assertFalse(evaluated.isascii() and evaluated != "\x00", f"Surrogate pair string '{expr}' should not be ASCII.")


if __name__ == '__main__':
    unittest.main()
