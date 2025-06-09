import unittest
import sys
import os
import types
import typing
import collections.abc

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    # --- Import the object to be tested ---
    from fusil.python.samples.tricky_typing import big_union
    TYPING_AVAILABLE = True
except (ImportError, TypeError) as e:
    # This can happen if the Python version is too old for some typing features
    print(f"Could not import tricky_typing module, skipping tests: {e}", file=sys.stderr)
    big_union = None
    TYPING_AVAILABLE = False


@unittest.skipIf(not TYPING_AVAILABLE, "Could not import tricky_typing module, skipping tests.")
class TestTrickyTyping(unittest.TestCase):
    """
    Test suite for the tricky_typing sample module.

    These tests verify that the final 'big_union' object is constructed
    correctly, contains the expected types, and has filtered out unwanted types.
    """

    def test_big_union_is_valid_type(self):
        """
        Verifies that 'big_union' is a valid Union type object.
        """
        # In Python 3.10+, unions created with | are types.UnionType.
        # In older versions, they are typing.Union. We check for both.
        self.assertTrue(
            isinstance(big_union, (types.UnionType, typing.Union)),
            f"'big_union' is not a valid Union type, but {type(big_union)}"
        )

    def test_big_union_contains_expected_types(self):
        """
        Verifies that 'big_union' contains a sample of key expected types.
        """
        # typing.get_args() lets us inspect the contents of the Union
        union_contents = typing.get_args(big_union)

        # Check for types from various modules to ensure they were all processed
        self.assertIn(int, union_contents, "int (the base type) should be in the union")
        self.assertIn(str, union_contents, "str from builtins should be in the union")
        self.assertIn(collections.abc.Iterable, union_contents, "Iterable from collections.abc should be in the union")
        self.assertIn(typing.Generic, union_contents, "Generic from typing should be in the union")
        self.assertIn(types.ModuleType, union_contents, "ModuleType from types should be in the union")

    def test_big_union_excludes_exceptions(self):
        """
        Verifies that the filtering logic correctly excluded exception types.
        """
        union_contents = typing.get_args(big_union)

        # Check that common exception types are NOT in the union
        self.assertNotIn(Exception, union_contents, "Exception class should have been filtered out")
        self.assertNotIn(ValueError, union_contents, "ValueError class should have been filtered out")
        self.assertNotIn(BaseException, union_contents, "BaseException class should have been filtered out")


if __name__ == '__main__':
    unittest.main()
