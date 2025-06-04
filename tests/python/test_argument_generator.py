import unittest
import sys
from random import seed # To make tests reproducible if needed

# Add fusil to path if tests are run from a different directory
# This might need adjustment based on your exact test running setup
# For example, if tests/ is a sibling of fusil/
# sys.path.insert(0, '..') # Assuming tests/ is one level down from the root where fusil/ is

from fusil.python.argument_generator import ArgumentGenerator
from fusil.config import FusilConfig # ArgumentGenerator needs options
# You might need to mock or provide minimal options for FusilConfig

class TestArgumentGenerator(unittest.TestCase):

    def setUp(self):
        """
        Set up for each test. This will be called before every test method.
        """
        # Create a minimal FusilConfig or mock options
        # For now, let's assume default options are sufficient or create a dummy one
        # In a real scenario, you might pass a mock object or a simplified config
        mock_options = FusilConfig(read=False) # Create a default config without reading files

        # Add any specific options ArgumentGenerator might expect if not covered by defaults
        mock_options.no_numpy = False # Assuming defaults, adjust if needed
        mock_options.no_tstrings = True # Example: disable tstrings if TEMPLATES is None
        # ... any other relevant options ...
        mock_options.fuzz_exceptions = getattr(mock_options, 'fuzz_exceptions', False) # Ensure it exists


        self.arg_gen = ArgumentGenerator(
            options=mock_options,
            filenames=["/tmp/testfile1.txt", "/tmp/testfile2.log"], # Dummy filenames
            use_numpy=True,  # Enable/disable based on your testing focus
            use_templates=True, # Enable/disable
            use_h5py=True # Enable/disable, though not directly used by base ArgumentGenerator methods
        )
        # Optional: seed random for reproducible tests if generation is heavily random
        # seed(12345)

    def assertIsListOfStrings(self, result, method_name):
        self.assertIsInstance(result, list, f"{method_name} should return a list.")
        for item in result:
            self.assertIsInstance(item, str, f"Items in list from {method_name} should be strings.")

    def test_genNone(self):
        result = self.arg_gen.genNone()
        self.assertIsListOfStrings(result, "genNone")
        self.assertEqual(len(result), 1, "genNone should return a list with one element.")
        self.assertEqual(result[0], "None", "genNone should return 'None'.")

    def test_genBool(self):
        result = self.arg_gen.genBool()
        self.assertIsListOfStrings(result, "genBool")
        self.assertEqual(len(result), 1)
        self.assertIn(result[0], ["True", "False"], "genBool should return 'True' or 'False'.")

        # Check for variety (optional, might sometimes fail by chance if not seeded)
        outputs = {self.arg_gen.genBool()[0] for _ in range(20)}
        self.assertTrue(len(outputs) > 1, "genBool should produce varied outputs over time.")

    def test_genInt(self):
        result = self.arg_gen.genInt()
        self.assertIsListOfStrings(result, "genInt")
        self.assertEqual(len(result), 1)
        try:
            val = eval(result[0])  # Use eval cautiously, or use regex
            self.assertIsInstance(val, int, "genInt should produce a string representing an integer.")
        except Exception as e:
            self.fail(f"eval({result[0]}) from genInt failed: {e}")

    def test_genString(self):
        result = self.arg_gen.genString()
        self.assertIsListOfStrings(result, "genString")
        self.assertEqual(len(result), 1)
        val_str = result[0]
        self.assertTrue(
            (val_str.startswith('"') and val_str.endswith('"')) or \
            (val_str.startswith("'") and val_str.endswith("'")),
            f"genString output '{val_str}' should be a quoted string."
        )
        # Further checks could involve trying to eval it to see if it's valid string literal
        try:
            eval(val_str)
        except SyntaxError:
            self.fail(f"genString produced a syntactically invalid string literal: {val_str}")

    def test_genList(self):
        result = self.arg_gen.genList()
        self.assertIsListOfStrings(result, "genList")
        # A list can be empty '[]' or multi-line
        full_expr = "".join(result)
        self.assertTrue(full_expr.startswith("[") and full_expr.endswith("]"),
                        f"genList output '{full_expr}' should start with [ and end with ].")
        # More complex: try to eval if contents are simple enough, or just check structure

    def test_create_simple_argument_runs_without_error(self):
        # This is a broader test to ensure the main dispatcher works
        try:
            for _ in range(10):  # Call it a few times
                result = self.arg_gen.create_simple_argument()
                self.assertIsListOfStrings(result, "create_simple_argument")
        except Exception as e:
            self.fail(f"create_simple_argument raised an unexpected exception: {e}")

    def test_create_hashable_argument_is_likely_hashable_expr(self):
        # Check that the generated expression is likely to be hashable
        # This is heuristic as we don't want to eval too much.
        for _ in range(20):
            result = self.arg_gen.create_hashable_argument()
            self.assertIsListOfStrings(result, "create_hashable_argument")
            expr_str = "".join(result)
            # Avoid lists, dicts, sets as top-level from hashable
            self.assertFalse(expr_str.lstrip().startswith('['),
                             f"Hashable arg '{expr_str}' shouldn't be a list literal.")
            self.assertFalse(expr_str.lstrip().startswith('{') and not expr_str.lstrip().startswith('set('),
                             f"Hashable arg '{expr_str}' shouldn't be a dict literal.")
            # Note: set literals like {1,2} are also hashable issues if they *contain* unhashable types.
            # This test is primarily for the top-level structure.


if __name__ == '__main__':
    unittest.main()