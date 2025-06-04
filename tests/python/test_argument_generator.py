import unittest
import sys
from random import seed, choice as random_choice  # For potentially overriding choice
from unittest.mock import patch  # For more advanced mocking if needed

# Add fusil to path if tests are run from a different directory
# (Adjust as per your project structure)
# import os
# SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# sys.path.insert(0, os.path.join(SCRIPT_DIR, '..', '..')) # Assuming tests/python/

from fusil.python.argument_generator import ArgumentGenerator, TEMPLATES
from fusil.config import FusilConfig
import fusil.python.tricky_weird  # To access its defined names


# Ensure dummy files exist if genExistingFilename is tested heavily
# For simplicity, we'll mock its output or check if it gracefully handles missing files.

class TestArgumentGenerator(unittest.TestCase):

    def _setup_arg_gen(self, use_numpy=True, use_templates=True, use_h5py=True, no_numpy_opt=False,
                       no_tstrings_opt=False):
        """Helper to initialize ArgumentGenerator with specific options."""
        mock_options = FusilConfig(read=False)

        # Apply options that affect ArgumentGenerator's internal lists
        mock_options.no_numpy = no_numpy_opt
        mock_options.no_tstrings = no_tstrings_opt

        # Ensure other potentially accessed options have defaults
        mock_options.functions_number = getattr(mock_options, 'functions_number', 10)  # Example default
        mock_options.methods_number = getattr(mock_options, 'methods_number', 5)
        mock_options.classes_number = getattr(mock_options, 'classes_number', 5)
        mock_options.objects_number = getattr(mock_options, 'objects_number', 5)
        mock_options.fuzz_exceptions = getattr(mock_options, 'fuzz_exceptions', False)

        # Default filenames, can be overridden in specific tests if needed
        default_filenames = ["/tmp/testfile1.txt", "/tmp/testfile2.log"]
        if hasattr(mock_options, 'filenames') and not mock_options.filenames:
            mock_options.filenames = ",".join(default_filenames)
        elif not hasattr(mock_options, 'filenames'):
            mock_options.filenames = ",".join(default_filenames)

        self.arg_gen = ArgumentGenerator(
            options=mock_options,
            filenames=mock_options.filenames.split(',') if mock_options.filenames else default_filenames,
            use_numpy=use_numpy,
            use_templates=use_templates,
            use_h5py=use_h5py
        )
        # Optional: seed(12345) for reproducibility during development

    def setUp(self):
        """Default setup: all features enabled in ArgumentGenerator construction,
           and no conflicting options."""
        self._setup_arg_gen(use_numpy=True, use_templates=True, use_h5py=True,
                            no_numpy_opt=False, no_tstrings_opt=False)

    def assertIsListOfStrings(self, result, method_name):
        self.assertIsInstance(result, list, f"{method_name} should return a list.")
        if result:  # Only check items if list is not empty
            for item in result:
                self.assertIsInstance(item, str,
                                      f"Items in list from {method_name} should be strings. Got: {type(item)} for item '{item}'")

    # --- Previous test methods (genNone, genBool, genInt, genString) ---
    # (Keep them as they are good base cases)
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

        outputs = {self.arg_gen.genBool()[0] for _ in range(20)}
        self.assertTrue(len(outputs) >= 1, "genBool should produce at least one valid output.")
        if "True" in outputs and "False" in outputs:  # Ideal case for variety
            self.assertTrue(len(outputs) > 1, "genBool should ideally produce varied outputs over time.")

    def test_genInt(self):
        result = self.arg_gen.genInt()
        self.assertIsListOfStrings(result, "genInt")
        self.assertEqual(len(result), 1)
        try:
            val = eval(result[0])  # Use eval cautiously
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
        try:
            eval(val_str)
        except SyntaxError:
            self.fail(f"genString produced a syntactically invalid string literal: {val_str}")

    # --- Tests for collection types ---
    def test_genList_structure(self):
        result = self.arg_gen.genList()
        self.assertIsListOfStrings(result, "genList")
        full_expr = "".join(result)
        self.assertTrue(full_expr.startswith("[") and full_expr.endswith("]"),
                        f"genList output '{full_expr}' should start with [ and end with ].")
        try:
            # This is a more robust check, but relies on generated content also being valid
            eval(full_expr)
        except Exception as e:
            self.fail(f"genList produced an invalid expression '{full_expr}': {e}")

    def test_genTuple_structure(self):
        result = self.arg_gen.genTuple()
        self.assertIsListOfStrings(result, "genTuple")
        full_expr = "".join(result)
        self.assertTrue(full_expr.startswith("(") and full_expr.endswith(")"),
                        f"genTuple output '{full_expr}' should start with ( and end with ).")
        try:
            eval(full_expr)
        except Exception as e:
            self.fail(f"genTuple produced an invalid expression '{full_expr}': {e}")

    def test_genDict_structure(self):
        result = self.arg_gen.genDict()
        self.assertIsListOfStrings(result, "genDict")
        full_expr = "".join(result)
        self.assertTrue(full_expr.startswith("{") and full_expr.endswith("}"),
                        f"genDict output '{full_expr}' should start with {{ and end with }}.")
        try:
            eval(full_expr)
        except Exception as e:
            self.fail(f"genDict produced an invalid expression '{full_expr}': {e}")

    def test_genList_empty(self):
        # To test empty list generation, we might need to influence randint or run many times
        # For now, let's assume it *can* generate empty lists. A more targeted test:
        with patch('random.randint', return_value=0):  # Force nb_item = 0
            result = self.arg_gen.genList()
            self.assertEqual("".join(result), "[]")

    # --- Tests for specific value generators ---
    def test_genExistingFilename(self):
        # Test with default filenames from setUp
        result = self.arg_gen.genExistingFilename()
        self.assertIsListOfStrings(result, "genExistingFilename")
        self.assertEqual(len(result), 1)
        # Ensure the returned string is one of the provided filenames, correctly quoted
        expected_filenames_quoted = [f"'{f.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}'"
                                     for f in self.arg_gen.filenames]
        self.assertIn(result[0], expected_filenames_quoted,
                      f"genExistingFilename did not return one of the expected filenames: {result[0]}")

        # Test with no filenames provided to ArgumentGenerator
        self._setup_arg_gen(use_numpy=False, use_templates=False, use_h5py=False)  # Re-init with no filenames
        self.arg_gen.filenames = []  # Explicitly empty it
        result_no_files = self.arg_gen.genExistingFilename()
        self.assertIsListOfStrings(result_no_files, "genExistingFilename (no files)")
        self.assertEqual(result_no_files[0], '"NO_FILE_AVAILABLE"')

    def test_genTrickyObjects(self):
        result = self.arg_gen.genTrickyObjects()
        self.assertIsListOfStrings(result, "genTrickyObjects")
        self.assertEqual(len(result), 1)
        self.assertIn(result[0], fusil.python.tricky_weird.tricky_objects_names,
                      "genTrickyObjects should pick from tricky_objects_names.")

    def test_genInterestingValues(self):
        result = self.arg_gen.genInterestingValues()
        self.assertIsListOfStrings(result, "genInterestingValues")
        self.assertEqual(len(result), 1)
        self.assertIn(result[0], fusil.python.values.INTERESTING,
                      "genInterestingValues should pick from INTERESTING values.")

    # --- Testing the effect of options on create_simple_argument ---

    def _check_if_generator_in_tuple(self, generator_method_name, arg_gen_tuple_name):
        """Checks if a specific generator method (by name) is in a generator tuple."""
        arg_gen_tuple = getattr(self.arg_gen, arg_gen_tuple_name)
        for gen_func_or_tuple in arg_gen_tuple:
            if isinstance(gen_func_or_tuple, tuple):  # Handle weighted tuples like (method,) * 50
                actual_func = gen_func_or_tuple[0]
            else:
                actual_func = gen_func_or_tuple

            if hasattr(actual_func, '__name__') and actual_func.__name__ == generator_method_name:
                return True
            # For methods of H5PyArgumentGenerator, which are bound methods
            if hasattr(actual_func, '__func__') and hasattr(actual_func.__func__,
                                                            '__name__') and actual_func.__func__.__name__ == generator_method_name:
                if actual_func.__self__ == self.arg_gen.h5py_argument_generator:
                    return True
        return False

    def test_simple_generators_composition_with_numpy_h5py(self):
        self._setup_arg_gen(use_numpy=True, use_h5py=True, no_numpy_opt=False)
        self.assertTrue(self._check_if_generator_in_tuple('genTrickyNumpy', 'simple_argument_generators'))
        self.assertTrue(self._check_if_generator_in_tuple('genH5PyObject', 'simple_argument_generators'))

    def test_simple_generators_composition_without_numpy_opt(self):
        self._setup_arg_gen(use_numpy=True, use_h5py=True, no_numpy_opt=True)  # no_numpy option is True
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyNumpy', 'simple_argument_generators'))
        # genH5PyObject also depends on numpy not being disabled by options
        self.assertFalse(self._check_if_generator_in_tuple('genH5PyObject', 'simple_argument_generators'))

    def test_simple_generators_composition_without_numpy_init(self):
        self._setup_arg_gen(use_numpy=False, use_h5py=True, no_numpy_opt=False)  # use_numpy init flag is False
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyNumpy', 'simple_argument_generators'))
        self.assertFalse(self._check_if_generator_in_tuple('genH5PyObject', 'simple_argument_generators'))

    def test_complex_generators_composition_with_templates(self):
        if TEMPLATES:  # Only run if templates are supposed to be available
            self._setup_arg_gen(use_templates=True, no_tstrings_opt=False)
            self.assertTrue(self._check_if_generator_in_tuple('genTrickyTemplate', 'complex_argument_generators'))
        else:
            self.skipTest("Template strings (TEMPLATES) not available for testing genTrickyTemplate.")

    def test_complex_generators_composition_without_templates_opt(self):
        self._setup_arg_gen(use_templates=True, no_tstrings_opt=True)  # no_tstrings option is True
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyTemplate', 'complex_argument_generators'))

    def test_complex_generators_composition_without_templates_init(self):
        self._setup_arg_gen(use_templates=False, no_tstrings_opt=False)  # use_templates init flag is False
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyTemplate', 'complex_argument_generators'))

    def test_create_simple_argument_variety(self):
        """Try to detect if create_simple_argument uses different sub-generators."""
        self._setup_arg_gen(use_numpy=True, use_templates=True, use_h5py=True,
                            no_numpy_opt=False, no_tstrings_opt=False)

        # This is a probabilistic test. We try to see if different kinds of expressions are generated.
        # A more robust way would be to mock 'random.choice' used within create_simple_argument
        # to control which sub-generator is picked.

        seen_types = set()
        for _ in range(100):  # More iterations increase chance of hitting different generators
            arg_list = self.arg_gen.create_simple_argument()
            arg_str = "".join(arg_list)
            if arg_str == "None":
                seen_types.add("None")
            elif arg_str in ["True", "False"]:
                seen_types.add("Bool")
            elif arg_str.isdigit() or (arg_str.startswith('-') and arg_str[1:].isdigit()):
                seen_types.add("Int")
            elif arg_str.startswith("b'") or arg_str.startswith('b"'):
                seen_types.add("Bytes")
            elif arg_str.startswith("'") or arg_str.startswith('"'):
                seen_types.add("String")
            elif "numpy" in arg_str:
                seen_types.add("Numpy")
            elif "h5py_tricky_objects" in arg_str:
                seen_types.add("H5PyObject")
            elif "weird_instances" in arg_str:
                seen_types.add("WeirdInstance")
            # Add more checks for other types if needed

        # Expect to see a few different types of arguments generated
        self.assertTrue(len(seen_types) > 3, f"create_simple_argument did not show much variety. Seen: {seen_types}")


if __name__ == '__main__':
    unittest.main()