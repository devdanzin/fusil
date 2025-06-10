import ast
import unittest
import sys
import re  # For test_genWeirdUnion and test_genWeirdType
from random import randint, sample, seed, choice as random_choice
from unittest.mock import patch, MagicMock  # MagicMock for placeholders

# (Your sys.path setup if needed)
# import os
# SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# sys.path.insert(0, os.path.join(SCRIPT_DIR, '..', '..'))

import fusil.python.argument_generator
from fusil.config import FusilConfig
import fusil.python.tricky_weird
import fusil.python.values
import fusil.python.h5py.h5py_tricky_weird  # For h5py_tricky_names

USE_NUMPY = USE_H5PY = True
try:
    import numpy
except ImportError:
    USE_NUMPY = False
    numpy = None

try:
    import h5py
    import fusil.python.h5py.h5py_tricky_weird
    from fusil.python.h5py.h5py_argument_generator import H5PyArgumentGenerator
except ImportError:
    USE_H5PY = False
    h5py = None
    H5PyArgumentGenerator = None


class TestArgumentGenerator(unittest.TestCase):

    def _setup_arg_gen(self, use_numpy=True, use_templates=True, use_h5py_arg_gen=True,  # Renamed use_h5py for clarity
                       no_numpy_opt=False, no_tstrings_opt=False):
        mock_options = FusilConfig(read=False)
        mock_options.no_numpy = no_numpy_opt
        mock_options.no_tstrings = no_tstrings_opt
        mock_options.functions_number = getattr(mock_options, 'functions_number', 10)
        mock_options.methods_number = getattr(mock_options, 'methods_number', 5)
        mock_options.classes_number = getattr(mock_options, 'classes_number', 5)
        mock_options.objects_number = getattr(mock_options, 'objects_number', 5)
        mock_options.fuzz_exceptions = getattr(mock_options, 'fuzz_exceptions', False)

        default_filenames = ["/tmp/testfile1.txt", "/tmp/testfile2.log"]
        if hasattr(mock_options, 'filenames') and not mock_options.filenames:
            mock_options.filenames = ",".join(default_filenames)
        elif not hasattr(mock_options, 'filenames'):
            mock_options.filenames = ",".join(default_filenames)

        self.arg_gen = fusil.python.argument_generator.ArgumentGenerator(
            options=mock_options,
            filenames=mock_options.filenames.split(',') if mock_options.filenames else default_filenames,
            use_numpy=use_numpy,
            use_templates=use_templates,
            use_h5py=use_h5py_arg_gen  # Pass the renamed flag
        )

        # --- Define globals for eval() ---
        self.test_globals = {
            "sys": sys,  # For sys.maxsize, etc.
            "numpy": numpy,  # For numpy.nan, numpy.inf, etc. and direct numpy calls
            "h5py": h5py,  # For h5py.File, h5py.Empty etc.
            "MagicMock": MagicMock,  # For "MagicMock()" expressions
            "Liar1": MagicMock(name="Liar1_mock"),
            "Liar2": MagicMock(name="Liar2_mock"),
            "Evil": MagicMock(name="Evil_mock"),
            fusil.python.argument_generator.ERRBACK_NAME_CONST: MagicMock(name="errback_mock"),  # For "errback"
            "True": True, "False": False, "None": None,  # Basic builtins
            "object": object, "list": list, "dict": dict, "tuple": tuple, "set": set,
            "int": int, "float": float, "str": str, "bytes": bytes, "bytearray": bytearray,
            "Exception": Exception,
            "range": range, "len": len, "repr": repr, "choice": random_choice,  # if generated code uses them
            "randint": randint, "sample": sample,  # if generated code uses them
            # For template strings, if they were to be eval'd directly (they usually create Template objects)
            "Template": MagicMock(name="Template_mock"),
            "Interpolation": MagicMock(name="Interpolation_mock"),
        }

        # Placeholder for h5py_tricky_objects.get('name')
        # The .get() method will be called on this mock.
        h5py_tricky_objects_mock = MagicMock(name="h5py_tricky_objects_mock")
        h5py_tricky_objects_mock.get.return_value = "mocked_h5py_object"  # Default return for any .get()
        self.test_globals["h5py_tricky_objects"] = h5py_tricky_objects_mock

        # Placeholders for tricky_numpy names
        for name in fusil.python.tricky_weird.tricky_numpy_names:
            self.test_globals[name] = f"numpy_placeholder_for_{name}"

        # Placeholders for tricky_objects names
        for name in fusil.python.tricky_weird.tricky_objects_names:
            self.test_globals[name] = f"tricky_obj_placeholder_for_{name}"

        # Placeholders for weird_classes and weird_instances
        weird_classes_mock = MagicMock(name="weird_classes_mock")
        weird_classes_mock.__getitem__.return_value = "mocked_weird_class"
        self.test_globals["weird_classes"] = weird_classes_mock

        weird_instances_mock = MagicMock(name="weird_instances_mock")
        weird_instances_mock.__getitem__.return_value = "mocked_weird_instance"
        self.test_globals["weird_instances"] = weird_instances_mock

        # Placeholder for big_union (if it's just a name)
        self.test_globals["big_union"] = "mocked_big_union"

    def setUp(self):
        self._setup_arg_gen(use_numpy=True, use_templates=True, use_h5py_arg_gen=True,
                            no_numpy_opt=False, no_tstrings_opt=False)

    def assertIsListOfStrings(self, result, method_name):
        self.assertIsInstance(result, list, f"{method_name} should return a list.")
        if result:
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
            try:
                val = ast.literal_eval(result[0])  # Use ast.literal_eval
                self.assertIsInstance(val, int, f"{result[0]} did not evaluate to an integer.")
            except (ValueError, SyntaxError) as e:  # ast.literal_eval raises these
                self.fail(f"ast.literal_eval({result[0]}) failed: {e}")
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
            evaluated_content = ast.literal_eval(val_str)
            self.assertIsInstance(evaluated_content, str)  # Ensure it evaluated to a Python string
            # For test_genAsciiString, you can keep the content check:
            # self.assertTrue(all(0 <= ord(c) < 256 for c in evaluated_content), ...)
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on '{val_str}' failed: {e}")
    # --- Tests for collection types ---
    def test_genList_structure(self):
        result = self.arg_gen.genList()
        self.assertIsListOfStrings(result, "genList")
        full_expr = "".join(result)
        self.assertTrue(full_expr.startswith("[") and full_expr.endswith("]"),
                        f"genList output '{full_expr}' should start with [ and end with ].")
        try:
            parsed_ast = ast.parse(full_expr)  # Parse the expression
            self.assertTrue(parsed_ast.body, "ast.parse result should not be empty")
            self.assertIsInstance(parsed_ast.body[0], ast.Expr, "Parsed expression should be an ast.Expr")
            self.assertIsInstance(parsed_ast.body[0].value, ast.List,  # Check the value is an ast.List node
                                  f"Parsed expression '{full_expr}' is not an AST List node.")
        except SyntaxError as e:
            self.fail(f"genList produced a syntactically invalid expression '{full_expr}': {e}")

    def test_genTuple_structure(self):
        """
        Tests that genTuple produces a syntactically valid tuple expression.
        """
        full_expr = " ".join(self.arg_gen.genTuple())
        try:
            # Use mode='eval' for single expressions
            parsed_ast = ast.parse(full_expr, mode='eval')
        except SyntaxError as e:
            self.fail(f"genTuple produced a syntax error in expression '{full_expr}': {e}")

        # The result can be a tuple literal (ast.Tuple) or a call to the
        # constructor (ast.Call). We need to validate both possibilities.
        node = parsed_ast.body  # mode='eval' puts the node in .body

        if isinstance(node, ast.Call):
            # If it's a Call, verify it's a call to the name 'tuple'.
            self.assertEqual(getattr(node.func, 'id', None), 'tuple',
                             f"Expression '{full_expr}' is a Call, but not to tuple()")
        else:
            # Otherwise, it must be a literal tuple.
            self.assertIsInstance(node, ast.Tuple,
                                  f"Parsed expression '{full_expr}' is not an AST Tuple or Call node.")

    def test_genDict_structure(self):
        result = self.arg_gen.genDict()
        self.assertIsListOfStrings(result, "genDict")
        full_expr = "".join(result)
        self.assertTrue(full_expr.startswith("{") and full_expr.endswith("}"),
                        f"genDict output '{full_expr}' should start with {{ and end with }}.")
        try:
            parsed_ast = ast.parse(full_expr)
            self.assertTrue(parsed_ast.body, "ast.parse result should not be empty")
            self.assertIsInstance(parsed_ast.body[0], ast.Expr)
            self.assertIsInstance(parsed_ast.body[0].value, ast.Dict,
                                  f"Parsed expression '{full_expr}' is not an AST Dict node.")
        except SyntaxError as e:
            self.fail(f"genDict produced a syntactically invalid expression '{full_expr}': {e}")

    def test_genList_empty(self):
        # To test empty list generation, we might need to influence randint or run many times
        # For now, let's assume it *can* generate empty lists. A more targeted test:
        with patch('fusil.python.argument_generator.randint', return_value=0):  # Force nb_item = 0
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
        self._setup_arg_gen(use_numpy=False, use_templates=False, use_h5py_arg_gen=False)  # Re-init with no filenames
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

    @unittest.skipUnless(USE_NUMPY, "Only works with Numpy")
    def test_simple_generators_composition_with_numpy_h5py(self):
        self._setup_arg_gen(use_numpy=True, use_h5py_arg_gen=True, no_numpy_opt=False)
        self.assertTrue(self._check_if_generator_in_tuple('genTrickyNumpy', 'simple_argument_generators'))
        self.assertTrue(self._check_if_generator_in_tuple('genH5PyObject', 'simple_argument_generators'))

    def test_simple_generators_composition_without_numpy_opt(self):
        self._setup_arg_gen(use_numpy=True, use_h5py_arg_gen=True, no_numpy_opt=True)  # no_numpy option is True
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyNumpy', 'simple_argument_generators'))
        # genH5PyObject also depends on numpy not being disabled by options
        self.assertFalse(self._check_if_generator_in_tuple('genH5PyObject', 'simple_argument_generators'))

    def test_simple_generators_composition_without_numpy_init(self):
        self._setup_arg_gen(use_numpy=False, use_h5py_arg_gen=True, no_numpy_opt=False)  # use_numpy init flag is False
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyNumpy', 'simple_argument_generators'))
        self.assertFalse(self._check_if_generator_in_tuple('genH5PyObject', 'simple_argument_generators'))

    def test_complex_generators_composition_with_templates(self):
        if fusil.python.argument_generator.TEMPLATES:  # Only run if templates are supposed to be available
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
        self._setup_arg_gen(use_numpy=True, use_templates=True, use_h5py_arg_gen=True,
                            no_numpy_opt=False, no_tstrings_opt=False)

        # This is a probabilistic test. We try to see if different kinds of expressions are generated.
        # A more robust way would be to mock 'random.choice' used within create_simple_argument
        # to control which sub-generator is picked.

        seen_types = set()
        for _ in range(1000):  # More iterations increase chance of hitting different generators
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

    def test_genSmallUint(self):
        result = self.arg_gen.genSmallUint()
        self.assertIsListOfStrings(result, "genSmallUint")
        self.assertEqual(len(result), 1)
        try:
            try:
                val = ast.literal_eval(result[0])  # Use ast.literal_eval
                self.assertIsInstance(val, int, f"{result[0]} did not evaluate to an integer.")
                self.assertTrue(-19 <= val <= 19,
                                f"genSmallUint produced {val}, which is outside the expected range -19 to 19.")
            except (ValueError, SyntaxError) as e:  # ast.literal_eval raises these
                self.fail(f"ast.literal_eval({result[0]}) failed: {e}")
        except Exception as e:
            self.fail(f"eval({result[0]}) from genSmallUint failed: {e}")

        # Check for variety
        outputs = {int(self.arg_gen.genSmallUint()[0]) for _ in range(50)} # More iterations for better chance of variety
        self.assertTrue(len(outputs) > 1, "genSmallUint should ideally produce varied outputs.")

    def test_genBytes(self):
        result = self.arg_gen.genBytes()
        self.assertIsListOfStrings(result, "genBytes")
        self.assertEqual(len(result), 1)
        val_str = result[0]
        self.assertTrue(
            (val_str.startswith('b"') and val_str.endswith('"')) or \
            (val_str.startswith("b'") and val_str.endswith("'")),
            f"genBytes output '{val_str}' should be a quoted bytes literal."
        )
        try:
            val_bytes = ast.literal_eval(val_str)  # ast.literal_eval handles bytes literals
            self.assertIsInstance(val_bytes, bytes, f"'{val_str}' did not evaluate to bytes.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on '{val_str}' failed: {e}")

        # Test for empty bytes generation (might require mocking or many runs)
        # Forcing it with a patch:
        with patch.object(self.arg_gen.bytes_generator, 'createLength', return_value=0):
            result_empty = self.arg_gen.genBytes()
            # self.assertEqual(eval("".join(result_empty)), b"") # Old
            self.assertEqual(ast.literal_eval("".join(result_empty)), b"")

    def test_genLetterDigit(self):
        result = self.arg_gen.genLetterDigit()
        self.assertIsListOfStrings(result, "genLetterDigit")
        self.assertEqual(len(result), 1)
        val_str = result[0]
        self.assertTrue(
            (val_str.startswith('"') and val_str.endswith('"')) or \
            (val_str.startswith("'") and val_str.endswith("'")),
            f"genLetterDigit output '{val_str}' should be a quoted string."
        )
        # Check if it's a valid string literal. Content check is harder without knowing exact charset.
        try:
            evaluated_content = ast.literal_eval(val_str)
            self.assertIsInstance(evaluated_content, str)  # Ensure it evaluated to a Python string
            # For test_genAsciiString, you can keep the content check:
            # self.assertTrue(all(0 <= ord(c) < 256 for c in evaluated_content), ...)
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on '{val_str}' failed: {e}")

    def test_genAsciiString(self):
        result = self.arg_gen.genAsciiString()
        self.assertIsListOfStrings(result, "genAsciiString")
        self.assertEqual(len(result), 1)
        val_str = result[0]
        self.assertTrue(
            (val_str.startswith('"') and val_str.endswith('"')) or \
            (val_str.startswith("'") and val_str.endswith("'")),
            f"genAsciiString output '{val_str}' should be a quoted string."
        )
        try:
            try:
                evaluated_content = ast.literal_eval(val_str)
                self.assertIsInstance(evaluated_content, str)  # Ensure it evaluated to a Python string
            except (ValueError, SyntaxError) as e:
                self.fail(f"ast.literal_eval on '{val_str}' failed: {e}")
            self.assertTrue(all(0 <= ord(c) < 256 for c in evaluated_content), # From ASCII8
                            f"genAsciiString content '{evaluated_content}' not in ASCII8 range.")
        except Exception as e: # Catches eval errors or issues in ord(c)
            self.fail(f"genAsciiString produced an invalid string or content: {val_str}, error: {e}")

    def test_genUnixPath(self):
        result = self.arg_gen.genUnixPath()
        self.assertIsListOfStrings(result, "genUnixPath")
        self.assertEqual(len(result), 1)
        val_str = result[0]
        self.assertTrue(
            (val_str.startswith('"') and val_str.endswith('"')) or \
            (val_str.startswith("'") and val_str.endswith("'")),
            f"genUnixPath output '{val_str}' should be a quoted string."
        )
        # Content check: should ideally resemble a path. For now, just eval.
        try:
            evaluated_content = ast.literal_eval(val_str)
            self.assertIsInstance(evaluated_content, str)  # Ensure it evaluated to a Python string
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on '{val_str}' failed: {e}")

    def test_genFloat(self):
        result = self.arg_gen.genFloat()
        self.assertIsListOfStrings(result, "genFloat")
        self.assertEqual(len(result), 1)
        try:
            val = ast.literal_eval(result[0])  # ast.literal_eval handles floats
            self.assertIsInstance(val, float, f"'{result[0]}' did not evaluate to a float.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval({result[0]}) failed: {e}")

    def test_genErrback(self):
        result = self.arg_gen.genErrback()
        self.assertIsListOfStrings(result, "genErrback")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], self.arg_gen.errback_name,
                         f"genErrback should return the errback_name ('{self.arg_gen.errback_name}').")

    def test_genOpenFile(self):
        # Case 1: Filenames are available
        self._setup_arg_gen() # Ensures self.arg_gen.filenames is populated
        result_with_files = self.arg_gen.genOpenFile()
        self.assertIsListOfStrings(result_with_files, "genOpenFile (with files)")
        self.assertEqual(len(result_with_files), 1)
        expr_str = result_with_files[0]
        self.assertTrue(expr_str.startswith("open(") and expr_str.endswith(")"),
                        "genOpenFile should produce an open(...) expression.")
        # Ensure the filename inside open() is one of the provided ones
        opened_file_arg = expr_str[len("open("):-1]
        expected_filenames_quoted = [f"'{f.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}'"
                                     for f in self.arg_gen.filenames]
        self.assertIn(opened_file_arg, expected_filenames_quoted,
                      f"genOpenFile arg {opened_file_arg} not in expected {expected_filenames_quoted}")

        # Case 2: No filenames available
        self.arg_gen.filenames = []
        result_no_files = self.arg_gen.genOpenFile()
        self.assertIsListOfStrings(result_no_files, "genOpenFile (no files)")
        self.assertEqual(result_no_files[0], "open('NO_FILE_AVAILABLE')")

    def test_genException(self):
        result = self.arg_gen.genException()
        self.assertIsListOfStrings(result, "genException")
        self.assertEqual(len(result), 1)
        expr_str = result[0]
        self.assertTrue(expr_str.startswith("Exception(") and expr_str.endswith(")"),
                        "genException should produce an Exception(...) expression.")
        try:
            # Check it's a valid expression that would create an Exception
            compile(expr_str, '<string>', 'eval')
        except SyntaxError:
            self.fail(f"genException produced a syntactically invalid expression: {expr_str}")

    def test_genBufferObject(self):
        result = self.arg_gen.genBufferObject()
        self.assertIsListOfStrings(result, "genBufferObject")
        self.assertEqual(len(result), 1)
        self.assertIn(result[0], fusil.python.values.BUFFER_OBJECTS,
                      "genBufferObject should pick from BUFFER_OBJECTS.")

    def test_genTricky(self):
        result = self.arg_gen.genTricky()
        self.assertIsListOfStrings(result, "genTricky")
        self.assertEqual(len(result), 1)
        # Just check it's one of the predefined strings, actual behavior is too complex for unit test here
        predefined_tricky = [
            "liar1", "liar2", "lambda *args, **kwargs: 1/0", "int", "type", "object()",
            "[[[[[[[[[[[[[[]]]]]]]]]]]]]]", "MagicMock()", "Evil()", "MagicMock", "Evil", "Liar1", "Liar2",
        ]
        self.assertIn(result[0], predefined_tricky)

    def test_genWeirdClass(self):
        result = self.arg_gen.genWeirdClass()
        self.assertIsListOfStrings(result, "genWeirdClass")
        self.assertEqual(len(result), 1)
        expr_str = result[0]
        # Example: "weird_classes['weird_list']"
        self.assertTrue(expr_str.startswith("weird_classes['") and expr_str.endswith("']"),
                        f"genWeirdClass expression '{expr_str}' has incorrect format.")
        weird_class_key = expr_str[len("weird_classes['"):-len("']")]
        self.assertIn(weird_class_key, fusil.python.tricky_weird.weird_names,
                      f"Key '{weird_class_key}' from genWeirdClass not in tricky_weird.weird_names")

    def test_genWeirdInstance(self):
        result = self.arg_gen.genWeirdInstance()
        self.assertIsListOfStrings(result, "genWeirdInstance")
        self.assertEqual(len(result), 1)
        expr_str = result[0]
        self.assertTrue(expr_str.startswith("weird_instances['") and expr_str.endswith("']"),
                        f"genWeirdInstance expression '{expr_str}' has incorrect format.")
        weird_instance_key = expr_str[len("weird_instances['"):-len("']")]
        self.assertIn(weird_instance_key, fusil.python.tricky_weird.weird_instance_names,
                      f"Key '{weird_instance_key}' from genWeirdInstance not in tricky_weird.weird_instance_names")

    def test_genRawString(self):
        result = self.arg_gen.genRawString()
        self.assertIsListOfStrings(result, "genRawString")
        self.assertEqual(len(result), 1)
        val_str = result[0]
        self.assertTrue(
            (val_str.startswith('r"') and val_str.endswith('"')) or \
            (val_str.startswith("r'") and val_str.endswith("'")),
            f"genRawString output '{val_str}' should be a raw string literal (r'...' or r\"...\")."
        )
        # Check if it's a valid Python string expression (compiles as a raw string)
        try:
            compile(val_str, '<string>', 'eval')
        except SyntaxError:
            self.fail(f"genRawString produced a syntactically invalid raw string literal: {val_str}")

    def test_genSurrogates(self):
        result = self.arg_gen.genSurrogates()
        self.assertIsListOfStrings(result, "genSurrogates")
        self.assertEqual(len(result), 1)
        self.assertIn(result[0], fusil.python.values.SURROGATES,
                      "genSurrogates should pick from fusil.python.values.SURROGATES.")

    def test_genWeirdType(self):
        result = self.arg_gen.genWeirdType()
        self.assertIsListOfStrings(result, "genWeirdType")
        self.assertEqual(len(result), 1)
        expr_str = result[0]
        # Example: "list[weird_classes['weird_someclass']]"
        # We need to check if it matches the pattern: type_name[weird_classes['class_name']]
        match = re.match(r"(\w+)\[weird_classes\['(\w+)'\]\]", expr_str)
        self.assertIsNotNone(match,
                             f"genWeirdType expression '{expr_str}' has incorrect format.")
        if match:
            type_name_generated = match.group(1)
            weird_class_key_generated = match.group(2)
            self.assertIn(type_name_generated, fusil.python.tricky_weird.type_names,
                          f"Type name '{type_name_generated}' from genWeirdType not in tricky_weird.type_names.")
            self.assertIn(weird_class_key_generated, fusil.python.tricky_weird.weird_names,
                          f"Key '{weird_class_key_generated}' from genWeirdType not in tricky_weird.weird_names.")

    def test_genWeirdUnion(self):
        result = self.arg_gen.genWeirdUnion()
        self.assertIsListOfStrings(result, "genWeirdUnion")
        self.assertEqual(len(result), 1)
        expr_str = result[0]
        # Example: "list[weird_classes['weird_class1']] | weird_classes['weird_class2'] | big_union"
        # This regex is a bit more complex due to the optional type_name[] part
        # It tries to match the general structure.
        # type_name[weird_classes['weird_class1']] | weird_classes['weird_class2'] | big_union
        pattern = r"(\w+)\[weird_classes\['(\w+)'\]\]\s*\|\s*weird_classes\['(\w+)'\]\s*\|\s*big_union"
        match = re.match(pattern, expr_str)

        self.assertIsNotNone(match,
                             f"genWeirdUnion expression '{expr_str}' did not match expected format.")

        if match:
            type_name_generated = match.group(1)
            weird_class_key1_generated = match.group(2)
            weird_class_key2_generated = match.group(3)

            self.assertIn(type_name_generated, fusil.python.tricky_weird.type_names,
                          f"Type name '{type_name_generated}' from genWeirdUnion not in tricky_weird.type_names.")
            self.assertIn(weird_class_key1_generated, fusil.python.tricky_weird.weird_names,
                          f"Key 1 '{weird_class_key1_generated}' from genWeirdUnion not in tricky_weird.weird_names.")
            self.assertIn(weird_class_key2_generated, fusil.python.tricky_weird.weird_names,
                          f"Key 2 '{weird_class_key2_generated}' from genWeirdUnion not in tricky_weird.weird_names.")

    # --- Testing create_complex_argument composition ---
    @unittest.skipUnless(USE_NUMPY, "Only works with Numpy")
    def test_create_complex_argument_with_numpy(self):
        self._setup_arg_gen(use_numpy=True, no_numpy_opt=False)
        self.assertTrue(self._check_if_generator_in_tuple('genTrickyNumpy', 'complex_argument_generators'))

        # Probabilistic check that genTrickyNumpy can be chosen
        numpy_seen = False
        for _ in range(100):  # Increase iterations if this is flaky
            # Temporarily make genTrickyNumpy the only choice to ensure it's picked
            with patch.object(self.arg_gen, 'complex_argument_generators', (self.arg_gen.genTrickyNumpy,)):
                result = self.arg_gen.create_complex_argument()
                if "numpy" in "".join(result) or any(
                        name in "".join(result) for name in fusil.python.tricky_weird.tricky_numpy_names):
                    numpy_seen = True
                    break
        self.assertTrue(numpy_seen,
                        "create_complex_argument with numpy enabled did not seem to produce numpy output after forced choice.")
        # Restore original setup for other tests
        self.setUp()

    def test_create_complex_argument_without_numpy_opt(self):
        self._setup_arg_gen(use_numpy=True, no_numpy_opt=True)  # no_numpy option is True
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyNumpy', 'complex_argument_generators'))

    def test_create_complex_argument_without_numpy_init(self):
        self._setup_arg_gen(use_numpy=False, no_numpy_opt=False)  # use_numpy init flag is False
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyNumpy', 'complex_argument_generators'))

    def test_create_complex_argument_with_templates(self):
        if fusil.python.argument_generator.TEMPLATES:
            self._setup_arg_gen(use_templates=True, no_tstrings_opt=False)
            self.assertTrue(self._check_if_generator_in_tuple('genTrickyTemplate', 'complex_argument_generators'))

            # Probabilistic check
            template_seen = False
            # Temporarily make genTrickyTemplate the only choice
            with patch.object(self.arg_gen, 'complex_argument_generators', (self.arg_gen.genTrickyTemplate,)):
                with patch("fusil.python.argument_generator.randint", lambda *args: 1):
                    assert self.arg_gen.complex_argument_generators == (self.arg_gen.genTrickyTemplate,)
                    for _ in range(10):  # Should be quick if it's the only choice
                        result = self.arg_gen.create_complex_argument()
                        if any(tmpl_part in "".join(result) for tmpl_part in ["Template(", "Interpolation("]):
                            template_seen = True
                            break
            self.assertTrue(template_seen,
                            "create_complex_argument with templates enabled did not seem to produce template output after forced choice.")
            self.setUp()  # Restore
        else:
            self.skipTest(
                "Template strings (TEMPLATES) not available for testing genTrickyTemplate with create_complex_argument.")

    def test_create_complex_argument_without_templates_opt(self):
        self._setup_arg_gen(use_templates=True, no_tstrings_opt=True)
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyTemplate', 'complex_argument_generators'))

    def test_create_complex_argument_without_templates_init(self):
        self._setup_arg_gen(use_templates=False, no_tstrings_opt=False)
        self.assertFalse(self._check_if_generator_in_tuple('genTrickyTemplate', 'complex_argument_generators'))


if __name__ == '__main__':
    unittest.main()
