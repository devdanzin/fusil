import unittest
import re
import sys
import ast # For ast.literal_eval and ast.parse
from random import randint, random, sample, seed, uniform, choice as random_choice
from unittest.mock import MagicMock, patch

import numpy # For numpy placeholders and type checks
import h5py # For h5py type checks and placeholders

import fusil.python.h5py.h5py_argument_generator
import fusil.python.argument_generator
from fusil.config import FusilConfig
import fusil.python.h5py.h5py_tricky_weird # For tricky names list
import fusil.python.values # For INTERESTING values, if parent methods are involved

class TestH5PyArgumentGenerator(unittest.TestCase):

    def setUp(self):
        """
        Set up for each test.
        H5PyArgumentGenerator requires a parent ArgumentGenerator instance.
        """
        # Create a minimal FusilConfig for the parent ArgumentGenerator
        mock_options = FusilConfig(read=False)
        mock_options.no_numpy = False
        mock_options.no_tstrings = False
        # Add any other options ArgumentGenerator or H5PyArgumentGenerator might expect
        default_filenames = ["/tmp/h5py_testfile.h5", "/tmp/another.data"]
        if hasattr(mock_options, 'filenames') and not mock_options.filenames:
             mock_options.filenames = ",".join(default_filenames)
        elif not hasattr(mock_options, 'filenames'):
             mock_options.filenames = ",".join(default_filenames)


        # Create a real parent ArgumentGenerator, as H5PyArgumentGenerator might
        # delegate some calls or use its properties.
        parent_arg_gen = fusil.python.argument_generator.ArgumentGenerator(
            options=mock_options,
            filenames=mock_options.filenames.split(',') if mock_options.filenames else default_filenames,
            use_numpy=True,
            use_templates=True,
            use_h5py=True # This flag on parent is for parent's composition
        )

        self.h5_arg_gen = fusil.python.h5py.h5py_argument_generator.H5PyArgumentGenerator(parent=parent_arg_gen)

        # Globals for eval/ast.parse if needed (similar to TestArgumentGenerator)
        # For now, we'll try to use ast.literal_eval and ast.parse without complex globals
        # and add them only if strictly necessary for a specific test.
        self.test_globals = {
            "numpy": numpy,
            "h5py": h5py,
            "ast": ast,
            "sys": sys, # For things like sys.maxsize if they appear in expressions
            "io": MagicMock(), # For io.BytesIO if gen_h5py_file_name_or_object is tested with eval
            "os": MagicMock(), # For os.close if gen_h5py_file_name_or_object is tested with eval
            "tempfile": MagicMock(), # For tempfile.mkstemp
            "uuid": MagicMock(uuid4=MagicMock(hex="testhex")), # For _h5_unique_name used in some generated exprs
            "_h5_unique_name": lambda base="item": f"{base}_mockeduuid",
             # Placeholder for h5py_tricky_objects.get('name')
            "h5py_tricky_objects": MagicMock(get=MagicMock(return_value="mocked_h5py_object")),
            # Placeholder for runtime helpers if their calls are directly evaluated
            "_fusil_h5_create_dynamic_slice_for_rank": MagicMock(return_value=numpy.s_[:]),
            "_fusil_h5_get_link_target_in_file": MagicMock(return_value="mocked_link_target"),
            # Ensure basic builtins are available if complex expressions are evaluated
            "True": True, "False": False, "None": None,
            "list": list, "tuple": tuple, "dict": dict, "str": str, "int": int, "float": float,
            "choice": random_choice, "randint": randint, "sample": sample, "round": round,
            "uniform": uniform, "random": random, # if generators use these directly in output expr
        }
        self.test_globals["h5py_runtime_objects"] = MagicMock(name="h5py_runtime_objects_mock")
        # Add tricky numpy names as placeholders
        for name in fusil.python.tricky_weird.tricky_numpy_names:
            self.test_globals[name] = f"numpy_placeholder_for_{name}"


    def assertIsListOfStrings(self, result, method_name):
        self.assertIsInstance(result, list, f"{method_name} should return a list.")
        if result:
            for item in result:
                self.assertIsInstance(item, str, f"Items in list from {method_name} should be strings. Got: {type(item)} for item '{item}'")

    def test_genH5PyObject(self):
        result = self.h5_arg_gen.genH5PyObject()
        self.assertIsListOfStrings(result, "genH5PyObject")
        self.assertEqual(len(result), 1)
        expr_str = result[0]
        # Example: "h5py_tricky_objects.get('some_name')"
        self.assertTrue(expr_str.startswith("h5py_tricky_objects.get('") and expr_str.endswith("')"),
                        f"genH5PyObject expression '{expr_str}' has incorrect format.")

        # Extract the key and check if it's in the known tricky names
        key_match = re.search(r"h5py_tricky_objects.get\('([^']+)'\)", expr_str)
        self.assertIsNotNone(key_match, "Could not extract key from genH5PyObject expression")
        if key_match:
            generated_key = key_match.group(1)
            self.assertIn(generated_key, fusil.python.h5py.h5py_tricky_weird.tricky_h5py_names,
                          f"Key '{generated_key}' from genH5PyObject not in h5py_tricky_weird.tricky_h5py_names")

    def test_genH5PyFileMode(self):
        result = self.h5_arg_gen.genH5PyFileMode()
        self.assertIsListOfStrings(result, "genH5PyFileMode")
        self.assertEqual(len(result), 1)
        mode_expr = result[0]
        # Expected modes: 'r', 'r+', 'w', 'w-', 'x', 'a', plus some tricky ones
        # We'll check it's a quoted string.
        self.assertTrue(mode_expr.startswith("'") and mode_expr.endswith("'"),
                        f"genH5PyFileMode output '{mode_expr}' should be a quoted string.")
        try:
            mode_val = ast.literal_eval(mode_expr)
            self.assertIsInstance(mode_val, str, "File mode should be a string.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on file mode '{mode_expr}' failed: {e}")

        # Check for variety
        outputs = {self.h5_arg_gen.genH5PyFileMode()[0] for _ in range(30)}
        self.assertTrue(len(outputs) > 1, "genH5PyFileMode should produce varied outputs.")

    def test_genH5PyFileDriver(self):
        result = self.h5_arg_gen.genH5PyFileDriver()
        self.assertIsListOfStrings(result, "genH5PyFileDriver")
        self.assertEqual(len(result), 1)
        driver_expr = result[0]
        # Expected: "'core'", "'stdio'", ..., "None", or "'invalid_driver'"
        if driver_expr != "None":
            self.assertTrue(driver_expr.startswith("'") and driver_expr.endswith("'"),
                            f"genH5PyFileDriver output '{driver_expr}' should be a quoted string or 'None'.")
        try:
            driver_val = ast.literal_eval(driver_expr)  # Works for 'string' and None
            self.assertIn(driver_val,
                          ["core", "sec2", "stdio", "direct", "split", "fileobj", None, "mydriver", "\x00"],
                          f"Unexpected driver value: {driver_val}")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on driver '{driver_expr}' failed: {e}")

    def test_genH5PySimpleDtype_expr(self):
        result_expr = self.h5_arg_gen.genH5PySimpleDtype_expr()
        self.assertIsInstance(result_expr, str, "genH5PySimpleDtype_expr should return a string.")
        # Examples: "'i4'", "numpy.dtype('f8')"
        is_quoted_literal = result_expr.startswith("'") and result_expr.endswith("'")
        is_numpy_dtype_call = result_expr.startswith("numpy.dtype(") and result_expr.endswith(")")

        self.assertTrue(is_quoted_literal or is_numpy_dtype_call,
                        f"Output '{result_expr}' is not a recognized dtype expression format.")

        # Attempt to eval with globals to see if it resolves to a dtype
        try:
            dt = eval(result_expr, self.test_globals)
            self.assertTrue(isinstance(dt, numpy.dtype) or isinstance(dt, str),  # str if it was just like "'i4'"
                            f"Expression {result_expr} did not evaluate to a numpy.dtype or basic string.")
        except Exception as e:
            self.fail(f"eval({result_expr}) with test_globals failed: {e}")

    def test_genH5PyDatasetShape_expr(self):
        result_expr = self.h5_arg_gen.genH5PyDatasetShape_expr()
        self.assertIsInstance(result_expr, str, "genH5PyDatasetShape_expr should return a string.")
        # Examples: "()", "None", "(10,)", "(5,0,3)", "20"
        try:
            shape_val = eval(result_expr,
                             self.test_globals)  # Use globals in case an expr uses a var, though unlikely here
            self.assertTrue(shape_val is None or isinstance(shape_val, (int, tuple)),
                            f"Shape expression '{result_expr}' evaluated to unexpected type: {type(shape_val)}")
            if isinstance(shape_val, tuple):
                self.assertTrue(all(isinstance(d, int) for d in shape_val),
                                f"Shape tuple '{shape_val}' contains non-integers.")
        except Exception as e:
            self.fail(f"eval({result_expr}) for shape failed: {e}")

    def test_genH5PyDatasetChunks_expr(self):
        # This method takes shape_expr_str as an argument. We need to provide one.
        test_shapes = ["(10, 20)", "(5,)", "None", "()", "(0, 10)"]
        for shape_str in test_shapes:
            with self.subTest(shape_expr_str=shape_str):
                result_expr = self.h5_arg_gen.genH5PyDatasetChunks_expr(shape_str)
                self.assertIsInstance(result_expr, str)
                # Examples: "True", "None", "(5,10)", "False", "(150, 150)"
                try:
                    chunk_val = eval(result_expr, self.test_globals)
                    self.assertTrue(chunk_val is None or isinstance(chunk_val, (bool, tuple)),
                                    f"Chunks expr '{result_expr}' (for shape {shape_str}) -> type {type(chunk_val)}")
                    if isinstance(chunk_val, tuple):
                        self.assertTrue(all(isinstance(d, int) and d > 0 for d in chunk_val),
                                        f"Chunk tuple '{chunk_val}' invalid for shape {shape_str}.")
                except Exception as e:
                    self.fail(f"eval({result_expr}) for chunks (shape {shape_str}) failed: {e}")

    def test_genH5PyLibver(self):
        result = self.h5_arg_gen.genH5PyLibver()
        self.assertIsListOfStrings(result, "genH5PyLibver")
        self.assertEqual(len(result), 1)
        libver_expr = result[0]

        try:
            val = ast.literal_eval(libver_expr)
            self.assertTrue(val is None or isinstance(val, str) or
                            (isinstance(val, tuple) and len(val) == 2 and
                             all(isinstance(x, str) for x in val)),
                            f"genH5PyLibver evaluated to unexpected type: {val}")
            if isinstance(val, str):
                self.assertIn(val, ["earliest", "latest", "v108", "v110", "v112", "v114"])
            elif isinstance(val, tuple):
                for v_item in val:
                    self.assertIn(v_item, ["earliest", "latest", "v108", "v110", "v112", "v114"])
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on libver expression '{libver_expr}' failed: {e}")

        # Check for variety
        outputs = {self.h5_arg_gen.genH5PyLibver()[0] for _ in range(30)}
        self.assertTrue(len(outputs) > 1, "genH5PyLibver should produce varied outputs.")

    def test_genH5PyUserblockSize(self):
        result = self.h5_arg_gen.genH5PyUserblockSize()
        self.assertIsListOfStrings(result, "genH5PyUserblockSize")
        self.assertEqual(len(result), 1)
        ubs_expr = result[0]
        try:
            val = ast.literal_eval(ubs_expr)
            self.assertIsInstance(val, int, f"Userblock size '{ubs_expr}' should evaluate to an int.")
            self.assertTrue(val == 0 or val >= 512 and (val & (val - 1) == 0) or val in [256, 513, 1000],
                            f"Userblock size {val} is not a typical valid value or a known tricky one.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on userblock size expression '{ubs_expr}' failed: {e}")

        outputs = {self.h5_arg_gen.genH5PyUserblockSize()[0] for _ in range(30)}
        self.assertTrue(len(outputs) > 1, "genH5PyUserblockSize should produce varied outputs.")

    def test_genH5PyFillTime_expr(self):
        result_expr = self.h5_arg_gen.genH5PyFillTime_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("'") and result_expr.endswith("'"),
                        f"Fill time expression '{result_expr}' should be a quoted string.")
        try:
            val = ast.literal_eval(result_expr)
            self.assertIn(val, ["ifset", "never", "alloc", "invalid_fill_time_option"])
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on fill time expr '{result_expr}' failed: {e}")

    def test_genH5PyTrackTimes_expr(self):
        result_expr = self.h5_arg_gen.genH5PyTrackTimes_expr()
        self.assertIsInstance(result_expr, str)
        try:
            val = ast.literal_eval(result_expr)  # Handles True, False
            self.assertIn(val, [True, False, "invalid_track_times_val"])
        except (ValueError, SyntaxError) as e:
            # This case for "'invalid_track_times_val'" if ast.literal_eval fails on it directly
            # (it shouldn't, it should eval to the string itself)
            self.assertTrue(result_expr == "'invalid_track_times_val'", f"Unexpected track_times expr: {result_expr}")

    def test_genH5PyFileDriver_actualval(self):
        # This returns an actual value, not an expression string list
        driver = self.h5_arg_gen.genH5PyFileDriver_actualval()
        self.assertIn(driver, ["core", "sec2", "stdio", "direct", "split", "fileobj", None])

        # Check variety
        outputs = {self.h5_arg_gen.genH5PyFileDriver_actualval() for _ in range(30)}
        self.assertTrue(len(outputs) > 1, "genH5PyFileDriver_actualval should produce varied outputs.")

    def test_genH5PyFileMode_actualval(self):
        mode = self.h5_arg_gen.genH5PyFileMode_actualval()
        self.assertIn(mode, ["r", "r+", "w", "w-", "x", "a"])

        outputs = {self.h5_arg_gen.genH5PyFileMode_actualval() for _ in range(30)}
        self.assertTrue(len(outputs) > 1, "genH5PyFileMode_actualval should produce varied outputs.")

    def test_genH5PyDriverKwargs(self):
        drivers_to_test = ["core", "stdio", None, "other_driver"]
        for driver in drivers_to_test:
            with self.subTest(driver=driver):
                result = self.h5_arg_gen.genH5PyDriverKwargs(driver)
                self.assertIsListOfStrings(result, f"genH5PyDriverKwargs for {driver}")
                self.assertEqual(len(result), 1)
                kwargs_str = result[0]

                if driver == "core":
                    if kwargs_str:  # If not empty, parse it
                        kw_parts = kwargs_str.split(", ")
                        for part in kw_parts:
                            self.assertIn("=", part, f"Core kwarg part '{part}' missing '='")
                            key, value = part.split("=", 1)
                            self.assertTrue(key.isidentifier(), f"Key '{key}' is not an identifier.")
                            self.assertIn(key, ["backing_store", "block_size"],
                                          f"Unexpected key '{key}' in core kwargs.")
                else:
                    # For other drivers, the generator currently returns an empty string.
                    self.assertEqual(kwargs_str, "", f"Expected empty kwargs for driver '{driver}', got '{kwargs_str}'")

    def test_genH5PyData_expr(self):
        test_cases = [
            ("()", "'i4'", ["None", "h5py.Empty(dtype='i4')", "0", "1", "True", "False"]),  # Scalar or None
            ("None", "'f8'", ["None", "h5py.Empty(dtype='f8')"]),  # Null dataspace
            ("(10,)", "'u2'",
             ["None", "h5py.Empty(dtype='u2')", "numpy.arange(10, dtype='u2')", "numpy.zeros((10,), dtype='u2')"]),
            # 1D
            ("(3,4)", "'bool'", ["None", "h5py.Empty(dtype='bool')", "numpy.zeros((3,4), dtype='bool')"])  # 2D
        ]
        for shape_expr, dtype_expr, possible_starts in test_cases:
            with self.subTest(shape=shape_expr, dtype=dtype_expr):
                result_expr = self.h5_arg_gen.genH5PyData_expr(shape_expr, dtype_expr)
                self.assertIsInstance(result_expr, str)

                # Check if the result expression starts with one of the expected patterns
                try:
                    val = ast.literal_eval(result_expr)  # Check if it's a simple literal
                    is_simple_literal = isinstance(val, (int, float, bool, str, bytes))
                except (ValueError, SyntaxError):
                    is_simple_literal = False

                self.assertTrue(any(result_expr.startswith(p) for p in possible_starts) or is_simple_literal,
                                f"Unexpected data expr: {result_expr} for shape {shape_expr}, dtype {dtype_expr}")
                # Attempt to compile for syntactic validity
                try:
                    compile(result_expr, '<string>', 'eval')
                except SyntaxError as e:
                    self.fail(f"genH5PyData_expr produced invalid expression '{result_expr}': {e}")

    def test_genH5PyMaxshape_expr(self):
        test_shapes = ["(10,)", "(5, 10, 15)", "()", "None", "20"]
        for shape_expr in test_shapes:
            with self.subTest(shape_expr=shape_expr):
                result_expr = self.h5_arg_gen.genH5PyMaxshape_expr(shape_expr)
                self.assertIsInstance(result_expr, str)
                # Expected: "None" or a tuple string like "(None, 20)" or "(15,)"
                try:
                    val = eval(result_expr, self.test_globals)  # eval can handle None and tuples
                    self.assertTrue(val is None or isinstance(val, tuple),
                                    f"Maxshape '{result_expr}' (for shape {shape_expr}) evaluated to unexpected type: {type(val)}")
                    if isinstance(val, tuple):
                        self.assertTrue(all(x is None or isinstance(x, int) for x in val),
                                        f"Maxshape tuple '{val}' contains non-None/non-int elements.")
                except Exception as e:
                    self.fail(f"eval({result_expr}) for maxshape (shape {shape_expr}) failed: {e}")

    def test_genH5PyFillvalue_expr(self):
        test_dtypes = ["'i4'", "numpy.dtype('f8')", "'bool'", "'S10'"]  # S10 might lead to None or error
        for dtype_expr in test_dtypes:
            with self.subTest(dtype_expr=dtype_expr):
                result_expr = self.h5_arg_gen.genH5PyFillvalue_expr(dtype_expr)
                self.assertIsInstance(result_expr, str)
                # Expected: a number string, 'True', 'False', 'numpy.nan', 'numpy.inf', or 'None'
                try:
                    # We use eval because of numpy.nan etc.
                    val = eval(result_expr, self.test_globals)
                    # Basic check, type compatibility is complex to verify here fully
                    is_basic_literal = isinstance(val, (int, float, bool, str, bytes))
                    is_numpy_special = isinstance(val, float) and (numpy.isnan(val) or numpy.isinf(val))

                    self.assertTrue(val is None or is_basic_literal or is_numpy_special,
                                    f"Fillvalue '{result_expr}' (for dtype {dtype_expr}) "
                                    f"evaluated to unexpected type or value: {val} (type: {type(val)})")
                except Exception as e:
                    # Allow failure if dtype is 'S10' and result is None, as it's a valid outcome
                    if "S10" in dtype_expr and result_expr == "None":
                        pass  # This is fine
                    else:
                        self.fail(f"eval({result_expr}) for fillvalue (dtype {dtype_expr}) failed: {e}")

    def test_genH5PyVlenDtype_expr(self):
        result_expr = self.h5_arg_gen.genH5PyVlenDtype_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("h5py.vlen_dtype("),
                        f"Vlen dtype expr '{result_expr}' should start with 'h5py.vlen_dtype('.")
        self.assertTrue(result_expr.endswith(")"),
                        f"Vlen dtype expr '{result_expr}' should end with ')'.")
        try:
            # Check it can be compiled; actual dtype creation happens in fuzz script
            compile(result_expr, '<string>', 'eval')
            # More thorough: eval and check type (requires h5py in globals)
            dtype_obj = eval(result_expr, self.test_globals)
            self.assertTrue(h5py.check_vlen_dtype(dtype_obj) is not None,  # type: ignore
                            f"Expression {result_expr} did not evaluate to a valid vlen dtype.")
        except Exception as e:
            self.fail(f"eval/compile of vlen_dtype expression '{result_expr}' failed: {e}")

    def test_genH5PyEnumDtype_expr(self):
        result_expr = self.h5_arg_gen.genH5PyEnumDtype_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("h5py.enum_dtype({"),
                        f"Enum dtype expr '{result_expr}' should start with 'h5py.enum_dtype({{'.")
        self.assertTrue("basetype=" in result_expr and result_expr.endswith(")"),
                        f"Enum dtype expr '{result_expr}' missing basetype or closing parenthesis.")
        try:
            compile(result_expr, '<string>', 'eval')
            dtype_obj = eval(result_expr, self.test_globals)
            self.assertTrue(h5py.check_enum_dtype(dtype_obj) is not None,  # type: ignore
                            f"Expression {result_expr} did not evaluate to a valid enum dtype.")
        except Exception as e:
            self.fail(f"eval/compile of enum_dtype expression '{result_expr}' failed: {e}")

    def test_genH5PyCompoundDtype_expr(self):
        result_expr = self.h5_arg_gen.genH5PyCompoundDtype_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("numpy.dtype([") and result_expr.endswith("])"),
                        f"Compound dtype expr '{result_expr}' should be 'numpy.dtype([...])'.")
        try:
            compile(result_expr, '<string>', 'eval')
            dtype_obj = eval(result_expr, self.test_globals)
            self.assertIsInstance(dtype_obj, numpy.dtype,
                                  f"Expression {result_expr} did not evaluate to a numpy.dtype.")
            self.assertTrue(dtype_obj.fields is not None and len(dtype_obj.fields) > 0,
                            f"Generated compound dtype {result_expr} has no fields.")
        except Exception as e:
            self.fail(f"eval/compile of compound_dtype expression '{result_expr}' failed: {e}")

    def test_genH5PyComplexDtype_expr_variety(self):
        # This is a dispatcher, so we check if it can produce various types of dtypes
        # by looking at the string patterns it generates.
        seen_patterns = set()
        for _ in range(100):  # Run multiple times for variety
            expr = self.h5_arg_gen.genH5PyComplexDtype_expr()
            if expr.startswith("h5py.vlen_dtype"):
                seen_patterns.add("vlen")
            elif expr.startswith("h5py.enum_dtype"):
                seen_patterns.add("enum")
            elif expr.startswith("numpy.dtype(["):
                seen_patterns.add("compound")
            elif expr.startswith("h5py.string_dtype"):
                seen_patterns.add("h5string")
            elif expr == "h5py.ref_dtype":
                seen_patterns.add("ref")
            elif expr == "h5py.regionref_dtype":
                seen_patterns.add("regionref")
            elif expr.startswith("'") or "numpy.dtype('" in expr:
                seen_patterns.add("simple")  # Simple or numpy.dtype('simple')
            # Check for array dtype pattern like "'(2,)i2'"
            elif re.match(r"'\(\d+(,\d+)*\)\w\d+'", expr):
                seen_patterns.add("array")

        self.assertTrue(len(seen_patterns) > 3,  # Expect at least a few different types
                        f"genH5PyComplexDtype_expr did not show much variety. Seen: {seen_patterns}")

    def test_genH5PyCompressionKwargs_expr(self):
        result_list = self.h5_arg_gen.genH5PyCompressionKwargs_expr()
        self.assertIsInstance(result_list, list, "Should return a list")
        if not result_list:  # It can be empty
            return

        for kwarg_str in result_list:
            self.assertIsInstance(kwarg_str, str)
            if kwarg_str:  # Skip if it's an empty string (though it shouldn't be if list not empty)
                self.assertIn("=", kwarg_str, f"kwarg string '{kwarg_str}' should contain '='.")
                # Simple validation that it's somewhat like key=value
                parts = kwarg_str.split("=", 1)
                self.assertEqual(len(parts), 2, f"kwarg string '{kwarg_str}' not in key=value format.")
                # Further validation could check for known keys (compression, compression_opts, etc.)
                # and plausible values using ast.literal_eval on parts[1]

    def test_gen_h5py_file_name_or_object(self):
        # Test cases: (driver, mode, is_core_backing), expected_name_pattern, expected_setup_snippets
        test_cases = [
            ("fileobj", "w", False, r"^io\.BytesIO\(\)$", []),
            ("core", "w", False, r"^'mem_core_\w+'$", []),  # Check for unique name pattern
            ("core", "r", True, r"^temp_disk_path_\w+$", ["tempfile.mkstemp", "os.close"]),  # Expects a var name
            ("stdio", "a", False, r"^temp_disk_path_\w+$", ["tempfile.mkstemp", "os.close"])  # Expects a var name
        ]

        for driver, mode, is_core_backing, name_pattern_re, setup_snippets in test_cases:
            with self.subTest(driver=driver, mode=mode, is_core_backing=is_core_backing):
                # Mock os, io, tempfile if they are called directly by the generator
                # The generator is currently written to return strings of code, so direct calls aren't made by it.
                # The mocks in self.test_globals are for if we try to *exec* the setup_lines.

                name_expr, setup_lines = self.h5_arg_gen.gen_h5py_file_name_or_object(
                    driver, mode, is_core_backing
                )

                self.assertIsInstance(name_expr, str)
                self.assertRegex(name_expr, name_pattern_re,
                                 f"Name expression '{name_expr}' did not match pattern '{name_pattern_re}'")

                self.assertIsInstance(setup_lines, list)
                for line in setup_lines:
                    self.assertIsInstance(line, str)
                    try:
                        ast.parse(line)  # Check each setup line for syntactic validity
                    except SyntaxError as e:
                        self.fail(f"Setup line '{line}' is not valid Python: {e}")
                    if setup_snippets:  # Only check if we expect specific snippets for this case
                        found_all_snippets = True
                        for snippet in setup_snippets:
                            if not any(snippet in line_code for line_code in setup_lines):
                                found_all_snippets = False
                                self.fail(
                                    f"Expected snippet '{snippet}' not found in any of the setup lines: {setup_lines}")
                                break
                        # self.assertTrue(found_all_snippets, f"Not all expected snippets found for {driver}, {mode}") # Redundant if fail is used
                    elif not setup_snippets and any(
                            "tempfile.mkstemp" in l or "os.close" in l for l in setup_lines if not l.startswith("#")):
                        # If we didn't expect disk operations but they seem to be there
                        self.fail(f"Unexpected disk operations in setup lines for non-disk case: {setup_lines}")

    def test_genH5PyFsStrategyKwargs(self):
        result = self.h5_arg_gen.genH5PyFsStrategyKwargs()
        self.assertIsListOfStrings(result, "genH5PyFsStrategyKwargs")
        self.assertEqual(len(result), 1)
        kwargs_str = result[0]

        if kwargs_str:  # Can be empty if no strategy options are chosen
            # Basic check that it looks like a comma-separated list of assignments
            parts = kwargs_str.split(", ")
            for part in parts:
                if not part: continue  # Skip if empty string results from split by any chance
                self.assertIn("=", part, f"Expected 'key=value' in fs_strategy kwarg part: '{part}'")
                key, value = part.split("=", 1)
                self.assertTrue(key.isidentifier(), f"Key '{key}' in fs_strategy is not a valid identifier.")
                # Value can be complex, try to compile it as an expression
                try:
                    compile(value, '<string>', 'eval')
                except SyntaxError:
                    self.fail(f"Value '{value}' in fs_strategy kwarg '{key}' is not a valid Python expression.")

            # Check for presence of known strategy keywords if strategy is chosen
            if "fs_strategy=" in kwargs_str:
                self.assertTrue(any(s in kwargs_str for s in ["page", "fsm", "aggregate", "none", "invalid_strat"]))

    def test_genH5PyLocking(self):
        result = self.h5_arg_gen.genH5PyLocking()
        self.assertIsListOfStrings(result, "genH5PyLocking")
        self.assertEqual(len(result), 1)
        locking_expr = result[0]
        try:
            val = ast.literal_eval(locking_expr)  # Handles True, False, None, 'string'
            self.assertIn(val, [True, False, "best-effort", "invalid_lock_opt", None])
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on locking expression '{locking_expr}' failed: {e}")

    def test_genH5PyAsTypeDtype_expr_variety(self):
        # Similar to genH5PyComplexDtype_expr_variety, check for varied dtype expressions
        seen_patterns = set()
        for _ in range(100):  # Run multiple times for variety
            expr = self.h5_arg_gen.genH5PyAsTypeDtype_expr()
            if expr.startswith("h5py.vlen_dtype"):
                seen_patterns.add("vlen")
            elif expr.startswith("h5py.enum_dtype"):
                seen_patterns.add("enum")
            elif expr.startswith("numpy.dtype(["):
                seen_patterns.add("compound")
            elif expr.startswith("h5py.string_dtype"):
                seen_patterns.add("h5string")
            elif expr == "h5py.ref_dtype":
                seen_patterns.add("ref")
            elif expr == "h5py.regionref_dtype":
                seen_patterns.add("regionref")
            elif expr.startswith("'") or "numpy.dtype('" in expr:
                seen_patterns.add("simple")
            elif re.match(r"'\(\d+(,\d+)*\)\w\d+'", expr):
                seen_patterns.add("array")

        self.assertTrue(len(seen_patterns) > 2,  # Expect at least simple and one complex type
                        f"genH5PyAsTypeDtype_expr did not show much variety. Seen: {seen_patterns}")

    def test_genH5PyAsStrEncoding_expr(self):
        result_expr = self.h5_arg_gen.genH5PyAsStrEncoding_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("'") and result_expr.endswith("'"),
                        f"Encoding expression '{result_expr}' should be a quoted string.")
        try:
            val = ast.literal_eval(result_expr)
            self.assertIsInstance(val, str)
            self.assertIn(val, ["ascii", "utf-8", "latin-1", "utf-16", "cp1252", "invalid_encoding_fuzz"])
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on encoding expr '{result_expr}' failed: {e}")

    def test_genH5PyAsStrErrors_expr(self):
        result_expr = self.h5_arg_gen.genH5PyAsStrErrors_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("'") and result_expr.endswith("'"),
                        f"Errors expression '{result_expr}' should be a quoted string.")
        try:
            val = ast.literal_eval(result_expr)
            self.assertIsInstance(val, str)
            self.assertIn(val, ["strict", "ignore", "replace", "xmlcharrefreplace", "bogus_error_handler"])
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on errors expr '{result_expr}' failed: {e}")

    def test_genNumpyValueForComparison_expr(self):
        test_dtypes = ["'i4'", "numpy.dtype('f8')", "'bool'"]
        for dtype_expr in test_dtypes:
            with self.subTest(dtype_expr=dtype_expr):
                result_expr = self.h5_arg_gen.genNumpyValueForComparison_expr(dtype_expr)
                self.assertIsInstance(result_expr, str)
                try:
                    val = eval(result_expr, self.test_globals)
                    # Check if it's a numpy scalar or a small numpy array
                    is_python_or_numpy_scalar = isinstance(val, (int, float, bool, numpy.number, numpy.bool_))
                    is_numpy_array = isinstance(val, numpy.ndarray)

                    self.assertTrue(is_python_or_numpy_scalar or (is_numpy_array and val.ndim <= 1 and val.size <= 2),
                                    f"Numpy value for comparison '{result_expr}' (for dtype {dtype_expr}) "
                                    f"evaluated to unexpected type or shape: {val} (type: {type(val)})")
                    if is_numpy_array:
                        # Attempt to get target dtype for comparison
                        target_dt = eval(dtype_expr, self.test_globals)
                        if isinstance(target_dt, str): target_dt = numpy.dtype(target_dt)
                        self.assertEqual(val.dtype, target_dt, "Array dtype mismatch")

                except Exception as e:
                    self.fail(f"eval({result_expr}) for numpy comparison value (dtype {dtype_expr}) failed: {e}")

    def test_genH5PyAttributeName_expr(self):
        result_expr = self.h5_arg_gen.genH5PyAttributeName_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("'") and result_expr.endswith("'"),
                        f"Attribute name expression '{result_expr}' should be a quoted string.")
        try:
            val = ast.literal_eval(result_expr)
            self.assertIsInstance(val, str)
            self.assertTrue(len(val) > 0, "Attribute name should not be empty.")
            # Check for plausible characters (though h5py might be more permissive)
            self.assertTrue(re.match(r"^[a-zA-Z0-9_😀]+$", val.replace("very_long_attribute_name_", "")),  # type: ignore
                            f"Attribute name '{val}' contains unexpected characters.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on attribute name expr '{result_expr}' failed: {e}")

    def test_genH5PyAttributeValue_expr(self):
        result_expr = self.h5_arg_gen.genH5PyAttributeValue_expr()
        if isinstance(result_expr, list):
            result_expr = result_expr[0]
        self.assertIsInstance(result_expr, str)
        try:
            val = eval(result_expr, self.test_globals)
            is_simple_scalar = isinstance(val, (int, float, str, bytes, bool))
            is_numpy_array = isinstance(val, numpy.ndarray)

            self.assertTrue(is_simple_scalar or is_numpy_array,
                            f"Attribute value '{result_expr}' evaluated to unexpected type: {type(val)}")
            if is_numpy_array:
                self.assertTrue(val.ndim == 1 and val.size >= 1 and val.size <= 5,
                                f"Generated numpy array attribute has unexpected shape/size: {val.shape}")
        except Exception as e:
            self.fail(f"eval({result_expr}) for attribute value failed: {e}")

    def test_genH5PyNewLinkName_expr(self):
        result_expr = self.h5_arg_gen.genH5PyNewLinkName_expr()
        self.assertIsInstance(result_expr, str)
        self.assertTrue(result_expr.startswith("'link_") and result_expr.endswith("'"),
                        f"Link name expression '{result_expr}' has incorrect format.")
        try:
            val = ast.literal_eval(result_expr)
            self.assertIsInstance(val, str)
            self.assertTrue(val.startswith("link_"))
            self.assertEqual(len(val), len("link_") + 6, "Link name should have 6 random hex chars.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on link name expr '{result_expr}' failed: {e}")

    def test_genLargePythonInt_expr(self):
        result_expr = self.h5_arg_gen.genLargePythonInt_expr()
        self.assertIsInstance(result_expr, str)
        try:
            val = ast.literal_eval(result_expr)
            self.assertIsInstance(val, int)
            # Check if it's one of the expected large numbers
            expected_large_values = [
                2 ** 63 - 1, 2 ** 63, 2 ** 63 + 1, 2 ** 64 - 1, 2 ** 64,
                sys.maxsize, sys.maxsize + 1
            ]
            self.assertIn(val, expected_large_values, f"Generated large int {val} not in expected set.")
        except (ValueError, SyntaxError) as e:
            self.fail(f"ast.literal_eval on large int expr '{result_expr}' failed: {e}")

    def test_genH5PyLinkPath_expr(self):
        test_group_paths = ["'/'", "'/foo/bar'", "some_group_var_name"]
        for group_path_expr in test_group_paths:
            with self.subTest(group_path_expr=group_path_expr):
                result_expr = self.h5_arg_gen.genH5PyLinkPath_expr(group_path_expr)
                self.assertIsInstance(result_expr, str)
                # The result can be a simple string literal or a string concatenation
                try:
                    # This eval is to check if the expression is valid and produces a string
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, str,
                                          f"Link path expr '{result_expr}' did not eval to a string (got {type(val)}).")
                except Exception as e:
                    self.fail(f"eval of link path expr '{result_expr}' failed: {e}")

    def test_genH5PyExternalLinkFilename_expr(self):
        test_target_filenames = ["'target_file.h5'", "some_filename_var"]
        for target_expr in test_target_filenames:
            with self.subTest(target_expr=target_expr):
                if target_expr.isidentifier():
                    self.test_globals[target_expr] = "mocked_target_filename.h5"

                result_expr = self.h5_arg_gen.genH5PyExternalLinkFilename_expr(target_expr)
                self.assertIsInstance(result_expr, str)
                try:
                    val = eval(result_expr, self.test_globals)  # Should evaluate to a string
                    self.assertIsInstance(val, str)
                except Exception as e:
                    self.fail(f"eval of external link filename expr '{result_expr}' failed: {e}")

    def test_genH5PyExistingObjectPath_expr(self):
        parent_group_expr = "my_mocked_group"
        self.test_globals[parent_group_expr] = MagicMock(
            name=parent_group_expr)  # Ensure parent_group_expr is in globals

        result_expr = self.h5_arg_gen.genH5PyExistingObjectPath_expr(parent_group_expr)
        self.assertIsInstance(result_expr, str)
        expected_start = f"_fusil_h5_get_link_target_in_file({parent_group_expr}, "
        self.assertTrue(result_expr.startswith(expected_start),
                        f"Expression '{result_expr}' does not start with expected call.")
        self.assertTrue(result_expr.endswith("h5py_tricky_objects, h5py_runtime_objects)"),
                        f"Expression '{result_expr}' does not end as expected.")
        try:
            # Check it's a valid expression that calls our (mocked) helper
            eval(result_expr, self.test_globals)
            self.test_globals['_fusil_h5_get_link_target_in_file'].assert_called_once_with(
                self.test_globals[parent_group_expr],
                self.test_globals['h5py_tricky_objects'],
                self.test_globals['h5py_runtime_objects']
            )
            self.test_globals['_fusil_h5_get_link_target_in_file'].reset_mock()  # Reset for other tests
        except Exception as e:
            self.fail(f"eval of existing object path expr '{result_expr}' failed: {e}")

    def test_genH5PySliceForDirectIO_expr(self):
        ranks_to_test = [0, 1, 2, 5]  # Test scalar, 1D, 2D, and higher rank
        for rank in ranks_to_test:
            with self.subTest(rank=rank):
                result_expr = self.h5_arg_gen.genH5PySliceForDirectIO_expr(rank)
                self.assertIsInstance(result_expr, str)

                is_none = result_expr == "None"
                is_ellipsis_call = result_expr == "numpy.s_[...]"
                is_empty_tuple = result_expr == "()"
                is_numpy_s_slice = result_expr.startswith("numpy.s_[") and result_expr.endswith("]")

                self.assertTrue(is_none or is_ellipsis_call or is_numpy_s_slice or is_empty_tuple,
                                f"Slice expression '{result_expr}' for rank {rank} has unexpected format.")

                if is_numpy_s_slice and not is_ellipsis_call:  # Check content of a regular slice
                    slice_content = result_expr[len("numpy.s_["):-1]
                    if rank == 0:  # Rank 0 should not typically produce complex numpy.s_ slices other than "..."
                        self.assertTrue(not slice_content or slice_content == "...",
                                        f"Rank 0 slice '{result_expr}' should be simple.")
                    elif rank > 0 and slice_content:
                        num_commas = slice_content.count(',')
                        # Number of components should be related to rank, but can vary.
                        # Max number of components for rank N is N-1 commas.
                        self.assertTrue(num_commas <= max(0, rank - 1),
                                        f"Slice '{slice_content}' for rank {rank} has too many components.")
                try:
                    # Syntactic check is good enough here as exact slice object is random
                    compile(result_expr, '<string>', 'eval')
                except SyntaxError as e:
                    self.fail(f"Slice expression '{result_expr}' for rank {rank} is not valid Python: {e}")

    def test_genDataForFancyIndexing_expr(self):
        block_shape_expr = "(5, 2)"
        dtype_expr = "'i4'"
        self.test_globals['some_block_shape_var'] = (5, 2)  # If block_shape_expr was a var name

        result_expr = self.h5_arg_gen.genDataForFancyIndexing_expr(block_shape_expr, dtype_expr)
        self.assertIsInstance(result_expr, str)

        expected_call_structure = f"numpy.random.randint(0, 255, size={block_shape_expr}, dtype={dtype_expr})"
        # This will fail due to the f-string evaluating block_shape_expr as a string rather than its value.
        # We need to check the components.
        self.assertTrue(result_expr.startswith("numpy.random.randint(0, 255, size=("))
        self.assertIn(f"dtype={dtype_expr}", result_expr)
        self.assertTrue(result_expr.endswith(")"))

        # Ensure block_shape_expr is correctly embedded
        # This regex tries to find "size=(<block_shape_expr_content>)"
        match = re.search(r"size=\(\s*" + re.escape(block_shape_expr) + r"\s*\)", result_expr)
        if not match:  # Fallback if block_shape_expr might be a variable name in the expression
            match = re.search(r"size=\(\s*eval\(" + re.escape(block_shape_expr) + r"\)\s*\)", result_expr) or \
                    re.search(r"size=" + re.escape(block_shape_expr) + r"", result_expr)

        self.assertIsNotNone(match,
                             f"Block shape expression '{block_shape_expr}' not correctly embedded in '{result_expr}'")

        try:
            val = eval(result_expr, self.test_globals)
            self.assertIsInstance(val, numpy.ndarray)
            expected_shape = ast.literal_eval(block_shape_expr) if block_shape_expr.startswith(
                "(") else self.test_globals.get(block_shape_expr, (1, 1))
            self.assertEqual(val.shape, expected_shape)
            expected_dtype = numpy.dtype(ast.literal_eval(dtype_expr))
            self.assertEqual(val.dtype, expected_dtype)
        except Exception as e:
            self.fail(f"eval of fancy indexing data expr '{result_expr}' failed: {e}")

    def test_genH5PyLinkPath_expr_2(self):
        # This method's output depends on the input 'current_group_path_expr_str'
        # and internal randomness.
        test_group_paths = ["'/'", "'/foo/bar'", "some_group_var_name"]
        for group_path_expr in test_group_paths:
            with self.subTest(group_path_expr=group_path_expr):
                # Add the mock variable name to globals if it's a variable
                if group_path_expr.isidentifier():
                    self.test_globals[group_path_expr] = "/mocked/group/path"

                result_expr = self.h5_arg_gen.genH5PyLinkPath_expr(group_path_expr)
                self.assertIsInstance(result_expr, str)

                # The result can be a simple string literal or a string concatenation
                # (e.g., current_group_path_expr_str + '/...')
                # We'll check if it evaluates to a string.
                try:
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, str,
                                          f"Link path expr '{result_expr}' did not eval to a string (got {type(val)}).")
                    # Check for plausible path characters or known patterns
                    self.assertTrue(val.startswith("/") or val in ['.', '..'] or \
                                    (not "/" in val and len(val) > 0) or \
                                    (val == "/mocked/group/path" and group_path_expr.isidentifier()),  # from mock
                                    f"Generated path '{val}' doesn't look like a typical link target.")

                except Exception as e:
                    self.fail(
                        f"eval of link path expr '{result_expr}' (for group path '{group_path_expr}') failed: {e}")

                # Clean up mock var from globals if it was added
                if group_path_expr.isidentifier() and group_path_expr in self.test_globals:
                    del self.test_globals[group_path_expr]

    def test_genH5PyExternalLinkFilename_expr_2(self):
        test_target_filenames = ["'target_file.h5'", "some_filename_var"]
        for target_expr in test_target_filenames:
            with self.subTest(target_expr=target_expr):
                if target_expr.isidentifier():
                    self.test_globals[target_expr] = "actual_target_file.h5"

                result_expr = self.h5_arg_gen.genH5PyExternalLinkFilename_expr(target_expr)
                self.assertIsInstance(result_expr, str)
                try:
                    val = eval(result_expr, self.test_globals)  # Should evaluate to a string
                    self.assertIsInstance(val, str)
                    self.assertTrue(val.endswith(".h5") or "dangling" in val,  # Basic check
                                    f"External link filename '{val}' has unexpected format.")
                except Exception as e:
                    self.fail(
                        f"eval of external link filename expr '{result_expr}' (for target '{target_expr}') failed: {e}")

                if target_expr.isidentifier() and target_expr in self.test_globals:
                    del self.test_globals[target_expr]

    def test_genH5PyExistingObjectPath_expr_2(self):
        parent_group_expr = "my_mocked_group_for_existing_obj"
        # Ensure the parent_group_expr (if it's a variable name) is in test_globals
        self.test_globals[parent_group_expr] = MagicMock(name=parent_group_expr)
        # Ensure the mocked helper is in test_globals (it should be from setUp)
        self.assertTrue(callable(self.test_globals['_fusil_h5_get_link_target_in_file']))

        result_expr = self.h5_arg_gen.genH5PyExistingObjectPath_expr(parent_group_expr)
        self.assertIsInstance(result_expr, str)

        # Verify the structure of the call
        expected_start = f"_fusil_h5_get_link_target_in_file({parent_group_expr}, "
        self.assertTrue(result_expr.startswith(expected_start),
                        f"Expression '{result_expr}' does not start with expected call.")
        self.assertTrue(result_expr.endswith("h5py_tricky_objects, h5py_runtime_objects)"),
                        f"Expression '{result_expr}' does not end as expected.")

        try:
            # Evaluate to ensure the mock is called correctly
            eval(result_expr, self.test_globals)
            self.test_globals['_fusil_h5_get_link_target_in_file'].assert_called_once_with(
                self.test_globals[parent_group_expr],
                self.test_globals['h5py_tricky_objects'],
                self.test_globals['h5py_runtime_objects']
            )
        except Exception as e:
            self.fail(f"eval of existing object path expr '{result_expr}' failed: {e}")
        finally:
            # Reset mock and clean up globals for other tests
            self.test_globals['_fusil_h5_get_link_target_in_file'].reset_mock()
            if parent_group_expr in self.test_globals:
                del self.test_globals[parent_group_expr]

    def test_genH5PySliceForDirectIO_expr_2(self):
        ranks_to_test = [0, 1, 2, 5]  # Test scalar, 1D, 2D, and higher rank
        for rank in ranks_to_test:
            with self.subTest(rank=rank):
                result_expr = self.h5_arg_gen.genH5PySliceForDirectIO_expr(rank)
                self.assertIsInstance(result_expr, str)

                is_none = result_expr == "None"
                is_ellipsis_call = result_expr == "numpy.s_[...]"
                # Regex to match numpy.s_[...] with content, or just numpy.s_[]
                is_numpy_s_slice = bool(re.match(r"numpy\.s_\[(.*?)\]", result_expr))
                is_empty_tuple = result_expr == "()"  # Add this check

                self.assertTrue(is_none or is_ellipsis_call or is_numpy_s_slice or is_empty_tuple,
                                f"Slice expression '{result_expr}' for rank {rank} has unexpected format.")

                if is_numpy_s_slice and not is_ellipsis_call:
                    slice_content = result_expr[len("numpy.s_["):-1]
                    if rank == 0:
                        self.assertTrue(not slice_content or slice_content == "...",
                                        f"Rank 0 slice '{result_expr}' should be simple like () or ...")
                    elif rank > 0 and slice_content:  # If there's content for rank > 0
                        num_commas = slice_content.count(',')
                        # A slice for rank N can have at most N-1 commas (N components)
                        self.assertTrue(num_commas <= max(0, rank - 1),
                                        f"Slice '{slice_content}' for rank {rank} appears to have too many components ({num_commas + 1}).")
                try:
                    # Syntactic check is good enough here as exact slice object is random
                    compile(result_expr, '<string>', 'eval')
                except SyntaxError as e:
                    self.fail(f"Slice expression '{result_expr}' for rank {rank} is not valid Python: {e}")

    def test_genDataForFancyIndexing_expr_2(self):
        test_cases = [
            ("(5, 2)", "'i4'"),
            ("(10,)", "'f8'"),
            ("block_shape_var", "dtype_var"),
        ]
        for block_shape_expr, dtype_expr in test_cases:
            with self.subTest(block_shape=block_shape_expr, dtype=dtype_expr):
                # Ensure any variable names used in expressions are in test_globals
                if block_shape_expr.isidentifier():
                    self.test_globals[block_shape_expr] = (3, 3)  # Example shape
                if dtype_expr.isidentifier():
                    self.test_globals[dtype_expr] = numpy.dtype('u1')  # Example dtype

                result_expr = self.h5_arg_gen.genDataForFancyIndexing_expr(block_shape_expr, dtype_expr)
                self.assertIsInstance(result_expr, str)

                is_randint_form = result_expr.startswith("numpy.random.randint")  # Note: no parens here
                is_rand_form = result_expr.startswith("(numpy.random.rand(") and ".astype(" in result_expr

                self.assertTrue(is_randint_form or is_rand_form,
                                f"Result expression '{result_expr}' does not match expected randint or rand patterns.")

                if is_randint_form:
                    self.assertIn(f"size={block_shape_expr}", result_expr)
                    self.assertIn(f"dtype={dtype_expr}", result_expr)
                elif is_rand_form:
                    self.assertIn(f"rand({block_shape_expr})", result_expr)
                    self.assertIn(f".astype({dtype_expr})", result_expr)

                self.assertTrue(result_expr.endswith(")"))

                try:
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, numpy.ndarray)

                    # Determine expected shape and dtype from inputs
                    if block_shape_expr.startswith("("):  # Literal tuple string
                        expected_shape = ast.literal_eval(block_shape_expr)
                    else:  # Variable name
                        expected_shape = self.test_globals.get(block_shape_expr, (1, 1))

                    if dtype_expr.startswith("'"):  # Literal dtype string
                        expected_dtype = numpy.dtype(ast.literal_eval(dtype_expr))
                    else:  # Variable name
                        expected_dtype = self.test_globals.get(dtype_expr, numpy.dtype('i4'))

                    self.assertEqual(val.shape, expected_shape)
                    self.assertEqual(val.dtype, expected_dtype)
                except Exception as e:
                    self.fail(f"eval of fancy indexing data expr '{result_expr}' failed: {e}")
                finally:
                    # Clean up test_globals if vars were added
                    if block_shape_expr.isidentifier() and block_shape_expr in self.test_globals:
                        del self.test_globals[block_shape_expr]
                    if dtype_expr.isidentifier() and dtype_expr in self.test_globals:
                        del self.test_globals[dtype_expr]

    def test_genNumpyArrayForDirectIO_expr(self):
        test_cases = [
            ("(5,5)", "'i4'", True),
            ("(10,)", "'f8'", False),
            ("shape_var", "dtype_var", True),  # Test with variable names
            ("()", "'bool'", True),  # Scalar shape
        ]
        for shape_expr, dtype_expr, allow_non_contig in test_cases:
            with self.subTest(shape=shape_expr, dtype=dtype_expr, non_contig=allow_non_contig):
                # Setup globals if using variable names
                if shape_expr.isidentifier():
                    self.test_globals[shape_expr] = (3, 2)  # Example value
                if dtype_expr.isidentifier():
                    self.test_globals[dtype_expr] = numpy.dtype('u1')  # Example value

                result_expr = self.h5_arg_gen.genNumpyArrayForDirectIO_expr(shape_expr, dtype_expr, allow_non_contig)
                self.assertIsInstance(result_expr, str)

                self.assertTrue(
                    result_expr.startswith("numpy.arange(") or result_expr.startswith("numpy.full("),
                    f"Unexpected start for numpy array expr: {result_expr}"
                )

                try:
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, numpy.ndarray)

                    # Determine expected shape and dtype from inputs for eval
                    if shape_expr.startswith("("):  # Literal tuple string
                        expected_shape = ast.literal_eval(shape_expr)
                    elif shape_expr.isidentifier():
                        expected_shape = self.test_globals.get(shape_expr, (1, 1))
                    else:  # Fallback for single int string like "10"
                        try:
                            expected_shape = (int(shape_expr),)
                        except ValueError:  # Handle case like "()" from scalar
                            if shape_expr == "()":
                                expected_shape = ()
                            else:
                                expected_shape = (1, 1)

                    if dtype_expr.startswith("'") or dtype_expr.startswith('"'):  # Literal dtype string
                        expected_dtype_str = ast.literal_eval(dtype_expr)
                        expected_dtype = numpy.dtype(expected_dtype_str)
                    elif dtype_expr.isidentifier():
                        expected_dtype = self.test_globals.get(dtype_expr, numpy.dtype('i4'))
                    else:  # e.g. numpy.dtype('f8')
                        expected_dtype = eval(dtype_expr, self.test_globals)
                    # numpy.full might use a fill_value_expr that needs eval from fillvalue_gen
                    # For simplicity here, we're checking that eval(result_expr) works and gives an ndarray.
                    # A more precise check for shape/dtype if fill_value is complex:
                    if "numpy.full" in result_expr:
                        self.assertEqual(val.dtype, expected_dtype, f"numpy.full dtype mismatch for {result_expr}")
                        # Shape for full depends on the fill_value if shape_expr was complex.
                        # The generator tries to use shape_expr for shape of full, so:
                        self.assertEqual(val.shape, expected_shape, f"numpy.full shape mismatch for {result_expr}")

                    elif "numpy.arange" in result_expr:  # arange(10).reshape(2,5)
                        self.assertEqual(val.dtype, expected_dtype, f"numpy.arange dtype mismatch for {result_expr}")
                        # Shape check is more complex for arange().reshape combinations
                        # For now, we check that it produced *an* array.
                        if "arange(10" in result_expr and "reshape(2,5)" in result_expr:
                            current_expected_shape = (2, 5)
                        elif shape_expr.startswith("("):
                            current_expected_shape = ast.literal_eval(shape_expr)
                        self.assertEqual(val.shape, current_expected_shape, f"numpy.arange shape mismatch for {result_expr}")

                    if not allow_non_contig:
                        self.assertTrue(val.flags.c_contiguous or val.flags.f_contiguous,
                                        "Array should be contiguous when allow_non_contiguous is False")

                except Exception as e:
                    self.fail(
                        f"eval of numpy array expr '{result_expr}' (shape={shape_expr}, dtype={dtype_expr}) failed: {e}")
                finally:
                    if shape_expr.isidentifier() and shape_expr in self.test_globals:
                        del self.test_globals[shape_expr]
                    if dtype_expr.isidentifier() and dtype_expr in self.test_globals:
                        del self.test_globals[dtype_expr]

    def test_genArrayForArrayDtypeElement_expr(self):
        test_cases = [
            ("(3,)", "'i2'"),
            ("(2,2)", "numpy.dtype('f4')"),
            ("element_shape_var", "base_dtype_var"),
        ]
        for shape_tuple_expr, base_dtype_expr in test_cases:
            with self.subTest(shape_tuple=shape_tuple_expr, base_dtype=base_dtype_expr):
                if shape_tuple_expr.isidentifier():
                    self.test_globals[shape_tuple_expr] = (2, 1)
                if base_dtype_expr.isidentifier():
                    self.test_globals[base_dtype_expr] = numpy.dtype('u1')

                result_expr = self.h5_arg_gen.genArrayForArrayDtypeElement_expr(shape_tuple_expr, base_dtype_expr)
                self.assertIsInstance(result_expr, str)

                self.assertTrue(result_expr.startswith("numpy.arange(int(numpy.prod("))
                self.assertIn(f".astype({base_dtype_expr})", result_expr)
                self.assertIn(f".reshape({shape_tuple_expr})", result_expr)

                try:
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, numpy.ndarray)

                    if shape_tuple_expr.startswith("("):
                        expected_shape = ast.literal_eval(shape_tuple_expr)
                    else:
                        expected_shape = self.test_globals.get(shape_tuple_expr, (1, 1))

                    if base_dtype_expr.startswith("'") or base_dtype_expr.startswith('"'):
                        expected_dtype = numpy.dtype(ast.literal_eval(base_dtype_expr))
                    elif base_dtype_expr.isidentifier():
                        expected_dtype = self.test_globals.get(base_dtype_expr, numpy.dtype('i4'))
                    else:  # e.g. numpy.dtype('f8')
                        expected_dtype = eval(base_dtype_expr, self.test_globals)

                    self.assertEqual(val.shape, expected_shape)
                    self.assertEqual(val.dtype, expected_dtype)
                except Exception as e:
                    self.fail(f"eval of array for array dtype expr '{result_expr}' failed: {e}")
                finally:
                    if shape_tuple_expr.isidentifier() and shape_tuple_expr in self.test_globals:
                        del self.test_globals[shape_tuple_expr]
                    if base_dtype_expr.isidentifier() and base_dtype_expr in self.test_globals:
                        del self.test_globals[base_dtype_expr]

    def test_genH5PySliceForDirectIO_expr_runtime(self):
        rank_var_name = "my_rank_variable"
        self.test_globals[rank_var_name] = 2  # Example rank for eval

        result_expr = self.h5_arg_gen.genH5PySliceForDirectIO_expr_runtime(rank_var_name)
        self.assertIsInstance(result_expr, str)

        is_none = result_expr == "None"
        is_ellipsis_call = result_expr == "numpy.s_[...]"
        is_empty_tuple = result_expr == "()"
        is_helper_call = result_expr == f"_fusil_h5_create_dynamic_slice_for_rank({rank_var_name})"

        self.assertTrue(is_none or is_ellipsis_call or is_helper_call or is_empty_tuple,
                        f"Slice runtime expr '{result_expr}' has unexpected format.")
        try:
            # This eval will call the mocked _fusil_h5_create_dynamic_slice_for_rank
            eval(result_expr, self.test_globals)
            if is_helper_call:
                self.test_globals['_fusil_h5_create_dynamic_slice_for_rank'].assert_called_with(
                    self.test_globals[rank_var_name])
                self.test_globals['_fusil_h5_create_dynamic_slice_for_rank'].reset_mock()
        except Exception as e:
            self.fail(f"eval of slice runtime expr '{result_expr}' failed: {e}")

        if rank_var_name in self.test_globals:
            del self.test_globals[rank_var_name]

    def test_genAdvancedSliceArgument_expr(self):
        # This is a dispatcher, so we test if it can produce different types of slice args
        # We'll mock random.random() to control the branches taken.
        dataset_expr = "dset_var"
        rank_expr = "rank_var"
        fields_keys_expr = "fields_var"

        self.test_globals[dataset_expr] = MagicMock(name="dset_mock")
        self.test_globals[rank_expr] = 2
        self.test_globals[fields_keys_expr] = ["field1", "field2"]

        # Mock the sub-generators to ensure they are called
        with patch.object(self.h5_arg_gen, 'genH5PyFieldNameForSlicing_expr',
                          return_value="'mocked_field_slice'") as mock_field_slice, \
                patch.object(self.h5_arg_gen, 'genH5PyMultiBlockSlice_expr',
                             return_value="h5py.MultiBlockSlice(0,1,1,1)") as mock_mbs_slice, \
                patch.object(self.h5_arg_gen, 'genH5PyRegionReferenceForSlicing_expr',
                             return_value="dset_var.regionref[:]") as mock_regref_slice:
            # Branch 1: Calls _fusil_h5_create_dynamic_slice_for_rank (random() < 0.4)
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.1):
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                self.assertEqual(result, f"_fusil_h5_create_dynamic_slice_for_rank({rank_expr})")
                # Ensure the mock in test_globals is callable for eval
                self.assertTrue(callable(self.test_globals['_fusil_h5_create_dynamic_slice_for_rank']))
                eval(result, self.test_globals)  # Should call the mock

            # Branch 2: Calls genH5PyFieldNameForSlicing_expr (0.4 <= random() < 0.6)
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.5):
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                mock_field_slice.assert_called_once_with(fields_keys_expr)
                self.assertEqual(result, "'mocked_field_slice'")

            # Branch 3: Calls genH5PyMultiBlockSlice_expr (0.6 <= random() < 0.8)
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.7):
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                # The argument to genH5PyMultiBlockSlice_expr is complex, check it was called
                mock_mbs_slice.assert_called_once()
                self.assertEqual(result, "h5py.MultiBlockSlice(0,1,1,1)")

            # Branch 4: Calls genH5PyRegionReferenceForSlicing_expr (random() >= 0.8)
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.9):
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                mock_regref_slice.assert_called_once_with(dataset_expr, rank_expr)
                self.assertEqual(result, "dset_var.regionref[:]")

        # Clean up globals
        del self.test_globals[dataset_expr]
        del self.test_globals[rank_expr]
        del self.test_globals[fields_keys_expr]

    def test_genNumpyArrayForDirectIO_expr_2(self):
        # This method was already partially tested in a previous response.
        # Here's a more focused version or an enhancement.
        test_cases = [
            ("(5,5)", "'i4'", True, "C_or_F_order_ok"),
            ("(10,)", "'f8'", False, "Contiguous_expected"),
            ("shape_var", "dtype_var", True, "Var_C_or_F_order_ok"),
            ("()", "'bool'", True, "Scalar_ok"),  # Scalar shape
        ]
        for shape_expr, dtype_expr, allow_non_contig, test_name_suffix in test_cases:
            with self.subTest(shape=shape_expr, dtype=dtype_expr, non_contig=allow_non_contig,
                              name_suffix=test_name_suffix):
                # Setup globals if using variable names
                if shape_expr.isidentifier():
                    self.test_globals[shape_expr] = (3, 2)  # Example value
                if dtype_expr.isidentifier():
                    self.test_globals[dtype_expr] = numpy.dtype('u1')  # Example value

                result_expr = self.h5_arg_gen.genNumpyArrayForDirectIO_expr(shape_expr, dtype_expr, allow_non_contig)
                self.assertIsInstance(result_expr, str)

                self.assertTrue(
                    result_expr.startswith("numpy.arange(") or result_expr.startswith("numpy.full("),
                    f"Unexpected start for numpy array expr: {result_expr}"
                )

                try:
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, numpy.ndarray)

                    current_expected_shape = None  # Initialize
                    if "arange(10" in result_expr and "reshape(2,5)" in result_expr:  # Generator's specific case
                        current_expected_shape = (2, 5)
                    elif shape_expr.startswith("("):  # Literal tuple string for shape
                        current_expected_shape = ast.literal_eval(shape_expr)
                    elif shape_expr.isidentifier():  # Variable name for shape
                        current_expected_shape = self.test_globals.get(shape_expr, (1, 1))
                    else:  # Fallback for single int string like "10" or "()"
                        try:
                            current_expected_shape = (int(shape_expr),)
                        except ValueError:
                            if shape_expr == "()":
                                current_expected_shape = ()
                            else:
                                current_expected_shape = (1, 1)  # Default fallback

                    self.assertEqual(val.shape, current_expected_shape, f"Shape mismatch for {result_expr}")

                    if dtype_expr.startswith("'") or dtype_expr.startswith('"'):  # Literal dtype string
                        expected_dtype_str_val = ast.literal_eval(dtype_expr)
                        expected_dtype = numpy.dtype(expected_dtype_str_val)
                    elif dtype_expr.isidentifier():  # Variable name for dtype
                        expected_dtype = self.test_globals.get(dtype_expr, numpy.dtype('i4'))
                    else:  # Direct numpy.dtype call e.g. numpy.dtype('f8')
                        expected_dtype = eval(dtype_expr, self.test_globals)

                    self.assertEqual(val.dtype, expected_dtype, f"Dtype mismatch for {result_expr}")

                    if not allow_non_contig:
                        # An array can be C and F contiguous if it's 0D, 1D, or has a dimension of size 0 or 1
                        if val.ndim > 1 and all(s > 1 for s in val.shape):
                            self.assertTrue(val.flags.c_contiguous or val.flags.f_contiguous,  # Original was too strict
                                            "Array should be C or F contiguous if non-contig not allowed and non-trivial.")
                        else:  # For 0D/1D, or trivial higher D, it's usually both.
                            self.assertTrue(val.flags.c_contiguous and val.flags.f_contiguous)


                except Exception as e:
                    self.fail(
                        f"eval of numpy array expr '{result_expr}' (shape={shape_expr}, dtype={dtype_expr}) failed: {e}")
                finally:
                    if shape_expr.isidentifier() and shape_expr in self.test_globals:
                        del self.test_globals[shape_expr]
                    if dtype_expr.isidentifier() and dtype_expr in self.test_globals:
                        del self.test_globals[dtype_expr]

    def test_genArrayForArrayDtypeElement_expr_2(self):
        # This method was already partially tested. Let's ensure it's robust.
        test_cases = [
            ("(3,)", "'i2'"),
            ("(2,2)", "numpy.dtype('f4')"),
            ("element_shape_var", "base_dtype_var"),
        ]
        for shape_tuple_expr, base_dtype_expr in test_cases:
            with self.subTest(shape_tuple=shape_tuple_expr, base_dtype=base_dtype_expr):
                if shape_tuple_expr.isidentifier():
                    self.test_globals[shape_tuple_expr] = (2, 1)
                if base_dtype_expr.isidentifier():
                    self.test_globals[base_dtype_expr] = numpy.dtype('u1')

                result_expr = self.h5_arg_gen.genArrayForArrayDtypeElement_expr(shape_tuple_expr, base_dtype_expr)
                self.assertIsInstance(result_expr, str)

                self.assertTrue(result_expr.startswith("numpy.arange(int(numpy.prod("),
                                f"Expression structure issue: {result_expr}")
                self.assertIn(f".astype({base_dtype_expr})", result_expr)
                self.assertIn(f".reshape({shape_tuple_expr})", result_expr)

                try:
                    val = eval(result_expr, self.test_globals)
                    self.assertIsInstance(val, numpy.ndarray)

                    if shape_tuple_expr.startswith("("):
                        expected_shape = ast.literal_eval(shape_tuple_expr)
                    else:
                        expected_shape = self.test_globals.get(shape_tuple_expr, (1, 1))

                    if base_dtype_expr.startswith("'") or base_dtype_expr.startswith('"'):
                        expected_dtype = numpy.dtype(ast.literal_eval(base_dtype_expr))
                    elif base_dtype_expr.isidentifier():
                        expected_dtype = self.test_globals.get(base_dtype_expr, numpy.dtype('i4'))
                    else:
                        expected_dtype = eval(base_dtype_expr, self.test_globals)

                    self.assertEqual(val.shape, expected_shape)
                    self.assertEqual(val.dtype, expected_dtype)
                except Exception as e:
                    self.fail(f"eval of array for array dtype expr '{result_expr}' failed: {e}")
                finally:
                    if shape_tuple_expr.isidentifier() and shape_tuple_expr in self.test_globals:
                        del self.test_globals[shape_tuple_expr]
                    if base_dtype_expr.isidentifier() and base_dtype_expr in self.test_globals:
                        del self.test_globals[base_dtype_expr]

    def test_genH5PySliceForDirectIO_expr_runtime_2(self):
        # This was also previously tested. This ensures it's robust.
        rank_var_name = "my_rank_variable_for_runtime_slice"
        self.test_globals[rank_var_name] = 3  # Example rank for eval

        # Ensure the mock is set up in test_globals (should be from setUp)
        self.assertTrue(callable(self.test_globals['_fusil_h5_create_dynamic_slice_for_rank']))

        result_expr = self.h5_arg_gen.genH5PySliceForDirectIO_expr_runtime(rank_var_name)
        self.assertIsInstance(result_expr, str)

        is_none = result_expr == "None"
        is_ellipsis_call = result_expr == "numpy.s_[...]"
        is_empty_tuple = result_expr == "()"
        is_helper_call = result_expr == f"_fusil_h5_create_dynamic_slice_for_rank({rank_var_name})"

        self.assertTrue(is_none or is_ellipsis_call or is_helper_call or is_empty_tuple,
                        f"Slice runtime expr '{result_expr}' has unexpected format.")
        try:
            eval(result_expr, self.test_globals)  # This will call the mocked helper
            if is_helper_call:
                self.test_globals['_fusil_h5_create_dynamic_slice_for_rank'].assert_called_with(
                    self.test_globals[rank_var_name])
        except Exception as e:
            self.fail(f"eval of slice runtime expr '{result_expr}' failed: {e}")
        finally:
            self.test_globals['_fusil_h5_create_dynamic_slice_for_rank'].reset_mock()
            if rank_var_name in self.test_globals:
                del self.test_globals[rank_var_name]

    def test_genAdvancedSliceArgument_expr_2(self):
        # This was also previously tested. This ensures it's robust.
        dataset_expr = "dset_adv_slice_var"
        rank_expr = "rank_adv_slice_var"
        fields_keys_expr = "fields_adv_slice_var"

        self.test_globals[dataset_expr] = MagicMock(name="dset_mock_adv_slice")
        self.test_globals[rank_expr] = 2
        self.test_globals[fields_keys_expr] = "['field1', 'field2']"  # String that evals to list

        # Ensure helper is in test_globals
        self.assertTrue(callable(self.test_globals['_fusil_h5_create_dynamic_slice_for_rank']))

        # Mock the sub-generators that genAdvancedSliceArgument_expr might call
        with patch.object(self.h5_arg_gen, 'genH5PyFieldNameForSlicing_expr',
                          return_value="'mocked_field_slice_adv'") as mock_field_slice, \
                patch.object(self.h5_arg_gen, 'genH5PyMultiBlockSlice_expr',
                             return_value="'mocked_mbs_slice_adv'") as mock_mbs_slice, \
                patch.object(self.h5_arg_gen, 'genH5PyRegionReferenceForSlicing_expr',
                             return_value="'mocked_regref_slice_adv'") as mock_regref_slice:

            # Test branch 1: Calls _fusil_h5_create_dynamic_slice_for_rank
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.1):  # choice_val < 0.4
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                self.assertEqual(result, f"_fusil_h5_create_dynamic_slice_for_rank({rank_expr})")
                eval(result, self.test_globals)  # Calls the mock from test_globals
                self.test_globals['_fusil_h5_create_dynamic_slice_for_rank'].assert_called_with(
                    self.test_globals[rank_expr])
                self.test_globals['_fusil_h5_create_dynamic_slice_for_rank'].reset_mock()

            # Test branch 2: Calls genH5PyFieldNameForSlicing_expr
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.5):  # 0.4 <= choice_val < 0.6
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                mock_field_slice.assert_called_once_with(fields_keys_expr)
                self.assertEqual(result, "'mocked_field_slice_adv'")
                mock_field_slice.reset_mock()

            # Test branch 3: Calls genH5PyMultiBlockSlice_expr
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.7):  # 0.6 <= choice_val < 0.8
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                mock_mbs_slice.assert_called_once()  # Argument is complex, just check call
                self.assertEqual(result, "'mocked_mbs_slice_adv'")
                mock_mbs_slice.reset_mock()

            # Test branch 4: Calls genH5PyRegionReferenceForSlicing_expr
            with patch('fusil.python.h5py.h5py_argument_generator.random', return_value=0.9):  # choice_val >= 0.8
                result = self.h5_arg_gen.genAdvancedSliceArgument_expr(dataset_expr, rank_expr, fields_keys_expr)
                mock_regref_slice.assert_called_once_with(dataset_expr, rank_expr)
                self.assertEqual(result, "'mocked_regref_slice_adv'")
                mock_regref_slice.reset_mock()

        # Clean up globals
        if dataset_expr in self.test_globals: del self.test_globals[dataset_expr]
        if rank_expr in self.test_globals: del self.test_globals[rank_expr]
        if fields_keys_expr in self.test_globals: del self.test_globals[fields_keys_expr]


if __name__ == '__main__':
    unittest.main()