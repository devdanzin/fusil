import unittest
import sys
import os
import ast
from io import StringIO
from unittest.mock import patch, MagicMock
from types import ModuleType, FunctionType, BuiltinFunctionType

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
# It assumes the tests are run from the project root or that this
# file is in a subdirectory like 'tests/'.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..')
sys.path.insert(0, PROJECT_ROOT)

# --- Imports of Code to be Tested ---
from fusil.python.write_python_code import WritePythonCode, PythonFuzzerError
from fusil.config import FusilConfig
# The following are imported to create realistic mocks or for type checks
import fusil.python.tricky_weird

# Conditional import for h5py to match the logic in the tested code
try:
    import h5py
    from fusil.python.h5py.write_h5py_code import WriteH5PyCode

    H5PY_AVAILABLE = True
except ImportError:
    h5py = None  # Mock h5py if not available
    WriteH5PyCode = None
    H5PY_AVAILABLE = False


# --- Mock Objects for Realistic Testing ---
# These mocks simulate a real-world module that WritePythonCode would process.

def mock_global_func(arg1, arg2=True):
    """A mock global function with a default argument."""
    return f"called with {arg1} and {arg2}"


class MockException(Exception):
    """A mock exception class to test exception filtering."""
    pass


class MockClass:
    """A mock class with various types of methods to test discovery."""

    def __init__(self, name="default"):
        self.name = name

    def public_method(self, data):
        """A public method."""
        return data

    def _private_method(self):
        """A private method; should be ignored by default."""
        return "private"

    def __dunder_method__(self):
        """A dunder method; should be ignored by default."""
        return "dunder"


# --- The Test Suite Class ---

class TestWritePythonCode(unittest.TestCase):
    """
    A comprehensive test suite for the WritePythonCode class.

    This suite includes:
    1.  High-level integration tests that validate the final generated script
        for syntactic correctness and overall structure.
    2.  Unit tests for individual methods, checking their logic and how they
        handle different configurations (e.g., options for testing private members).
    3.  "Wiring" tests that use mocks to verify the interactions and call order
        between different methods, which is valuable for safe refactoring.
    """

    def setUp(self):
        """
        Set up a fresh, detailed test fixture before each test method runs.
        This ensures that tests are isolated from one another.
        """
        # 1. Mock the parent 'PythonSource' object and its options.
        # This simulates the environment in which WritePythonCode operates.
        self.mock_python_source = MagicMock()

        # We use a real FusilConfig object to hold realistic options.
        options = FusilConfig(read=False)
        options.functions_number = 5
        options.methods_number = 3
        options.classes_number = 2
        options.objects_number = 2
        options.fuzz_exceptions = False
        options.test_private = False
        options.no_numpy = True  # Disable numpy-dependent features by default for simpler tests
        options.no_tstrings = True  # Disable template strings by default
        self.mock_python_source.options = options
        self.mock_python_source.filenames = ["/tmp/test_file1.txt", "/tmp/test_file2.log"]
        self.mock_python_source.warning = MagicMock()  # Mock the logger to avoid printing during tests

        # 2. Create a realistic mock module for testing member discovery logic.
        self.mock_module = MagicMock(spec=ModuleType)
        self.mock_module.__name__ = "mock_module"

        # Populate the mock module with a variety of attributes
        self.mock_module.test_function = mock_global_func
        self.mock_module.TestClass = MockClass
        self.mock_module.test_object = MockClass("instance1")
        self.mock_module._internal_function = lambda: "should be ignored by default"
        self.mock_module.SomeException = MockException

        # Configure what `dir(mock_module)` will return to the tested code
        # The lambda must accept one argument, which `dir()` passes to it.
        self.mock_module.__dir__ = lambda self: [
            "test_function", "TestClass", "test_object",
            "_internal_function", "SomeException",
            "__name__", "__file__", "__doc__"  # Standard attributes to be filtered out
        ]

        # Ensure our mock class is correctly identified as a type
        # We use a real type for this mock to ensure isinstance checks pass
        setattr(self.mock_module, 'TestClass', type(
            'TestClass',
            (object,),
            {'public_method': lambda self: None, '_private_method': lambda self: None,
             '__dunder_method__': lambda self: None}
        ))

        # 3. Instantiate the WritePythonCode class to be tested.
        self.test_filename = "test_output.py"
        self.writer = WritePythonCode(
            parent_python_source=self.mock_python_source,
            filename=self.test_filename,
            module=self.mock_module,
            module_name="mock_module",
            threads=True,
            _async=True,
            use_h5py=H5PY_AVAILABLE
        )

    # --- Initialization and Setup Tests ---

    def test_initialization_succeeds_with_valid_module(self):
        """Test that WritePythonCode initializes its attributes correctly."""
        self.assertEqual(self.writer.module_name, "mock_module")
        self.assertTrue(self.writer.enable_threads)
        self.assertTrue(self.writer.enable_async)
        if H5PY_AVAILABLE:
            self.assertIsNotNone(self.writer.h5py_writer)
        else:
            self.assertIsNone(self.writer.h5py_writer)
        self.assertIsNotNone(self.writer.arg_generator)
        # Check that the member lists were populated during initialization
        self.assertIn("test_function", self.writer.module_functions)
        self.assertIn("TestClass", self.writer.module_classes)
        self.assertIn("test_object", self.writer.module_objects)

    def test_initialization_fails_with_empty_module(self):
        """Test that initialization raises PythonFuzzerError for a module with no fuzzable members."""
        empty_module = MagicMock(spec=ModuleType)
        empty_module.__name__ = "empty_module"
        # The lambda must accept one argument.
        empty_module.__dir__ = lambda self: ["__name__", "__doc__"]

        with self.assertRaisesRegex(PythonFuzzerError, "has no function, no class, and no object to fuzz"):
            WritePythonCode(
                parent_python_source=self.mock_python_source,
                filename="empty.py",
                module=empty_module,
                module_name="empty_module"
            )

    # --- Member Discovery Logic Tests ---

    def test_get_module_members_correctly_categorizes(self):
        """Logic Test: Ensures _get_module_members correctly categorizes attributes."""
        setattr(self.mock_module, 'SomeException', MockException)
        self.writer.options.fuzz_exceptions = False

        functions, classes, objects = self.writer._get_module_members()

        self.assertEqual(functions, ["test_function"])
        self.assertEqual(classes, ["TestClass"])
        self.assertEqual(objects, ["test_object"])

    def test_get_module_members_respects_test_private_option(self):
        """Logic Test: Checks that private members are included only when options.test_private is True."""
        self.writer.options.test_private = False
        functions, _, _ = self.writer._get_module_members()
        self.assertNotIn("_internal_function", functions, "Private function should be excluded by default.")

        self.writer.options.test_private = True
        functions, _, _ = self.writer._get_module_members()
        self.assertIn("_internal_function", functions, "Private function should be included when test_private is True.")

    def test_get_module_members_respects_fuzz_exceptions_option(self):
        """Logic Test: Checks that exception classes are included only when options.fuzz_exceptions is True."""
        setattr(self.mock_module, 'SomeException', MockException)

        self.writer.options.fuzz_exceptions = False
        _, classes, _ = self.writer._get_module_members()
        self.assertNotIn("SomeException", classes, "Exception should be excluded by default.")

        self.writer.options.fuzz_exceptions = True
        _, classes, _ = self.writer._get_module_members()
        self.assertIn("SomeException", classes, "Exception should be included when fuzz_exceptions is True.")

    def test_get_object_methods_filters_correctly(self):
        """Logic Test: Ensures _get_object_methods filters private/dunder methods correctly."""
        obj = self.mock_module.TestClass()
        self.writer.options.test_private = False
        methods = self.writer._get_object_methods(obj, "TestClass")

        self.assertIn("public_method", methods)
        self.assertNotIn("_private_method", methods, "Private method should be filtered.")
        self.assertNotIn("__dunder_method__", methods, "Dunder method should be filtered.")

    # --- Tests for Private Code-Generation Methods ---

    def test_write_arguments_for_call_lines_formatting(self):
        """Logic Test: Ensures _write_arguments_for_call_lines places commas and newlines correctly."""
        test_cases = {
            "zero_args": (0, [], ""),
            "one_arg": (1, [["'arg1'"]], "'arg1'"),
            "two_args": (2, [["'arg1'"], ["'arg2'"]], "'arg1',\n 'arg2'"),
            "one_multiline_arg": (1, [["'line1'", "'line2'"]], "'line1' 'line2'")
        }
        for name, (num_args, arg_gen_return, expected_output) in test_cases.items():
            with self.subTest(name=name):
                output_stream = StringIO()
                self.writer.output = output_stream

                with patch.object(self.writer.arg_generator, 'create_complex_argument', side_effect=arg_gen_return):
                    self.writer._write_arguments_for_call_lines(num_args, base_indent_level=0)

                actual = " ".join(output_stream.getvalue().split())
                expected = " ".join(expected_output.split())
                self.assertEqual(actual, expected)

    @patch('fusil.python.write_python_code.get_arg_number', return_value=(2, 4))
    @patch('fusil.python.write_python_code.randint')
    def test_generate_and_write_call_argument_logic(self, mock_randint, mock_get_args):
        """Wiring Test: Verifies _generate_and_write_call uses the correct argument count logic."""

        def sample_func_for_test(a, b, c=None, d=None): pass

        self.mock_module.sample_func_for_test = sample_func_for_test

        test_cases = {
            # For the first 3 cases, randint is only called once.
            "zero_args_branch": ([0], 0),
            "one_arg_branch": ([1], 1),
            "max_plus_one_branch": ([2], 5),  # max_arg from mock is 4, so 4+1=5

            # For this case, the first call to randint (for branch selection) returns 5.
            # The second call (for the number of args) returns 3.
            "random_in_range_branch": ([5, 3], 3)
        }

        for name, (randint_side_effects, expected_num_args) in test_cases.items():
            with self.subTest(name=name):
                mock_randint.side_effect = randint_side_effects
                with patch.object(self.writer, '_write_arguments_for_call_lines') as mock_write_args:
                    self.writer.output = StringIO()
                    self.writer._generate_and_write_call(
                        prefix="t1",
                        callable_name="sample_func_for_test",
                        callable_obj=self.mock_module.sample_func_for_test,
                        min_arg_count=1,
                        target_obj_expr="fuzz_target_module",
                        is_method_call=False,
                        generation_depth=0
                    )
                    mock_write_args.assert_called_with(expected_num_args, 1)
    @unittest.skipIf(not H5PY_AVAILABLE, "h5py not installed")
    def test_dispatch_fuzz_on_instance_dispatches_correctly(self):
        """Logic Test: Validates _dispatch_fuzz_on_instance generates code for the correct fuzzer."""
        # This test checks the generated code string to ensure the correct `isinstance`
        # branch is created.

        # Test 1: Generate code for a known h5py type hint ('Dataset')
        self.writer.output = StringIO()
        self.writer._dispatch_fuzz_on_instance("h5_dispatch", "my_dataset_var", "Dataset", 0)
        generated_code_h5py = self.writer.output.getvalue()

        # It should generate the specific 'elif' for h5py.Dataset
        self.assertIn("elif isinstance(my_dataset_var, h5py.Dataset):", generated_code_h5py)
        # It should contain code specific to dataset fuzzing
        self.assertIn("--- Fuzzing Dataset Instance:", generated_code_h5py)
        # It should NOT fall back to the generic fuzzer if we want specialized fuzzing
        # to avoid generic fuzzing. So far, we don't.
        # self.assertNotIn("doing generic calls", generated_code_h5py)

        # Test 2: Generate code for a generic type hint
        self.writer.output = StringIO()
        self.writer._dispatch_fuzz_on_instance("generic_dispatch", "my_generic_var", "SomeGenericClass", 0)
        generated_code_generic = self.writer.output.getvalue()

        # It should NOT contain specific h5py checks
        # self.assertNotIn("elif isinstance(my_generic_var, h5py.Dataset):", generated_code_generic)
        # It should fall back to the generic case
        self.assertIn("doing generic calls", generated_code_generic)

    @patch('fusil.python.write_python_code.class_arg_number', return_value=2)
    def test_fuzz_one_class_orchestration(self, mock_arg_num):
        """Wiring Test: Ensures _fuzz_one_class correctly orchestrates instantiation and fuzzing calls."""
        class_obj = self.mock_module.TestClass

        with patch.object(self.writer, '_dispatch_fuzz_on_instance') as mock_dispatch, \
                patch.object(self.writer, '_fuzz_methods_on_object_or_specific_types') as mock_fuzz_methods:
            self.writer.output = StringIO()
            self.writer._fuzz_one_class(0, "TestClass", class_obj)

            # 1. Check that it tries to figure out constructor arguments
            mock_arg_num.assert_called_once_with("TestClass", class_obj)

            # 2. Check that it calls the deep-diving dispatcher on the instance variable
            mock_dispatch.assert_called_once()
            self.assertEqual(mock_dispatch.call_args.kwargs['target_obj_expr_str'], 'instance_c1_testclass')

            # 3. Check that it also calls the method fuzzer
            mock_fuzz_methods.assert_called_once()
            self.assertEqual(mock_fuzz_methods.call_args.kwargs['target_obj_expr_str'], 'instance_c1_testclass')

    # --- Full Script Generation and Validation Tests ---

    def test_full_script_is_syntactically_valid(self):
        """
        Integration Test: Verifies that the end-to-end script generation process
        produces a single, syntactically correct Python script.
        """
        output_stream = StringIO()

        # Temporarily reduce the number of generated calls to make the test run faster.
        # We only need a small number to verify the overall script structure.
        original_funcs = self.writer.options.functions_number
        original_methods = self.writer.options.methods_number
        original_classes = self.writer.options.classes_number
        original_objects = self.writer.options.objects_number

        try:
            self.writer.options.functions_number = 2
            self.writer.options.methods_number = 1
            self.writer.options.classes_number = 1
            self.writer.options.objects_number = 1

            with patch.object(self.writer, 'createFile'), \
                 patch.object(self.writer, 'close'):
                self.writer.output = output_stream
                self.writer.generate_fuzzing_script()
        finally:
            # Restore original options to avoid affecting other tests
            self.writer.options.functions_number = original_funcs
            self.writer.options.methods_number = original_methods
            self.writer.options.classes_number = original_classes
            self.writer.options.objects_number = original_objects

        full_script = output_stream.getvalue()

        self.assertTrue(full_script, "generate_fuzzing_script produced an empty file.")

        try:
            ast.parse(full_script)
        except SyntaxError as e:
            self.fail(f"The generated script has a syntax error: {e}\n--- SCRIPT ---\n{full_script}")

        # Basic checks to ensure major components are present
        self.assertIn("import mock_module", full_script)
        self.assertIn("def callMethod(", full_script)
        self.assertIn("fuzz_target_module = mock_module", full_script)
        self.assertIn("def main_async_fuzzer_tasks():", full_script)
        # Check that at least one function call was generated
        self.assertIn('callFunc("f1",', full_script)

    # --- Wiring and Call Order Tests ---

    def test_generate_fuzzing_script_call_order(self):
        """
        Wiring Test: Verifies that generate_fuzzing_script calls its internal
        helper methods in the correct sequence.
        """
        with patch.object(self.writer, 'createFile'), \
                patch.object(self.writer, '_write_script_header_and_imports') as mock_header, \
                patch.object(self.writer, '_write_tricky_definitions') as mock_tricky, \
                patch.object(self.writer, '_write_helper_call_functions') as mock_helpers, \
                patch.object(self.writer, '_write_main_fuzzing_logic') as mock_main, \
                patch.object(self.writer, '_write_concurrency_finalization') as mock_concurrency, \
                patch.object(self.writer, 'close'):
            manager = MagicMock()
            manager.attach_mock(mock_header, '_write_script_header_and_imports')
            manager.attach_mock(mock_tricky, '_write_tricky_definitions')
            manager.attach_mock(mock_helpers, '_write_helper_call_functions')
            manager.attach_mock(mock_main, '_write_main_fuzzing_logic')
            manager.attach_mock(mock_concurrency, '_write_concurrency_finalization')

            self.writer.generate_fuzzing_script()

            expected_calls = [
                unittest.mock.call._write_script_header_and_imports(),
                unittest.mock.call._write_tricky_definitions(),
                unittest.mock.call._write_helper_call_functions(),
                unittest.mock.call._write_main_fuzzing_logic(),
                unittest.mock.call._write_concurrency_finalization(),
            ]
            self.assertEqual(manager.mock_calls, expected_calls)

    def test_write_main_fuzzing_logic_call_counts(self):
        """Wiring Test: Checks that the main logic method calls the correct number
        of fuzzing sub-methods based on the options."""
        self.writer.output = StringIO()
        with patch.object(self.writer, '_generate_and_write_call') as mock_gen_call, \
                patch.object(self.writer, '_fuzz_one_class') as mock_fuzz_class, \
                patch.object(self.writer, '_fuzz_one_module_object') as mock_fuzz_obj:
            self.writer._write_main_fuzzing_logic()

            self.assertEqual(mock_gen_call.call_count, self.writer.options.functions_number)
            self.assertEqual(mock_fuzz_class.call_count, self.writer.options.classes_number)
            self.assertEqual(mock_fuzz_obj.call_count, self.writer.options.objects_number)

    def test_dispatch_fuzz_on_instance_stops_at_max_depth(self):
        """Logic Test: Ensure the recursive deep-diving logic terminates correctly."""
        output_stream = StringIO()
        self.writer.output = output_stream

        # Set a low max depth for testing
        original_depth = self.writer.MAX_FUZZ_GENERATION_DEPTH
        self.writer.MAX_FUZZ_GENERATION_DEPTH = 1

        try:
            self.writer._dispatch_fuzz_on_instance(
                current_prefix="prefix_at_max_depth",
                target_obj_expr_str="some_object",
                class_name_hint="SomeClass",
                generation_depth=2  # This depth is > MAX_FUZZ_GENERATION_DEPTH
            )
        finally:
            # Restore original depth to not affect other tests
            self.writer.MAX_FUZZ_GENERATION_DEPTH = original_depth

        generated_code = output_stream.getvalue()
        self.assertIn("Max fuzz code generation depth", generated_code)
        self.assertNotIn("Dispatching Fuzz for", generated_code, "Should not dispatch fuzzing when at max depth.")


if __name__ == '__main__':
    unittest.main()