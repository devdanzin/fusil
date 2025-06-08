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
# The following are imported to create realistic mocks
import fusil.python.tricky_weird
import fusil.python.h5py.h5py_tricky_weird


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
            use_h5py=False  # Keep h5py-specific logic disabled for these tests
        )

    # --- Initialization and Setup Tests ---

    def test_initialization_succeeds_with_valid_module(self):
        """Test that WritePythonCode initializes its attributes correctly."""
        self.assertEqual(self.writer.module_name, "mock_module")
        self.assertTrue(self.writer.enable_threads)
        self.assertTrue(self.writer.enable_async)
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
        self.assertEqual(classes, ["TestClass"])  # This will fail until the source bug is fixed
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

    # --- Full Script Generation and Validation Tests ---

    def test_full_script_is_syntactically_valid(self):
        """
        Integration Test: Verifies that the end-to-end script generation process
        produces a single, syntactically correct Python script.
        """
        output_stream = StringIO()

        # FIX: Patch createFile to prevent real file I/O and instead ensure
        # all subsequent write() calls go to our in-memory StringIO stream.
        with patch.object(self.writer, 'createFile') as mock_create_file:
            with patch.object(self.writer, 'close'):
                self.writer.output = output_stream
                self.writer.generate_fuzzing_script()

        full_script = output_stream.getvalue()

        self.assertTrue(full_script, "generate_fuzzing_script produced an empty file.")

        try:
            ast.parse(full_script)
        except SyntaxError as e:
            self.fail(f"The generated script has a syntax error: {e}\n--- SCRIPT ---\n{full_script}")

        self.assertIn("import mock_module", full_script)
        self.assertIn("def callMethod(", full_script)
        self.assertIn("fuzz_target_module = mock_module", full_script)
        self.assertIn("def main_async_fuzzer_tasks():", full_script)
        self.assertIn('callFunc("f1", "test_function",', full_script)

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
            # We don't attach createFile because we don't care about its call args here, just the order of others.
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
        # FIX: Manually set the output stream, as this unit test doesn't
        # call the main generate_fuzzing_script method.
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

        self.writer.MAX_FUZZ_GENERATION_DEPTH = 1

        self.writer._dispatch_fuzz_on_instance(
            current_prefix="prefix_at_max_depth",
            target_obj_expr_str="some_object",
            class_name_hint="SomeClass",
            generation_depth=2
        )

        generated_code = output_stream.getvalue()
        self.assertIn("Max fuzz code generation depth", generated_code)
        self.assertNotIn("Dispatching Fuzz for", generated_code, "Should not dispatch fuzzing when at max depth.")


if __name__ == '__main__':
    unittest.main()
