import ast
import os
import sys
import unittest
from io import StringIO
from types import ModuleType
from unittest.mock import MagicMock, patch

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, "..", "..")
sys.path.insert(0, PROJECT_ROOT)

# --- Imports of Code to be Tested ---
from python._test_options import make_test_options

from fusil.python.write_python_code import WritePythonCode


# --- Mock Objects for Realistic Testing ---
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


# --- The Test Suite Class ---


class TestWritePythonCodePrivateMethods(unittest.TestCase):
    """
    A dedicated test suite for the private methods of the WritePythonCode class.

    This suite uses mocking to isolate the logic of each private method,
    ensuring that its internal operations (dispatching, filtering, code
    generation) are correct. This is crucial for safe refactoring and
    maintaining code quality.
    """

    def setUp(self):
        """Set up a fresh test fixture before each test method runs."""
        self.mock_python_source = MagicMock()
        # All real fuzzer-option defaults (harvested from the option parser) + overrides.
        options = make_test_options(
            functions_number=5,
            methods_number=3,
            classes_number=2,
            objects_number=2,
            fuzz_exceptions=False,
            test_private=False,
            no_numpy=True,
            no_tstrings=True,
        )
        self.mock_python_source.options = options
        self.mock_python_source.filenames = ["/tmp/test_file.txt"]
        self.mock_python_source.warning = MagicMock()

        self.mock_module = MagicMock(spec=ModuleType)
        self.mock_module.__name__ = "mock_module"
        self.mock_module.test_function = mock_global_func
        self.mock_module.TestClass = MockClass

        self.writer = WritePythonCode(
            parent_python_source=self.mock_python_source,
            filename="test_output.py",
            module=self.mock_module,
            module_name="mock_module",
            threads=True,
            _async=True,
        )
        self.writer.output = StringIO()

    # --- Tests for Code-Writing Helper Methods ---

    def test_private_code_writers_are_syntactically_valid(self):
        """Logic Test: Ensures simple code-writing methods produce valid Python."""
        test_methods = [
            self.writer._write_script_header_and_imports,
            self.writer._write_tricky_definitions,
            self.writer._write_helper_call_functions,
            self.writer._write_concurrency_finalization,
        ]
        for method in test_methods:
            with self.subTest(method=method.__name__):
                self.writer.output = StringIO()
                method()
                generated_code = self.writer.output.getvalue()
                self.assertTrue(generated_code, f"{method.__name__} produced no output.")
                try:
                    ast.parse(generated_code)
                except SyntaxError as e:
                    self.fail(
                        f"{method.__name__} produced a syntax error: {e}\n--- CODE ---\n{generated_code}"
                    )

    def test_write_arguments_for_call_lines_formatting(self):
        """Logic Test: Ensures _write_arguments_for_call_lines places commas and newlines correctly."""
        # _write_arguments_for_call_lines appends a trailing comma after every argument
        # (valid Python in a multi-line call; long-standing behavior).
        test_cases = {
            "zero_args": (0, [], ""),
            "one_arg": (1, [["'arg1'"]], "'arg1',"),
            "two_args": (2, [["'arg1'"], ["'arg2'"]], "'arg1',\n 'arg2',"),
            "one_multiline_arg": (1, [["'line1'", "'line2'"]], "'line1' 'line2',"),
        }
        for name, (num_args, arg_gen_return, expected_output) in test_cases.items():
            with self.subTest(name=name):
                self.writer.output = StringIO()
                with patch.object(
                    self.writer.arg_generator, "create_complex_argument", side_effect=arg_gen_return
                ):
                    self.writer._write_arguments_for_call_lines(num_args, base_indent_level=0)

                actual = " ".join(self.writer.output.getvalue().split())
                expected = " ".join(expected_output.split())
                self.assertEqual(actual, expected)

    # --- Tests for Fuzzing Orchestration Methods ---

    @patch("fusil.python.write_python_code.get_arg_number", return_value=(2, 4))
    @patch("fusil.python.write_python_code.randint")
    def test_generate_and_write_call_argument_logic(self, mock_randint, mock_get_args):
        """Wiring Test: Verifies _generate_and_write_call uses the correct argument count logic."""

        def sample_func_for_test(a, b, c=None, d=None):
            pass

        self.mock_module.sample_func_for_test = sample_func_for_test

        test_cases = {
            "zero_args_branch": ([0], 0),
            "one_arg_branch": ([1], 1),
            "max_plus_one_branch": ([2], 5),
            "random_in_range_branch": ([5, 3], 3),
        }

        for name, (randint_side_effects, expected_num_args) in test_cases.items():
            with self.subTest(name=name):
                mock_randint.side_effect = randint_side_effects
                with patch.object(
                    self.writer, "_write_arguments_for_call_lines"
                ) as mock_write_args:
                    self.writer.output = StringIO()
                    self.writer._generate_and_write_call(
                        prefix="t1",
                        callable_name="sample_func_for_test",
                        callable_obj=self.mock_module.sample_func_for_test,
                        min_arg_count=1,
                        target_obj_expr="fuzz_target_module",
                        is_method_call=False,
                        generation_depth=0,
                    )
                    mock_write_args.assert_called_with(expected_num_args, 1)

    @patch("fusil.python.write_python_code.class_arg_number", return_value=2)
    def test_fuzz_one_class_orchestration(self, mock_arg_num):
        """Wiring Test: Ensures _fuzz_one_class correctly orchestrates instantiation and fuzzing calls."""
        class_obj = self.mock_module.TestClass

        with (
            patch.object(self.writer, "_dispatch_fuzz_on_instance") as mock_dispatch,
            patch.object(
                self.writer, "_fuzz_methods_on_object_or_specific_types"
            ) as mock_fuzz_methods,
        ):
            self.writer.output = StringIO()
            self.writer._fuzz_one_class(0, "TestClass", class_obj)

            mock_arg_num.assert_called_once_with("TestClass", class_obj)

            mock_dispatch.assert_called_once()
            self.assertEqual(
                mock_dispatch.call_args.kwargs["target_obj_expr_str"], "instance_c1_testclass"
            )

            mock_fuzz_methods.assert_called_once()
            self.assertEqual(
                mock_fuzz_methods.call_args.kwargs["target_obj_expr_str"], "instance_c1_testclass"
            )

    @patch("fusil.python.write_python_code.class_arg_number", return_value=1)
    def test_fuzz_one_class_uses_plugin_class_handler(self, mock_arg_num):
        """A plugin class handler that claims a class suppresses the generic callFunc init."""
        from fusil.plugin_manager import PluginManager

        pm = PluginManager()
        seen = []

        def handler(writer, class_name, class_type, instance_var, prefix):
            writer.write(0, f"{instance_var} = make_special()  # claimed by plugin")
            seen.append((class_name, instance_var, prefix))
            return True

        pm.add_class_handler(handler)
        self.writer.plugin_manager = pm
        self.writer.output = StringIO()
        with (
            patch.object(self.writer, "_dispatch_fuzz_on_instance"),
            patch.object(self.writer, "_fuzz_methods_on_object_or_specific_types"),
        ):
            self.writer._fuzz_one_class(0, "TestClass", self.mock_module.TestClass)
        out = self.writer.output.getvalue()
        self.assertEqual(seen, [("TestClass", "instance_c1_testclass", "c1")])
        self.assertIn("make_special()  # claimed by plugin", out)
        # generic callFunc instantiation is suppressed
        self.assertNotIn("callFunc('c1_init', 'TestClass'", out)

    @patch("fusil.python.write_python_code.class_arg_number", return_value=1)
    def test_fuzz_one_class_falls_through_when_handler_declines(self, mock_arg_num):
        """A class handler returning False leaves the generic callFunc instantiation in place."""
        from fusil.plugin_manager import PluginManager

        pm = PluginManager()
        pm.add_class_handler(lambda *a: False)
        self.writer.plugin_manager = pm
        self.writer.output = StringIO()
        with (
            patch.object(self.writer, "_dispatch_fuzz_on_instance"),
            patch.object(self.writer, "_fuzz_methods_on_object_or_specific_types"),
        ):
            self.writer._fuzz_one_class(0, "TestClass", self.mock_module.TestClass)
        self.assertIn("callFunc('c1_init', 'TestClass'", self.writer.output.getvalue())

    def test_get_object_methods_respects_plugin_blacklist_and_whitelist(self):
        """Plugin method blacklist drops names; whitelist keeps normally-skipped ones (__del__)."""
        from fusil.plugin_manager import PluginManager

        class Obj:
            def keep_me(self):
                pass

            def drop_me(self):
                pass

            def __del__(self):
                pass

        # Baseline (no plugin): public methods discovered, __del__ skipped as private.
        self.writer.plugin_manager = None
        base = self.writer._get_object_methods(Obj(), "Obj")
        self.assertIn("keep_me", base)
        self.assertIn("drop_me", base)
        self.assertNotIn("__del__", base)

        # With a plugin blacklist + whitelist.
        pm = PluginManager()
        pm.add_blacklist_entry("method", "drop_me")
        pm.add_whitelist_entry("method", "__del__")
        self.writer.plugin_manager = pm
        got = self.writer._get_object_methods(Obj(), "Obj")
        self.assertIn("keep_me", got)
        self.assertNotIn("drop_me", got)  # blacklisted
        self.assertIn("__del__", got)  # whitelisted through the private-name skip

    def test_fuzz_one_module_object_orchestration(self):
        """Wiring Test: Ensures _fuzz_one_module_object calls the method fuzzer correctly."""
        with patch.object(
            self.writer, "_fuzz_methods_on_object_or_specific_types"
        ) as mock_fuzz_methods:
            self.writer._fuzz_one_module_object(0, "test_object", MockClass("instance_runtime"))

            mock_fuzz_methods.assert_called_once()
            kwargs = mock_fuzz_methods.call_args.kwargs
            self.assertEqual(kwargs["target_obj_expr_str"], "fuzz_target_module.test_object")
            self.assertEqual(kwargs["target_obj_class_name"], "MockClass")
            self.assertEqual(kwargs["num_method_calls_to_make"], 3)

    @patch("fusil.python.write_python_code.WritePythonCode._get_object_methods")
    @patch("fusil.python.write_python_code.WritePythonCode._generate_and_write_call")
    def test_fuzz_methods_on_object(self, mock_generate_call, mock_get_methods):
        """Wiring Test: Validates that methods are discovered and fuzzed in a loop."""
        # Return a mock method dictionary
        mock_get_methods.return_value = {"public_method": self.mock_module.TestClass.public_method}

        self.writer._fuzz_methods_on_object_or_specific_types(
            current_prefix="c1m",
            target_obj_expr_str="instance_var",
            target_obj_class_name="TestClass",
            target_obj_actual_type_obj=self.mock_module.TestClass,
            num_method_calls_to_make=self.writer.options.methods_number,
        )

        # Check that methods were discovered on the object
        mock_get_methods.assert_called_once_with(self.mock_module.TestClass, "TestClass")

        # Check that a call was generated for each iteration in the options
        self.assertEqual(mock_generate_call.call_count, self.writer.options.methods_number)

        # Check one of the calls to ensure it's for the right method
        call_kwargs = mock_generate_call.call_args.kwargs
        self.assertEqual(call_kwargs["callable_name"], "public_method")
        self.assertEqual(call_kwargs["target_obj_expr"], "instance_var")

    def test_dispatch_fuzz_on_instance_recursion_depth(self):
        """Logic Test: Ensure the recursive deep-diving logic terminates correctly."""
        original_depth = self.writer.MAX_FUZZ_GENERATION_DEPTH
        self.writer.MAX_FUZZ_GENERATION_DEPTH = 1

        try:
            self.writer._dispatch_fuzz_on_instance(
                current_prefix="prefix_at_max_depth",
                target_obj_expr_str="some_object",
                class_name_hint="SomeClass",
                generation_depth=2,  # This depth is > MAX_FUZZ_GENERATION_DEPTH
            )
        finally:
            self.writer.MAX_FUZZ_GENERATION_DEPTH = original_depth

        generated_code = self.writer.output.getvalue()
        self.assertIn("Max fuzz code generation depth", generated_code)
        self.assertNotIn("Dispatching Fuzz for", generated_code)

    def test_dispatch_fuzz_on_instance_dispatching_logic(self):
        """_dispatch_fuzz_on_instance invokes plugin instance-dispatchers, then the generic fallback.

        Specialized per-type dispatch (e.g. h5py Dataset/Group) is registered by a plugin via
        add_instance_dispatcher rather than hard-coded in core.
        """
        from fusil.plugin_manager import PluginManager

        pm = PluginManager()
        seen = []

        def dispatcher(writer, current_prefix, target_expr, class_hint, depth):
            seen.append((current_prefix, target_expr, class_hint, depth))
            return None

        pm.add_instance_dispatcher(dispatcher)
        self.writer.plugin_manager = pm
        self.writer.output = StringIO()
        self.writer._dispatch_fuzz_on_instance("h5_dispatch", "my_dataset_var", "Dataset", 0)
        self.assertEqual(seen, [("h5_dispatch", "my_dataset_var", "Dataset", 0)])
        self.assertIn("doing generic calls", self.writer.output.getvalue())

        # No plugin manager -> only the generic fallback.
        self.writer.plugin_manager = None
        self.writer.output = StringIO()
        self.writer._dispatch_fuzz_on_instance(
            "generic_dispatch", "my_generic_var", "SomeGenericClass", 0
        )
        self.assertIn("doing generic calls", self.writer.output.getvalue())

    def test_write_main_fuzzing_logic_call_counts(self):
        """Wiring Test: Checks the main logic method calls the correct number of fuzzing sub-methods."""
        with (
            patch.object(self.writer, "_generate_and_write_call") as mock_gen_call,
            patch.object(self.writer, "_fuzz_one_class") as mock_fuzz_class,
            patch.object(self.writer, "_fuzz_one_module_object") as mock_fuzz_obj,
        ):
            self.writer._write_main_fuzzing_logic()

            self.assertEqual(mock_gen_call.call_count, self.writer.options.functions_number)
            self.assertEqual(mock_fuzz_class.call_count, self.writer.options.classes_number)
            self.assertEqual(mock_fuzz_obj.call_count, self.writer.options.objects_number)


if __name__ == "__main__":
    unittest.main()
