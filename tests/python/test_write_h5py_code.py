import unittest
import sys
import os
import ast
from io import StringIO
from unittest.mock import patch, MagicMock, ANY

# --- Test Setup: Path Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Adjust the path to go up to the project root
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

# --- Imports of Code to be Tested ---
# We test conditionally, but for the tests to run, h5py must be installed.
try:
    import h5py
    import numpy
    from fusil.python.h5py.write_h5py_code import WriteH5PyCode

    H5PY_AVAILABLE = True
except ImportError:
    h5py = None
    numpy = None
    WriteH5PyCode = None
    H5PY_AVAILABLE = False

from fusil.config import FusilConfig


@unittest.skipIf(not H5PY_AVAILABLE, "h5py or numpy is not installed, skipping h5py writer tests")
class TestWriteH5PyCode(unittest.TestCase):
    """
    A comprehensive test suite for the WriteH5PyCode class.

    This suite focuses on validating the h5py-specific code generation logic.
    It uses a mocked parent WritePythonCode object to isolate the h5py writer
    and verify its output and control flow under various conditions.
    """

    def setUp(self):
        """Set up a fresh test fixture before each test method runs."""
        # 1. Create a fully mocked parent WritePythonCode instance
        self.mock_parent_writer = MagicMock()

        # 2. Mock the necessary attributes on the parent
        self.mock_parent_writer.options = FusilConfig(read=False)
        self.mock_parent_writer.output = StringIO()

        # 3. Mock the parent's methods that WriteH5PyCode will call
        self.mock_parent_writer.write = MagicMock()
        self.mock_parent_writer.emptyLine = MagicMock()
        self.mock_parent_writer.addLevel = MagicMock()
        self.mock_parent_writer.restoreLevel = MagicMock()
        self.mock_parent_writer.write_print_to_stderr = MagicMock()
        self.mock_parent_writer._dispatch_fuzz_on_instance = MagicMock()
        self.mock_parent_writer.base_level = 0

        # 4. Set up a mock argument generator hierarchy
        self.mock_parent_writer.arg_generator = MagicMock()
        self.mock_h5py_arg_gen = MagicMock()
        self.mock_parent_writer.arg_generator.h5py_argument_generator = self.mock_h5py_arg_gen

        # 5. Instantiate the class we are testing
        self.h5py_writer = WriteH5PyCode(self.mock_parent_writer)
        self.mock_parent_writer.h5py_writer = self.h5py_writer

    # --- Tests for Private Helper Methods ---

    def test_write_h5py_script_header_and_imports(self):
        """Logic Test: Ensures the h5py header writes syntactically valid helper functions."""
        # We need a real StringIO to capture output for ast.parse
        output_stream = StringIO()
        self.mock_parent_writer.write.side_effect = lambda level, text: output_stream.write(text + "\n")
        self.mock_parent_writer.emptyLine.side_effect = lambda: output_stream.write("\n")

        self.h5py_writer._write_h5py_script_header_and_imports()

        generated_code = output_stream.getvalue()

        self.assertTrue(generated_code, "Header generation method produced no output.")
        self.assertIn("def _fusil_h5_create_dynamic_slice_for_rank(rank_value):", generated_code)
        self.assertIn("def _fusil_h5_get_link_target_in_file(parent_group_obj,", generated_code)

        # Verify the generated code is syntactically correct
        try:
            ast.parse(generated_code)
        except SyntaxError as e:
            self.fail(f"The h5py header has a syntax error: {e}\n--- SCRIPT ---\n{generated_code}")

    def test_write_h5py_file(self):
        """Wiring Test: Validates that _write_h5py_file correctly uses the argument generator."""
        # Configure mock argument generator to return predictable values
        self.mock_h5py_arg_gen.genH5PyFileDriver_actualval.return_value = 'core'
        self.mock_h5py_arg_gen.genH5PyFileMode_actualval.return_value = 'w'
        self.mock_h5py_arg_gen.gen_h5py_file_name_or_object.return_value = ("'mem_core_abc'", [])
        self.mock_h5py_arg_gen.genH5PyDriverKwargs.return_value = [", backing_store=False"]
        self.mock_h5py_arg_gen.genH5PyLibver.return_value = ["('v110', 'latest')"]
        self.mock_h5py_arg_gen.genH5PyUserblockSize.return_value = ["512"]
        self.mock_h5py_arg_gen.genH5PyLocking.return_value = ["True"]
        self.mock_h5py_arg_gen.genH5PyFsStrategyKwargs.return_value = [""]

        self.h5py_writer._write_h5py_file()

        # Check that the final call to parent.write contains a correctly constructed h5py.File call
        # We look for the call arguments among all calls to the mocked write method.
        found_call = False
        for call in self.mock_parent_writer.write.call_args_list:
            args, kwargs = call
            if "h5py.File('mem_core_abc', mode='w', driver='core', backing_store=False, libver=('v110', 'latest'), locking=True, userblock_size=512)" in \
                    args[1]:
                found_call = True
                break

        self.assertTrue(found_call, "The h5py.File constructor was not called with the expected arguments.")

    @patch('fusil.python.h5py.write_h5py_code.random', return_value=0.1)  # Ensure all operations inside are attempted
    def test_write_h5py_dataset_creation_call(self, mock_random):
        """Wiring Test: Ensures dataset creation calls are built correctly from generated arguments."""
        # Configure mocks
        self.mock_h5py_arg_gen.genH5PyDatasetShape_expr.return_value = "(10, 20)"
        self.mock_h5py_arg_gen.genH5PyComplexDtype_expr.return_value = "'i4'"
        self.mock_h5py_arg_gen.genH5PyData_expr.return_value = "None"
        self.mock_h5py_arg_gen.genH5PyDatasetChunks_expr.return_value = "True"
        self.mock_h5py_arg_gen.genH5PyFillvalue_expr.return_value = "0"
        self.mock_h5py_arg_gen.genH5PyFillTime_expr.return_value = "'ifset'"
        self.mock_h5py_arg_gen.genH5PyCompressionKwargs_expr.return_value = ["compression='gzip'"]
        self.mock_h5py_arg_gen.genH5PyTrackTimes_expr.return_value = "True"

        self.h5py_writer._write_h5py_dataset_creation_call("mock_parent", "'my_dset'", "dset_var")

        # Get the full generated string for the create_dataset call
        generated_call = ""
        for call in self.mock_parent_writer.write.call_args_list:
            args, kwargs = call
            if "create_dataset" in args[1]:
                generated_call = args[1]
                break

        self.assertTrue(generated_call, "create_dataset call was not generated.")

        # Assert that all expected components are present, ignoring order
        self.assertIn("dset_var = mock_parent.create_dataset('my_dset'", generated_call)
        self.assertIn("shape=(10, 20)", generated_call)
        self.assertIn("dtype='i4'", generated_call)
        self.assertIn("chunks=True", generated_call)
        self.assertIn("fillvalue=0", generated_call)
        self.assertIn("fill_time='ifset'", generated_call)
        self.assertIn("compression='gzip'", generated_call)
        self.assertIn("track_times=True", generated_call)

    # --- Tests for High-Level Fuzzing Orchestrators ---

    @patch('fusil.python.h5py.write_h5py_code.random', return_value=0.1)  # Ensure all operations inside are attempted
    def test_fuzz_one_dataset_instance(self, mock_random):
        """Wiring Test: Checks that _fuzz_one_dataset_instance attempts various dataset operations."""
        self.h5py_writer._fuzz_one_dataset_instance("dset_var", "my_dset", "p1", 0)

        # Check that it tried to dispatch fuzzing on the dataset's attributes
        self.mock_parent_writer._dispatch_fuzz_on_instance.assert_any_call(
            current_prefix='p1_attrs',
            target_obj_expr_str=ANY,
            class_name_hint='AttributeManager',
            generation_depth=1
        )

        # Check that it tried to generate code for various operations by looking at stderr prints
        self.mock_parent_writer.write_print_to_stderr.assert_any_call(0, unittest.mock.ANY)
        all_prints = " ".join(call.args[1] for call in self.mock_parent_writer.write_print_to_stderr.call_args_list)

        self.assertIn("DS_OP_CTX", all_prints)
        self.assertIn("DS_ASTYPE", all_prints)
        self.assertIn("DS_ADV_SLICE", all_prints)
        self.assertIn("DS_ITER", all_prints)

    @patch('fusil.python.h5py.write_h5py_code.random', return_value=0.1)  # Ensure all operations inside are attempted
    def test_fuzz_one_group_instance(self, mock_random):
        """Wiring Test: Verifies that _fuzz_one_group_instance tries to create children and links."""
        # Configure the argument generator to return predictable code strings for this test
        self.mock_h5py_arg_gen.genH5PyNewLinkName_expr.return_value = "'mock_link_name'"
        self.mock_h5py_arg_gen.genH5PyLinkPath_expr.return_value = "'/mock/path'"
        self.mock_h5py_arg_gen.genH5PyExternalLinkFilename_expr.return_value = "'ext_file.h5'"
        self.mock_h5py_arg_gen.genH5PyExistingObjectPath_expr.return_value = \
            "_fusil_h5_get_link_target_in_file(group_var, {}, {})"

        self.h5py_writer._fuzz_one_group_instance("group_var", "my_group", "p1", 0)

        # Check that the parent writer was called to write code
        all_write_calls = " ".join(call.args[1] for call in self.mock_parent_writer.write.call_args_list)

        # Verify that all major code-generation branches were entered
        self.assertIn("create_dataset", all_write_calls)
        self.assertIn("create_group", all_write_calls)
        self.assertIn("h5py.SoftLink", all_write_calls)
        self.assertIn("h5py.ExternalLink", all_write_calls)
        self.assertIn("_fusil_h5_get_link_target_in_file", all_write_calls)  # For HardLink
        self.assertIn("require_group", all_write_calls)
        self.assertIn("require_dataset", all_write_calls)

        # Check that it dispatches fuzzing on created children
        self.assertGreaterEqual(self.mock_parent_writer._dispatch_fuzz_on_instance.call_count, 2)

    def test_fuzz_one_h5py_class(self):
        """Wiring Test: Ensures the class factory dispatches to the correct private writer."""
        test_cases = {
            "File": "_write_h5py_file",
            "Dataset": "_write_h5py_dataset_creation_call",
            "Group": "create_group"  # This one writes the call directly
        }

        for class_name, expected_call_marker in test_cases.items():
            with self.subTest(class_name=class_name):
                # Reset mocks for each subtest
                self.setUp()

                # We patch the specific methods to see if they get called
                with patch.object(self.h5py_writer, '_write_h5py_file') as mock_write_file, \
                        patch.object(self.h5py_writer, '_write_h5py_dataset_creation_call') as mock_write_dset:

                    # Mock the h5py class type
                    mock_class_type = MagicMock()
                    mock_class_type.__module__ = 'h5py'

                    result = self.h5py_writer.fuzz_one_h5py_class(class_name, mock_class_type, "instance_var", "p1")

                    self.assertTrue(result, f"fuzz_one_h5py_class should have handled {class_name}")

                    if class_name == "File":
                        mock_write_file.assert_called_once()
                    elif class_name == "Dataset":
                        mock_write_dset.assert_called_once()
                    elif class_name == "Group":
                        all_write_calls = " ".join(call.args[1] for call in self.mock_parent_writer.write.call_args_list)
                        self.assertIn("create_group", all_write_calls)

        # Test non-h5py class
        result_fail = self.h5py_writer.fuzz_one_h5py_class("NotH5PyClass", MagicMock(), "instance_var", "p1")
        self.assertFalse(result_fail, "fuzz_one_h5py_class should not handle non-h5py classes.")

    def test_dispatch_fuzz_on_h5py_instance(self):
        """Logic Test: Checks that the h5py dispatcher generates the correct 'elif' chain."""
        # This test checks the generated code string output
        self.h5py_writer._dispatch_fuzz_on_h5py_instance("Dataset", "p1", 0, "target_var")

        generated_code = "".join(call.args[1] for call in self.mock_parent_writer.write.call_args_list)

        self.assertIn("elif isinstance(target_var, h5py.Dataset):", generated_code)
        self.assertIn("elif isinstance(target_var, h5py.Group):", generated_code)
        self.assertIn("elif isinstance(target_var, h5py.File):", generated_code)
        self.assertIn("elif isinstance(target_var, h5py.AttributeManager):", generated_code)


if __name__ == '__main__':
    unittest.main()