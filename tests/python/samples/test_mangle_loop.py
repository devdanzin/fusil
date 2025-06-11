import unittest
import sys
import os
import inspect
import io
from unittest.mock import MagicMock

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    # --- Import the object to be tested ---
    from fusil.python import mangle_object
    SAMPLES_AVAILABLE = True
except (ImportError, TypeError) as e:
    print(f"Could not import mangle_object module, skipping tests: {e}", file=sys.stderr)
    mangle_object = None
    SAMPLES_AVAILABLE = False


@unittest.skipIf(not SAMPLES_AVAILABLE, "Could not import mangle_object module, skipping tests.")
class TestMangleLoop(unittest.TestCase):
    """
    Test suite for the mangle_loop sample module.

    These tests execute the code snippet from mangle_loop.py in a controlled
    environment to verify its core logic: iterating over object attributes,
    calling the mangle_obj function, and handling exceptions.
    """

    def setUp(self):
        """
        Load the code from the sample file before each test.
        """
        # We need to reconstruct the string with the %s placeholder for testing
        self.mangle_loop_code = mangle_object.mangle_loop.replace(
            "REPLACEMENT_PLACEHOLDER", "%s"
        )

    def test_happy_path_calls_mangle_obj(self):
        """
        Tests that for a simple class, mangle_obj is called for the public method.
        """
        class DummyClass:
            def __init__(self):
                self.x = 1
            def public_method(self, a, b):
                pass

        test_obj = DummyClass()
        mock_mangle_obj = MagicMock()
        num_args = 5 # An arbitrary number for the %s replacement

        # Prepare the namespace for exec()
        test_namespace = {
            'obj': test_obj,
            'mangle_obj': mock_mangle_obj,
            'stderr': io.StringIO(),
            'inspect': inspect,
        }

        # Execute the code with the placeholder filled
        exec(self.mangle_loop_code % num_args, test_namespace)

        # The loop should find and call mangle_obj for 'public_method'
        # inspect.getfullargspec(DummyClass.public_method) has args ['self', 'a', 'b']
        expected_arg_count = 3
        mock_mangle_obj.assert_called_once_with(
            test_obj,
            'public_method',
            (1,) * expected_arg_count
        )

    def test_dunder_methods_are_filtered(self):
        """
        Tests that the loop correctly skips dunder methods like __init__.
        """
        class DummyClass:
            def __init__(self):
                pass
            def __repr__(self):
                return "dummy"

        test_obj = DummyClass()
        mock_mangle_obj = MagicMock()

        test_namespace = {
            'obj': test_obj,
            'mangle_obj': mock_mangle_obj,
            'stderr': io.StringIO(),
            'inspect': inspect,
        }

        exec(self.mangle_loop_code % 0, test_namespace)

        # mangle_obj should NOT have been called for __init__ or __repr__
        mock_mangle_obj.assert_not_called()

    def test_exception_handling(self):
        """
        Tests that exceptions from the mangle_obj call are caught and logged.
        """
        class DummyClass:
            def public_method(self):
                pass

        test_obj = DummyClass()
        # Configure the mock to raise an error
        mock_mangle_obj = MagicMock(side_effect=ValueError("Test Mangle Error"))
        mock_stderr = io.StringIO()

        test_namespace = {
            'obj': test_obj,
            'mangle_obj': mock_mangle_obj,
            'stderr': mock_stderr,
            'inspect': inspect,
        }

        code_without_stderr = self.mangle_loop_code.replace("from sys import stderr", "")
        exec(code_without_stderr % 0, test_namespace)

        # Check that the exception was caught and its message was printed to stderr
        output = mock_stderr.getvalue()
        self.assertIn("ValueError", output)
        self.assertIn("Test Mangle Error", output)


if __name__ == '__main__':
    unittest.main()
