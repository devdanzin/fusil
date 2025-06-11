import unittest
import sys
import pathlib
import os
import io
from unittest.mock import MagicMock, patch

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    # --- Import the object to be tested ---
    # We exec the code from the file into a temporary module's dict
    from fusil.python import mangle_object

    temp_module = type(sys)('temp_mangle_obj_module')
    # Use the fixed version of mangle_obj for testing
    exec(pathlib.Path(PROJECT_ROOT, "fusil/python/samples/mangle_obj.py").read_text(), temp_module.__dict__)
    mangle_obj_func = temp_module.mangle_obj
    SAMPLES_AVAILABLE = True
except (ImportError, TypeError, NameError) as e:
    print(f"Could not import mangle_object module, skipping tests: {e}", file=sys.stderr)
    mangle_obj_func = None
    SAMPLES_AVAILABLE = False


@unittest.skipIf(not SAMPLES_AVAILABLE, "Could not import mangle_object module, skipping tests.")
class TestMangleObj(unittest.TestCase):
    """
    Test suite for the mangle_obj sample module.

    These tests verify the core logic of the mangle_obj function:
    1. That it replaces attributes with mocks.
    2. That it preserves the specific method being tested.
    3. That it reliably restores the object's state afterward.
    4. That it correctly handles objects without a __dict__.
    """

    def test_attribute_mangling_effect(self):
        """
        Tests that mangling attributes has an effect on method execution
        and that the correct messages are logged.
        """

        class Dummy:
            def __init__(self):
                self.value = 10

            def get_value_plus(self, x):
                # When mangle_obj replaces it with a MagicMock, this will fail.
                if not isinstance(self.value, int):
                    raise TypeError("self.value has been mangled and is no longer an int!")
                return self.value + x

        test_obj = Dummy()
        mock_stderr = io.StringIO()

        mangle_obj_func.__globals__['stderr'] = mock_stderr
        mangle_obj_func.__globals__['MagicMock'] = MagicMock

        # When mangle_obj runs, it will replace self.value with a MagicMock.
        # The call to get_value_plus() will then execute our check and
        # raise the TypeError we are listening for.
        mangle_obj_func(test_obj, 'get_value_plus', 5)

        output = mock_stderr.getvalue()
        self.assertIn("TypeError", output, "A TypeError from the mangled call should be caught and logged.")
        self.assertIn("has been mangled", output, "The specific TypeError message should be logged.")

    def test_method_under_test_is_preserved(self):
        """
        Tests that the method being tested is not replaced by a mock.
        """
        canary = object()  # A unique object to act as a marker

        class Dummy:
            def __init__(self):
                self.value = 10

            def method_to_test(self):
                return canary  # Return our canary object

            def other_method(self):
                pass

        test_obj = Dummy()
        mangle_obj_func.__globals__['stderr'] = io.StringIO()
        mangle_obj_func.__globals__['MagicMock'] = MagicMock

        # This will mangle all attributes EXCEPT 'method_to_test'
        mangle_obj_func(test_obj, 'method_to_test')

        # After mangling, the method should still be the original, real method.
        # We can verify this by calling it and checking for our canary object.
        self.assertIs(test_obj.method_to_test(), canary,
                      "The method under test appears to have been mangled, but it shouldn't be.")

    def test_object_state_is_restored(self):
        """
        Tests that the object's attributes are restored after the call, even on error.
        """

        class Dummy:
            def __init__(self):
                self.value = 10
                self.other_value = "hello"

            def method_that_fails(self):
                raise RuntimeError("Intentional failure")

        test_obj = Dummy()
        original_value = test_obj.value
        original_other_value = test_obj.other_value

        mangle_obj_func.__globals__['stderr'] = io.StringIO()
        mangle_obj_func.__globals__['MagicMock'] = MagicMock

        mangle_obj_func(test_obj, 'method_that_fails')

        output = mangle_obj_func.__globals__['stderr'].getvalue()
        self.assertIn("RuntimeError", output,
                      "The intentional error should be logged to stderr.")
        self.assertIn("Intentional failure", output,
                      "The intentional error message should be logged to stderr.")

        self.assertEqual(test_obj.value, original_value, "Object attribute 'value' was not restored.")
        self.assertEqual(test_obj.other_value, original_other_value, "Object attribute 'other_value' was not restored.")
        self.assertNotIsInstance(test_obj.value, MagicMock)

    def test_mangling_object_with_no_dict(self):
        """
        Tests that mangle_obj handles objects with __slots__ gracefully.
        """

        class SlottedClass:
            __slots__ = ['value']

            def __init__(self):
                self.value = 10

            def get_value(self):
                return self.value

        test_obj = SlottedClass()
        mock_stderr = io.StringIO()

        mangle_obj_func.__globals__['stderr'] = mock_stderr

        # This call should not raise an AttributeError
        mangle_obj_func(test_obj, 'get_value')

        output = mock_stderr.getvalue()
        self.assertIn("object without __dict__", output,
                      "Should log that it's calling on a slotted object.")


if __name__ == '__main__':
    unittest.main()
