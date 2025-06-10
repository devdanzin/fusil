import unittest
import sys
import os
from decimal import Decimal

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    # --- Import the objects to be tested ---
    from fusil.python.samples.weird_classes import weird_classes, weird_instances
    SAMPLES_AVAILABLE = True
except (ImportError, TypeError) as e:
    print(f"Could not import weird_classes module, skipping tests: {e}", file=sys.stderr)
    weird_classes = None
    weird_instances = None
    SAMPLES_AVAILABLE = False


@unittest.skipIf(not SAMPLES_AVAILABLE, "Could not import weird_classes module, skipping tests.")
class TestWeirdClasses(unittest.TestCase):
    """
    Test suite for the weird_classes sample module.

    These tests verify that the dictionaries of weird classes and instances
    are generated correctly, have the expected types, and follow the
    intended inheritance structure.
    """

    def test_dictionaries_are_populated(self):
        """
        Verifies that the main dictionaries are created and not empty.
        """
        self.assertIsInstance(weird_classes, dict)
        self.assertIsInstance(weird_instances, dict)
        self.assertGreater(len(weird_classes), 0, "weird_classes dictionary should not be empty.")
        self.assertGreater(len(weird_instances), 0, "weird_instances dictionary should not be empty.")

    def test_weird_classes_inheritance(self):
        """
        Verifies that generated classes inherit from their correct Python base types.
        """
        # Test a few representative examples from the different base types.
        self.assertTrue(issubclass(weird_classes['weird_int'], int))
        self.assertTrue(issubclass(weird_classes['weird_list'], list))
        self.assertTrue(issubclass(weird_classes['weird_dict'], dict))
        self.assertTrue(issubclass(weird_classes['weird_bytes'], bytes))
        self.assertTrue(issubclass(weird_classes['weird_Decimal'], Decimal))

    def test_weird_classes_metaclass_behavior(self):
        """
        Verifies that the WeirdBase metaclass correctly modifies class behavior.
        """
        # The WeirdBase metaclass overrides __eq__ to always return False.
        weird_int_class = weird_classes['weird_int']
        self.assertNotEqual(weird_int_class, weird_int_class,
                          "A weird class should not be equal to itself due to the metaclass.")

    def test_weird_instances_types(self):
        """
        Verifies that generated instances are of the correct weird class type.
        """
        # Test a few key instances
        empty_list = weird_instances['weird_list_empty']
        self.assertIsInstance(empty_list, weird_classes['weird_list'])

        maxsize_int = weird_instances['weird_int_sys_maxsize']
        self.assertIsInstance(maxsize_int, weird_classes['weird_int'])

        tricky_str_dict = weird_instances['weird_dict_tricky_strs']
        self.assertIsInstance(tricky_str_dict, weird_classes['weird_dict'])

    def test_weird_instances_content(self):
        """
        Verifies the contents of a few representative generated instances.
        """
        # Test an empty instance
        empty_int = weird_instances['weird_int_empty']
        self.assertEqual(empty_int, 0) # int() defaults to 0

        # Test a populated instance
        single_item_str = weird_instances['weird_str_single']
        self.assertEqual(single_item_str, "a")

        # Test a numeric instance
        maxsize_int = weird_instances['weird_int_sys_maxsize']
        self.assertEqual(maxsize_int, sys.maxsize)

        # Test an instance created from a range
        range_tuple = weird_instances['weird_tuple_range']
        self.assertEqual(len(range_tuple), 20)
        self.assertEqual(range_tuple[5], 5)


if __name__ == '__main__':
    unittest.main()
