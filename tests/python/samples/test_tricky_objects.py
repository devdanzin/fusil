import unittest
import sys
import os
import types

# --- Test Setup: Path Configuration ---
# This ensures the test runner can find the 'fusil' package.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    # --- Import all the objects to be tested ---
    from fusil.python.samples.tricky_objects import (
        TrickyDescriptor,
        TrickyMeta,
        TrickyClass,
        tricky_instance,
        tricky_cell,
        tricky_simplenamespace,
        tricky_capsule,
        tricky_module,
        tricky_module2,
        tricky_genericalias,
        tricky_dict,
        tricky_mappingproxy,
        tricky_function,
        tricky_lambda,
        tricky_classmethod,
        tricky_staticmethod,
        tricky_property,
        tricky_code,
        tricky_closure,
        tricky_classmethod_descriptor,
        tricky_frame,
        tricky_traceback,
        tricky_list_with_cycle,
    )
    SAMPLES_AVAILABLE = True
except (ImportError, TypeError, SyntaxError) as e:
    print(f"Could not import tricky_objects module, skipping tests: {e}", file=sys.stderr)
    SAMPLES_AVAILABLE = False


@unittest.skipIf(not SAMPLES_AVAILABLE, "Could not import tricky_objects module, skipping tests.")
class TestTrickyObjects(unittest.TestCase):
    """
    Test suite for the tricky_objects sample module.

    These tests verify that the objects are created with their expected types
    and that their specific "tricky" characteristics (e.g., circular references,
    custom metaclass behavior) are working as intended.
    """

    def test_object_types(self):
        """
        Verifies the fundamental type of each tricky object.
        """
        self.assertIsInstance(tricky_function, types.FunctionType)
        self.assertIsInstance(tricky_lambda, types.LambdaType)
        self.assertIsInstance(tricky_code, types.CodeType)
        self.assertIsInstance(tricky_cell, types.CellType)
        self.assertIsInstance(tricky_module, types.ModuleType)
        self.assertIsInstance(tricky_mappingproxy, types.MappingProxyType)
        self.assertIsInstance(tricky_instance, TrickyClass)
        self.assertIsInstance(tricky_list_with_cycle, list)

        # Some objects might not exist on all Python versions, so test conditionally.
        if tricky_genericalias:
            self.assertIsInstance(tricky_genericalias, types.GenericAlias)
        if tricky_frame:
            self.assertIsInstance(tricky_frame, types.FrameType)
        if tricky_traceback:
            self.assertIsInstance(tricky_traceback, types.TracebackType)

    def test_circular_references(self):
        """
        Verifies that objects with intentional circular references are structured correctly.
        """
        # Test the self-referential dictionary
        self.assertIs(tricky_dict["tricky_dict"], tricky_dict)

        # Test the self-referential list
        self.assertIs(tricky_list_with_cycle[0][0], tricky_list_with_cycle)

        # Test the self-referential namespace
        self.assertIs(tricky_simplenamespace.dummy, tricky_simplenamespace)

    def test_tricky_class_and_meta_behavior(self):
        """
        Verifies the special behavior of TrickyClass, TrickyMeta, and TrickyDescriptor.
        """
        # Test TrickyMeta's overridden __signature__ property
        with self.assertRaises(AttributeError, msg="Accessing __signature__ should raise an error"):
            _ = TrickyClass.__signature__

        # Test TrickyClass's overridden __getattr__
        # Accessing any undefined attribute should return the instance itself.
        self.assertIs(tricky_instance.some_non_existent_attribute, tricky_instance)

        # Test that the descriptor works
        self.assertIsInstance(tricky_instance.tricky_descriptor, TrickyDescriptor)


if __name__ == '__main__':
    unittest.main()
