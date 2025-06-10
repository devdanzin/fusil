import unittest
import sys
import os
import numpy

# --- Test Setup: Path Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, '..', '..', '..')
sys.path.insert(0, PROJECT_ROOT)

try:
    # --- Import all the objects to be tested ---
    from fusil.python.samples import tricky_numpy

    NUMPY_AVAILABLE = True
except (ImportError, TypeError) as e:
    print(f"Could not import tricky_numpy module, skipping tests: {e}", file=sys.stderr)
    tricky_numpy = None
    NUMPY_AVAILABLE = False


@unittest.skipIf(not NUMPY_AVAILABLE, "Could not import tricky_numpy module, skipping tests.")
class TestTrickyNumpy(unittest.TestCase):
    """
    Test suite for the tricky_numpy sample module.

    These tests verify that the NumPy array objects are created with their
    expected properties, such as shape, dtype, memory layout, and special
    values (NaN, inf).
    """

    def test_basic_shapes_and_values(self):
        """
        Tests basic arrays with different shapes, dtypes, and creation methods.
        """
        self.assertEqual(tricky_numpy.numpy_zeros_large.shape, (1000, 1000))
        self.assertEqual(tricky_numpy.numpy_zeros_large.dtype, numpy.int16)
        self.assertEqual(tricky_numpy.numpy_zeros_large[0, 0], 0)

        self.assertIsInstance(tricky_numpy.numpy_ones_various_dtypes, list)
        self.assertEqual(tricky_numpy.numpy_ones_various_dtypes[0].dtype, numpy.uint8)
        self.assertEqual(tricky_numpy.numpy_ones_various_dtypes[1].dtype, numpy.float16)

        self.assertEqual(tricky_numpy.numpy_scalar_float64.shape, ())
        self.assertIsInstance(tricky_numpy.numpy_scalar_float64, numpy.float64)

    def test_special_float_arrays(self):
        """
        Tests arrays containing special floating point values like NaN and infinity.
        """
        self.assertTrue(numpy.isnan(tricky_numpy.numpy_nan_array).all())
        self.assertTrue(numpy.isinf(tricky_numpy.numpy_inf_array).all())
        self.assertTrue(numpy.isneginf(tricky_numpy.numpy_neginf_array).all())

        # Check for mixed values
        mixed_array = tricky_numpy.numpy_mixed_inf_nan_int_float
        self.assertTrue(numpy.isnan(mixed_array[1]))
        self.assertTrue(numpy.isposinf(mixed_array[3]))
        self.assertTrue(numpy.isneginf(mixed_array[4]))

    def test_structured_arrays(self):
        """
        Tests structured (compound dtype) arrays.
        """
        simple_struct = tricky_numpy.numpy_structured_array_simple
        self.assertEqual(simple_struct.shape, (2,))
        self.assertEqual(simple_struct.dtype.names, ('id', 'name', 'score'))
        self.assertEqual(simple_struct[1]['name'], 'Bob')

        nested_struct = tricky_numpy.numpy_structured_array_nested
        self.assertEqual(nested_struct.shape, (2,))
        self.assertEqual(nested_struct.dtype.names, ('coords', 'label'))
        self.assertEqual(nested_struct['coords'].dtype.names, ('x', 'y'))
        self.assertEqual(nested_struct[0]['coords']['y'], 2.0)

    def test_memory_layout_and_flags(self):
        """
        Tests arrays with specific memory layouts and flags (e.g., read-only).
        """
        # Test non-contiguous array created from a transpose
        non_contig = tricky_numpy.numpy_non_contiguous_view_transpose
        self.assertFalse(non_contig.flags.c_contiguous)
        self.assertTrue(non_contig.flags.f_contiguous)  # Transpose of C-order is F-order

        # Test Fortran-contiguous array
        f_contig = tricky_numpy.numpy_f_contiguous_3d
        self.assertFalse(f_contig.flags.c_contiguous)
        self.assertTrue(f_contig.flags.f_contiguous)

        # Test read-only array
        readonly_arr = tricky_numpy.numpy_readonly_array
        self.assertFalse(readonly_arr.flags.writeable)
        with self.assertRaises(ValueError, msg="Should not be able to write to a read-only array"):
            readonly_arr[0] = 100

    def test_problematic_and_edge_case_arrays(self):
        """
        Tests arrays designed to be problematic, e.g., with circular references.
        """
        # Test circular reference in an object array
        circ_ref_array = tricky_numpy.numpy_circular_references
        self.assertIs(circ_ref_array[0], circ_ref_array)

        # Test zero-dimensional (scalar) array
        self.assertEqual(tricky_numpy.numpy_zerodim_int.shape, ())
        self.assertEqual(tricky_numpy.numpy_zerodim_int, 101)

        # Test array with a zero-sized dimension
        self.assertEqual(tricky_numpy.numpy_array_with_zero_size_dim.shape, (5, 0, 5))


if __name__ == '__main__':
    unittest.main()
