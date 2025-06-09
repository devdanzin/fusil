import ctypes
import sys
import warnings

from math import factorial

import numpy

# --- Basic Shapes & Values ---
numpy_zeros_large = numpy.zeros((1000, 1000), dtype=numpy.int16)
numpy_ones_various_dtypes = [
    numpy.ones((2,2), dtype=numpy.uint8),
    numpy.ones((2,2), dtype=numpy.float16),
    numpy.ones((2,2), dtype=numpy.complex64)
]
numpy_empty_int_1d = numpy.empty(100, dtype=numpy.int32)
numpy_empty_object_2d = numpy.empty((10,10), dtype=object)
numpy_scalar_float64 = numpy.float64(3.14159)
numpy_scalar_object_none = numpy.array(None, dtype=object)
numpy_arange_negative_step = numpy.arange(10, 0, -1, dtype=numpy.int8)
numpy_linspace_weird = numpy.linspace(numpy.finfo(numpy.float32).min, numpy.finfo(numpy.float32).max, 5, dtype=numpy.float32)
numpy_logspace_sizes = [numpy.logspace(1,10,5), numpy.logspace(-5,5,1000)]

# --- Special Floats (NaN, Inf) and Complex ---
numpy_nan_array = numpy.full((50, 50), numpy.nan, dtype=numpy.float32)
numpy_inf_array = numpy.full((5,5), numpy.inf, dtype=numpy.float64)
numpy_neginf_array = numpy.full((5,5), -numpy.inf, dtype=numpy.float16)
numpy_mixed_inf_nan_int_float = numpy.array([1, numpy.nan, 3.0, numpy.inf, -numpy.inf, 0, -128, 255], dtype=numpy.float64)
numpy_complex_nan_inf = numpy.array([
    complex(numpy.nan, numpy.nan), complex(numpy.inf, 1), complex(1, -numpy.inf),
    complex(numpy.nan, 0), complex(0, numpy.inf)
], dtype=numpy.complex128)

# --- Large Numbers & Float Boundaries ---
numpy_factorial_int64 = numpy.array([factorial(x) for x in range(15, 21)], dtype=numpy.int64)
try:
    numpy_factorial_float128 = numpy.array([factorial(x) for x in range(20, 30)], dtype=numpy.float128)
except AttributeError: # float128 might not be available
    numpy_factorial_float128 = numpy.array([factorial(x) for x in range(20, 30)], dtype=numpy.float64)

numpy_sys_max_float_array =  numpy.array([sys.float_info.max/2, sys.float_info.max], dtype=numpy.float64)
numpy_sys_min_float_array =  numpy.array([sys.float_info.min*2, sys.float_info.min], dtype=numpy.float64)
numpy_float_subnormals = numpy.array([numpy.finfo(numpy.float32).tiny * 0.5, numpy.finfo(numpy.float64).tiny * 0.1], dtype=numpy.float64)
numpy_float_boundaries = numpy.array([
    numpy.finfo(numpy.float16).max, numpy.finfo(numpy.float16).min, numpy.finfo(numpy.float16).eps,
    numpy.finfo(numpy.float32).max, numpy.finfo(numpy.float32).min, numpy.finfo(numpy.float32).eps,
    numpy.finfo(numpy.float64).max, numpy.finfo(numpy.float64).min, numpy.finfo(numpy.float64).eps,
], dtype=numpy.float64)


# --- Object Arrays ---
numpy_object_array_mixed = numpy.array([1, "hello", None, (1,2), [3,4], {"a":1}, True, numpy.nan], dtype=object)
numpy_object_array_nested_lists = numpy.array([[[1],[2,3]], [[4,5,6]]], dtype=object)
numpy_object_array_none = numpy.full((3,3), None, dtype=object)


# --- Structured Arrays ---
numpy_structured_array_simple = numpy.array([(1, 'Alice', 0.5), (2, 'Bob', 0.88)],
                                dtype=[('id', 'i4'), ('name', 'U10'), ('score', 'f8')])
numpy_structured_array_nested = numpy.array([((1, 2.0), 'A'), ((3, 4.0), 'B')],
                                dtype=[('coords', [('x', 'i4'), ('y', 'f8')]), ('label', 'S1')])
try: # Offsets can be tricky
    numpy_structured_array_offsets = numpy.zeros(2, dtype={'names':['f1','f2'],
                                                        'formats':['i4','f8'],
                                                        'offsets':[0, 16], # Introduce gap
                                                        'itemsize':32})
except (TypeError, ValueError):
    numpy_structured_array_offsets = numpy.array([(1,1.0)], dtype=[('f1', 'i4'), ('f2', 'f8')])

numpy_structured_array_empty_fields = numpy.array([(), ()], dtype=[])
numpy_structured_array_bool_field = numpy.array([(True,), (False,)], dtype=[('flag', '?')])


# --- String and Bytes Arrays ---
numpy_string_array_fixed = numpy.array(['abc', 'defg', 'hi'], dtype='S4')
numpy_string_array_unicode_fixed = numpy.array(['abc', 'defg', 'hi😀'], dtype='U4')
numpy_string_array_empty = numpy.array(['', '', ''], dtype='U1')
numpy_string_array_null_bytes = numpy.array(['a\\0b', 'c\\0d\\0e'], dtype='S0')
numpy_bytes_array_mixed_len_via_object = numpy.array([b'short', b'mediumlength', b'a\\0verylongbytestringindeed'], dtype=object)


# --- Boolean Arrays ---
numpy_bool_array_all_true = numpy.full((100,100), True, dtype=bool)
numpy_bool_array_all_false = numpy.zeros((3,3,3), dtype=bool)
numpy_bool_array_mixed = numpy.array([True, False, True, True, False], dtype=bool)


# --- Datetime and Timedelta Arrays ---
numpy_datetime64_array_mixed_units = numpy.array(['2000-01-01', '2001-01-01T12:00', '2002-01-01T12:30:30.123'], dtype='datetime64[us]')
numpy_datetime64_array_nat = numpy.array(['2000-01-01', 'NaT', '2002-01-01'], dtype='datetime64[Y]')
numpy_timedelta64_array_mixed_units = numpy.array([10, 20000, 30000000], dtype='timedelta64[ns]')
numpy_timedelta64_array_nat = numpy.array([10, numpy.timedelta64('NaT','D'), 30], dtype='timedelta64[D]')


# --- Endianness ---
numpy_big_endian_int32 = numpy.array([1, 2, 3], dtype='>i4')
numpy_little_endian_float64 = numpy.array([1.0, 2.0, 3.0], dtype='<f8')


# --- Non-Contiguous and Memory Layout ---
_base_arr_for_views = numpy.arange(24, dtype=numpy.int16).reshape((4,6))
numpy_non_contiguous_view_transpose = _base_arr_for_views.T
numpy_non_contiguous_view_step = _base_arr_for_views[::2, ::2]
numpy_c_contiguous_3d = numpy.arange(27, dtype=numpy.float32).reshape((3,3,3), order='C')
numpy_f_contiguous_3d = numpy.arange(27, dtype=numpy.float32).reshape((3,3,3), order='F')


# --- Read-Only Arrays ---
numpy_readonly_array_base = numpy.arange(10)
numpy_readonly_array_base.flags.writeable = False
numpy_readonly_array = numpy_readonly_array_base


# --- Zero-Dimensional Arrays (Scalars with dtype) ---
numpy_zerodim_int = numpy.array(101, dtype=numpy.int16)
numpy_zerodim_structured = numpy.array((1, 'ScalarStruct', 3.14),
                                dtype=[('id', 'i1'), ('tag', 'U20'), ('val', 'f4')])
numpy_zerodim_from_list = numpy.array([[[1]]], dtype=int).reshape(())


# --- Arrays with Zero-Sized Dimensions or All Ones ---
numpy_array_with_zero_size_dim = numpy.empty((5,0,5), dtype=numpy.float32)
numpy_array_all_dims_one = numpy.ones((1,1,1,1), dtype=numpy.int8)
numpy_array_order_k = numpy.array([[1,2],[3,4]], order='K')


# --- For Broadcasting ---
numpy_broadcastable_a = numpy.arange(4).reshape(4,1)
numpy_broadcastable_b = numpy.arange(3).reshape(1,3)

# --- Custom void dtype with various field types ---
numpy_custom_void_dtype_multiple_fields = numpy.array([
    (1, 0.5, 'Hello', True, b'data1', numpy.datetime64('2020-01-01'), numpy.timedelta64(10, 'D')),
    (2, 1.5, 'World', False, b'data2', numpy.datetime64('2021-02-03'), numpy.timedelta64(20, 's'))
], dtype=[('id', 'i4'), ('value', 'f8'), ('name', 'U10'), ('flag', '?'),
          ('bytes_val', 'S5'), ('timestamp', 'datetime64[D]'), ('duration', 'timedelta64[s]')])

# Clean up temporary variable if any were used that should not be in the final list
del _base_arr_for_views
del numpy_readonly_array_base


# Basic problematic arrays
numpy_zeros = numpy.zeros((2000, 2000))
numpy_nan = numpy.array([[numpy.nan] * 1000 for n in range(1000)])
numpy_very_large_int = numpy.array([factorial(x) for x in range(150, 250)])
numpy_very_large_float = numpy.array([factorial(x) for x in range(250, 350)], dtype=numpy.float128)
numpy_sys_max_float = numpy.array([sys.float_info.max] * 100)
numpy_sys_min_float = numpy.array([sys.float_info.min] * 100)

# Memory-intensive arrays that might cause allocation issues
# try:
#     numpy_huge_1d = numpy.ones(2**31 - 1, dtype=numpy.int8)  # Just under 2GB
# except (MemoryError, OverflowError):
#     numpy_huge_1d = numpy.ones(2**20, dtype=numpy.int8)  # Fallback to 1MB
#
# try:
#     numpy_huge_multidim = numpy.ones((10000, 10000), dtype=numpy.float64)  # ~800MB
# except MemoryError:
#     numpy_huge_multidim = numpy.ones((1000, 1000), dtype=numpy.float64)

# Zero-size and edge case arrays
numpy_zero_size = numpy.array([], dtype=numpy.float64).reshape((0, 5, 0))

# Create array with negative strides
base_array = numpy.arange(100)
numpy_negative_strides = base_array[::-2]  # Negative stride view

# Complex numbers with infinities and NaNs
numpy_complex_inf = numpy.array([complex(numpy.inf, numpy.nan),
                                complex(numpy.nan, numpy.inf),
                                complex(-numpy.inf, numpy.inf)])

numpy_complex_nan = numpy.array([complex(numpy.nan, numpy.nan)] * 1000)

# Datetime/timedelta edge cases
numpy_datetime_extremes = numpy.array(['1677-09-21', '2262-04-11'], dtype='datetime64[D]')
numpy_timedelta_extremes = numpy.array([numpy.timedelta64('NaT'),
                                       numpy.timedelta64(2**63-1, 'ns')], dtype='timedelta64[ns]')

# Mixed endianness arrays
big_endian = numpy.array([1, 2, 3, 4], dtype='>i4')
little_endian = numpy.array([1, 2, 3, 4], dtype='<i4')
numpy_mixed_endian = numpy.concatenate([big_endian.view(numpy.uint8),
                                       little_endian.view(numpy.uint8)])

# Unicode arrays with problematic content
numpy_unicode_mess = numpy.array(['\\x00\\xff\\xfe\\xfd', '\\U0001F4A9' * 1000,
                                 '\\uFFFE\\uFFFF', ''], dtype='U10000')

# Arrays designed to cause broadcast errors
try:
    a = numpy.ones((1000, 1))
    b = numpy.ones((1, 1000))
    numpy_broadcast_error = numpy.broadcast_arrays(a, b)
except (ValueError, MemoryError):
    numpy_broadcast_error = (numpy.array([1]), numpy.array([2]))

# Invalid reshape attempts
base = numpy.ones(100)
try:
    numpy_reshape_invalid = base.reshape(-1, -1)  # Multiple -1 dimensions
except ValueError:
    numpy_reshape_invalid = base.reshape(10, 10)

# Overlapping memory views that could cause data corruption
base_overlap = numpy.arange(100)
view1 = base_overlap[10:60]
view2 = base_overlap[40:90]
numpy_overlapping_views = [view1, view2, base_overlap]

# Circular references in object arrays
obj_array = numpy.empty(2, dtype=object)
obj_array[0] = obj_array
obj_array[1] = [obj_array, obj_array]
numpy_circular_references = obj_array

# Structured arrays with nested/complex dtypes
nested_dt = numpy.dtype([('a', [('x', 'i4'), ('y', 'f8', (3,))]),
                        ('b', 'U10'),
                        ('c', 'O')])
numpy_nested_struct = numpy.zeros(1000, dtype=nested_dt)

# Unaligned structured array
unaligned_dt = numpy.dtype([('a', 'i1'), ('b', 'f8')], align=False)  # Unaligned float64
numpy_unaligned_struct = numpy.zeros(1000, dtype=unaligned_dt)

# Structured array with huge field names
huge_field_dt = numpy.dtype([(f'field_{"x" * 1000}_{i}', 'i4') for i in range(100)])
try:
    numpy_huge_field_names = numpy.zeros(10, dtype=huge_field_dt)
except (ValueError, MemoryError):
    numpy_huge_field_names = numpy.zeros(1, dtype=[('a', 'i4')])

# Attempt to create recursive dtype (should fail but might crash)
try:
    recursive_dt = numpy.dtype([('self', 'O')])
    recursive_array = numpy.empty(1, dtype=recursive_dt)
    recursive_array['self'][0] = recursive_array
    numpy_recursive_dtype = recursive_array
except:
    numpy_recursive_dtype = numpy.array([None], dtype=object)

# Fortran-ordered arrays
numpy_fortran_order = numpy.asfortranarray(numpy.random.random((1000, 1000)))

# Discontiguous array views
base_discontig = numpy.arange(10000).reshape(100, 100)
numpy_discontiguous = base_discontig[::3, ::7]  # Non-contiguous strides

# Read-only array that we try to modify
readonly_array = numpy.arange(1000)
readonly_array.flags.writeable = False
numpy_readonly_violation = readonly_array

# Array with broken buffer interface
class BrokenBuffer:
    def __array_interface__(self):
        return {'version': 3, 'typestr': '<i4', 'shape': (10,), 'data': (0, False)}

    def __array__(self):
        return numpy.arange(10)

try:
    numpy_buffer_interface_broken = numpy.array(BrokenBuffer())
except:
    numpy_buffer_interface_broken = numpy.array([1, 2, 3])

# Mathematical operations that cause warnings/errors
numpy_divide_by_zero_array = numpy.array([1.0, 2.0, 3.0]) / numpy.array([0.0, 0.0, 0.0])

# Arrays designed to overflow/underflow
huge_vals = numpy.array([sys.float_info.max] * 100)
numpy_overflow_operations = huge_vals * huge_vals

tiny_vals = numpy.array([sys.float_info.min] * 100)
numpy_underflow_operations = tiny_vals / huge_vals

# Invalid mathematical operations
numpy_invalid_operations = numpy.sqrt(numpy.array([-1, -2, -3, -numpy.inf]))

# Random state corruption attempts
rng = numpy.random.default_rng()
try:
    # Try to corrupt internal state
    rng.bit_generator.state = {'state': {'state': numpy.zeros(624, dtype=numpy.uint32), 'pos': 625}}
    numpy_random_corrupt_state = rng.random(1000)
except:
    numpy_random_corrupt_state = numpy.random.random(1000)

# Masked arrays with problematic masks
try:
    data = numpy.arange(1000)
    mask = numpy.random.choice([True, False], 1000)
    masked = numpy.ma.masked_array(data, mask=mask)
    # Create circular reference in masked array
    masked.data = masked
    numpy_masked_array_broken = masked
except:
    numpy_masked_array_broken = numpy.ma.masked_array([1, 2, 3], mask=[True, False, True])

# Deprecated numpy.matrix with problematic operations
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PendingDeprecationWarning)
        mat = numpy.matrix([[1, 2], [3, 4]])
        # Try to create problematic matrix operations
        numpy_matrix_deprecated = mat ** -1
except:
    numpy_matrix_deprecated = numpy.array([[1, 2], [3, 4]])

# Polynomial with roots that are numerically unstable
coeffs = [1] + [0] * 50 + [1]  # x^51 + 1, has complex roots near unit circle
try:
    numpy_polynomial_roots_unstable = numpy.roots(coeffs)
except:
    numpy_polynomial_roots_unstable = numpy.array([1+0j])
