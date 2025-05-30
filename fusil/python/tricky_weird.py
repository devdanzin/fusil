"""
Tricky and Weird Objects

This module defines problematic Python objects, classes, and edge cases designed to
trigger bugs. It contains boundary values like maximum integers, weird classes,
circular references, and other pathological objects that can expose crashes and other
undesirable behavior in Python code and C extensions.
"""

from _decimal import Decimal
from collections import Counter, OrderedDict, deque
from queue import Queue

sequences = [Queue, deque, frozenset, list, set, str, tuple]
bytes_ = [bytearray, bytes]
numbers = [Decimal, complex, float, int]
dicts = [Counter, OrderedDict, dict]
# dicts = [OrderedDict, dict]
bases = sequences + bytes_ + numbers + dicts + [object]
weird_names = [f"weird_{cls.__name__}" for cls in bases]
weird_instance_names = [f"{name}_empty" for name in weird_names]

for x in range(3):
    for cls in sequences:
        weird_instance_names.append(f"weird_{cls.__name__}_single")
        weird_instance_names.append(f"weird_{cls.__name__}_range")
        weird_instance_names.append(f"weird_{cls.__name__}_types")
        weird_instance_names.append(f"weird_{cls.__name__}_printable")
        weird_instance_names.append(f"weird_{cls.__name__}_special")
    for cls in bytes_:
        weird_instance_names.append(f"weird_{cls.__name__}_bytes")
    for cls in dicts:
        weird_instance_names.append(f"weird_{cls.__name__}_basic")
        weird_instance_names.append(f"weird_{cls.__name__}_tricky_strs")

for cls in numbers:
    weird_instance_names.append(f"weird_{cls.__name__}_sys_maxsize")
    weird_instance_names.append(f"weird_{cls.__name__}_sys_maxsize_minus_one")
    weird_instance_names.append(f"weird_{cls.__name__}_sys_maxsize_plus_one")
    weird_instance_names.append(f"weird_{cls.__name__}_neg_sys_maxsize")
    weird_instance_names.append(f"weird_{cls.__name__}_2**63-1")
    weird_instance_names.append(f"weird_{cls.__name__}_2**63")
    weird_instance_names.append(f"weird_{cls.__name__}_2**63+1")
    weird_instance_names.append(f"weird_{cls.__name__}_-2**63+1")
    weird_instance_names.append(f"weird_{cls.__name__}_-2**63")
    weird_instance_names.append(f"weird_{cls.__name__}_-2**63-1")
    weird_instance_names.append(f"weird_{cls.__name__}_2**31-1")
    weird_instance_names.append(f"weird_{cls.__name__}_2**31")
    weird_instance_names.append(f"weird_{cls.__name__}_2**31+1")
    weird_instance_names.append(f"weird_{cls.__name__}_-2**31+1")
    weird_instance_names.append(f"weird_{cls.__name__}_-2**31")
    weird_instance_names.append(f"weird_{cls.__name__}_-2**31-1")
    if cls not in (float, complex):
        weird_instance_names.append(
            f"weird_{cls.__name__}_10**default_max_str_digits+1"
        )


weird_classes = """
from _collections import OrderedDict, deque
from abc import ABCMeta
from collections import Counter
from decimal import Decimal
from queue import Queue
from random import randint
from string import printable

sequences = [Queue, deque, frozenset, list, set, str, tuple]
bytes_ = [bytearray, bytes]
numbers = [Decimal, complex, float, int]
dicts = [Counter, OrderedDict, dict]
# dicts = [OrderedDict, dict]
bases = sequences + bytes_ + numbers + dicts + [object]

large_num = 2**64
class WeirdBase(ABCMeta):
  def __hash__(self):
    return randint(0, large_num)

  def __eq__(self, other):
    return False


weird_instances = dict()
weird_classes = dict()
for cls in bases:
    class weird_cls(cls, metaclass=WeirdBase):
        def add(self, *args, **kwargs):
            pass
        append = clear = close = write = sort = reversed = add
        def encode(self, *args, **kwargs):
            return b""
        def decode(self, *args, **kwargs):
            return ""
        format = getvalue = join = read = replace = strip = rstrip = decode
        def get(self, *args, **kwargs):
            return self
        open = pop = update = get
        def readlines(self, *args, **kwargs):
            return [""]
        rsplit = split = partition = rpartition = readlines
        def items(self):
            return {}.items()
        def keys(self):
            return {}.keys()
        def values(self):
            return {}.values()

    weird_cls.__name__ = f"weird_{cls.__name__}"
    weird_instances[f"weird_{cls.__name__}_empty"] = weird_cls()
    weird_classes[f"weird_{cls.__name__}"] = weird_cls

tricky_strs = (chr(0), chr(127), chr(255), chr(0x10FFFF), "𝒜","\\x00" * 10, "A" * (2 ** 16), "💻" * 2**10,)

for cls in sequences:
    weird_instances[f"weird_{cls.__name__}_single"] = weird_classes[f"weird_{cls.__name__}"]("a")
    weird_instances[f"weird_{cls.__name__}_range"] = weird_classes[f"weird_{cls.__name__}"](range(20))
    weird_instances[f"weird_{cls.__name__}_types"] = weird_classes[f"weird_{cls.__name__}"](bases)
    weird_instances[f"weird_{cls.__name__}_printable"] = weird_classes[f"weird_{cls.__name__}"](printable)
    weird_instances[f"weird_{cls.__name__}_special"] = weird_classes[f"weird_{cls.__name__}"](tricky_strs)
for cls in bytes_:
    weird_instances[f"weird_{cls.__name__}_bytes"] = weird_classes[f"weird_{cls.__name__}"](b"abcdefgh_" * 10)
for cls in numbers:
    weird_instances[f"weird_{cls.__name__}_sys_maxsize"] = weird_classes[f"weird_{cls.__name__}"](sys.maxsize)
    weird_instances[f"weird_{cls.__name__}_sys_maxsize_minus_one"] = weird_classes[f"weird_{cls.__name__}"](sys.maxsize - 1)
    weird_instances[f"weird_{cls.__name__}_sys_maxsize_plus_one"] = weird_classes[f"weird_{cls.__name__}"](sys.maxsize + 1)
    weird_instances[f"weird_{cls.__name__}_neg_sys_maxsize"] = weird_classes[f"weird_{cls.__name__}"](-sys.maxsize)
    weird_instances[f"weird_{cls.__name__}_2**63-1"] = weird_classes[f"weird_{cls.__name__}"](2 ** 63 - 1)
    weird_instances[f"weird_{cls.__name__}_2**63"] = weird_classes[f"weird_{cls.__name__}"](2 ** 63)
    weird_instances[f"weird_{cls.__name__}_2**63+1"] = weird_classes[f"weird_{cls.__name__}"](2 ** 63 + 1)
    weird_instances[f"weird_{cls.__name__}_-2**63+1"] = weird_classes[f"weird_{cls.__name__}"](-2 ** 63 + 1)
    weird_instances[f"weird_{cls.__name__}_-2**63"] = weird_classes[f"weird_{cls.__name__}"](-2 ** 63)
    weird_instances[f"weird_{cls.__name__}_-2**63-1"] = weird_classes[f"weird_{cls.__name__}"](-2 ** 63 -1)
    weird_instances[f"weird_{cls.__name__}_2**31-1"] = weird_classes[f"weird_{cls.__name__}"](2 ** 31 - 1)
    weird_instances[f"weird_{cls.__name__}_2**31"] = weird_classes[f"weird_{cls.__name__}"](2 ** 31)
    weird_instances[f"weird_{cls.__name__}_2**31+1"] = weird_classes[f"weird_{cls.__name__}"](2 ** 31 + 1)
    weird_instances[f"weird_{cls.__name__}_-2**31+1"] = weird_classes[f"weird_{cls.__name__}"](-2 ** 31 + 1)
    weird_instances[f"weird_{cls.__name__}_-2**31"] = weird_classes[f"weird_{cls.__name__}"](-2 ** 31)
    weird_instances[f"weird_{cls.__name__}_-2**31-1"] = weird_classes[f"weird_{cls.__name__}"](-2 ** 31 - 1)
    if cls not in (float, complex) and hasattr(sys, 'int_info'):
        weird_instances[f"weird_{cls.__name__}_10**default_max_str_digits+1"] = weird_classes[f"weird_{cls.__name__}"](10 ** (sys.int_info.default_max_str_digits + 1))
for cls in dicts:
    weird_instances[f"weird_{cls.__name__}_basic"] = weird_classes[f"weird_{cls.__name__}"]({a: a for a in range(100)})
    weird_instances[f"weird_{cls.__name__}_tricky_strs"] = weird_classes[f"weird_{cls.__name__}"]({a: a for a in tricky_strs})

"""
tricky_typing = """
import abc
import builtins
import collections.abc
import itertools
import types
import typing
from functools import reduce
from operator import or_

abc_types = [cls for cls in abc.__dict__.values() if isinstance(cls, type)]
builtins_types = [cls for cls in builtins.__dict__.values() if isinstance(cls, type)]
collections_abc_types = [cls for cls in collections.abc.__dict__.values() if isinstance(cls, type)]
collections_types = [cls for cls in collections.__dict__.values() if isinstance(cls, type)]
itertools_types = [cls for cls in itertools.__dict__.values() if isinstance(cls, type)]
types_types = [cls for cls in types.__dict__.values() if isinstance(cls, type)]
typing_types = [cls for cls in typing.__dict__.values() if isinstance(cls, type)]

all_types = (abc_types + builtins_types + collections_abc_types + collections_types + itertools_types
             + types_types + typing_types)
all_types = [t for t in all_types if not (isinstance(t, type) and issubclass(t, BaseException))]
big_union = reduce(or_, all_types, int)
"""
tricky_objects_names = [
    "TrickyDescriptor()",
    "TrickyMeta",
    "tricky_capsule",
    "tricky_cell",
    "tricky_classmethod",
    "tricky_classmethod_descriptor",
    "tricky_closure",
    "tricky_code",
    "tricky_dict",
    "tricky_frame",
    "tricky_function",
    # "tricky_generator",  # Triggers too many free-threading segfaults
    "tricky_genericalias",
    "tricky_instance",
    "tricky_lambda",
    "tricky_mappingproxy",
    "tricky_module",
    "tricky_module2",
    "tricky_property",
    "tricky_simplenamespace",
    "tricky_staticmethod",
    "tricky_traceback",
    "tricky_list_with_cycle",
]
tricky_objects = """
import types
import inspect
import itertools
tricky_cell = types.CellType(None)
tricky_simplenamespace = types.SimpleNamespace(dummy=None, cell=tricky_cell)
tricky_simplenamespace.dummy = tricky_simplenamespace
tricky_capsule = types.CapsuleType
tricky_module = types.ModuleType("tricky_module", "docs")
tricky_module2 = types.ModuleType("tricky_module2\\x00", "docs\\x00")
try:
    tricky_genericalias = types.GenericAlias(list, (int,))
except AttributeError:
    tricky_genericalias = None

tricky_dict = {}
if tricky_capsule: tricky_dict[tricky_capsule] = tricky_cell
if tricky_module: tricky_dict[tricky_module] = tricky_genericalias
tricky_dict["tricky_dict"] = tricky_dict
tricky_mappingproxy = types.MappingProxyType(tricky_dict)


def tricky_function(*args, **kwargs):
    if len(args) > 150: raise RecursionError("Fuzzer controlled depth")
    a = 1
    def b(x=a):
        v = x
        return v
    return tricky_function(*(args + (1,)), **kwargs)


tricky_lambda = lambda *args, **kwargs: tricky_lambda(*args, **kwargs)
tricky_classmethod = classmethod(tricky_lambda)
tricky_staticmethod = staticmethod(tricky_lambda)
tricky_property = property(tricky_lambda)
tricky_code = tricky_lambda.__code__
tricky_closure = tricky_function.__code__.co_freevars
tricky_classmethod_descriptor = types.ClassMethodDescriptorType # This is the type itself


class TrickyDescriptor:
    def __get__(self, obj, objtype=None):
        return self
    def __set__(self, obj, value):
        try:
            obj.__dict__["_value_descriptor"] = value
        except AttributeError:
            pass
    def __delete__(self, obj):
        try:
            del obj.__dict__["_value_descriptor"]
        except (AttributeError, KeyError):
            pass


class TrickyMeta(type):
    @property
    def __signature__(self):
        raise AttributeError("Signature denied by TrickyMeta")
    def __mro_entries__(self, bases):
        return (object,)
        #return super().__mro_entries__(bases)


class TrickyClass(metaclass=TrickyMeta):
    tricky_descriptor = TrickyDescriptor()

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        self._value_init = None

    def __getattr__(self, name):
        if name == "crash_on_getattr": raise ValueError("getattr manipulated")
        return self


tricky_instance = TrickyClass()
try:
    tricky_frame = inspect.currentframe()
    if tricky_frame: # currentframe() can be None
        tricky_frame.f_builtins.update(tricky_dict)
        tricky_frame.f_globals.update(tricky_dict)
        tricky_frame.f_locals.update(tricky_dict)
except RuntimeError:
    tricky_frame = None


try:
    1 / 0
except ZeroDivisionError as e:
    tricky_traceback = e.__traceback__
else:
    tricky_traceback = None


# tricky_generator = (x for x in itertools.count())
tricky_list_with_cycle = [[]] * 6 + []
tricky_list_with_cycle[0].append(tricky_list_with_cycle)
tricky_list_with_cycle[-1].append(tricky_list_with_cycle)
tricky_list_with_cycle.append(tricky_list_with_cycle)
if tricky_list_with_cycle[0] and tricky_list_with_cycle[0][0] is tricky_list_with_cycle:
    tricky_list_with_cycle[0][0].append(tricky_list_with_cycle)
"""
type_names = ("list", "tuple", "dict")

tricky_numpy_names = [
    "numpy_zeros_large",
    "numpy_ones_various_dtypes",
    "numpy_empty_int_1d",
    "numpy_empty_object_2d",
    "numpy_scalar_float64",
    "numpy_scalar_object_none",
    "numpy_arange_negative_step",
    "numpy_linspace_weird",
    "numpy_logspace_sizes",

    "numpy_nan_array",
    "numpy_inf_array",
    "numpy_neginf_array",
    "numpy_mixed_inf_nan_int_float",
    "numpy_complex_nan_inf",

    "numpy_factorial_int64",
    "numpy_factorial_float128",
    "numpy_sys_max_float_array",
    "numpy_sys_min_float_array",
    "numpy_float_subnormals",
    "numpy_float_boundaries",

    "numpy_object_array_mixed",
    "numpy_object_array_nested_lists",
    "numpy_object_array_none",

    "numpy_structured_array_simple",
    "numpy_structured_array_nested",
    "numpy_structured_array_offsets",
    "numpy_structured_array_empty_fields",
    "numpy_structured_array_bool_field",

    "numpy_string_array_fixed",
    "numpy_string_array_unicode_fixed",
    "numpy_string_array_empty",
    "numpy_string_array_null_bytes",
    "numpy_bytes_array_mixed_len_via_object",

    "numpy_bool_array_all_true",
    "numpy_bool_array_all_false",
    "numpy_bool_array_mixed",

    "numpy_datetime64_array_mixed_units",
    "numpy_datetime64_array_nat",
    "numpy_timedelta64_array_mixed_units",
    "numpy_timedelta64_array_nat",

    "numpy_big_endian_int32",
    "numpy_little_endian_float64",

    "numpy_non_contiguous_view_transpose",
    "numpy_non_contiguous_view_step",
    "numpy_c_contiguous_3d",
    "numpy_f_contiguous_3d",

    "numpy_readonly_array",
    # "numpy_writeable_object_array_with_readonly_elements",

    "numpy_zerodim_int",
    "numpy_zerodim_structured",
    "numpy_zerodim_from_list",

    "numpy_array_with_zero_size_dim",
    "numpy_array_all_dims_one",
    "numpy_array_order_k",
    "numpy_broadcastable_a",
    "numpy_broadcastable_b",

    "numpy_custom_void_dtype_multiple_fields",

    "numpy_zeros",
    "numpy_nan",
    "numpy_very_large_int",
    "numpy_very_large_float",
    "numpy_sys_max_float",
    "numpy_sys_min_float",
    # Memory-intensive arrays
    # "numpy_huge_1d",
    # "numpy_huge_multidim",
    "numpy_zero_size",
    "numpy_negative_strides",
    # Extreme dtypes and values
    "numpy_complex_inf",
    "numpy_complex_nan",
    "numpy_datetime_extremes",
    "numpy_timedelta_extremes",
    "numpy_mixed_endian",
    "numpy_unicode_mess",
    # Shape manipulation edge cases
    "numpy_broadcast_error",
    "numpy_reshape_invalid",
    "numpy_overlapping_views",
    "numpy_circular_references",
    # Structured arrays with problems
    "numpy_nested_struct",
    "numpy_unaligned_struct",
    "numpy_huge_field_names",
    "numpy_recursive_dtype",
    # Memory layout issues
    "numpy_fortran_order",
    "numpy_discontiguous",
    "numpy_readonly_violation",
    "numpy_buffer_interface_broken",
    # Mathematical edge cases
    "numpy_divide_by_zero_array",
    "numpy_overflow_operations",
    "numpy_underflow_operations",
    "numpy_invalid_operations",
    # Random/special arrays
    "numpy_random_corrupt_state",
    "numpy_masked_array_broken",
    "numpy_matrix_deprecated",
    "numpy_polynomial_roots_unstable",
]

tricky_numpy = """
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
"""


tricky_h5py_names = [
    # File objects
    "h5_file_readonly_core",
    "h5_file_libver_earliest",
    "h5_file_already_closed", # Reference to a closed file object

    # Group objects
    "h5_group_deeply_nested",
    "h5_group_with_long_name",
    "h5_group_with_unicode_name",
    "h5_group_with_many_attrs",
    "h5_group_with_cycle_softlink", # Softlink to itself

    # Dataset objects - Basic & Tricky Data
    "h5_dset_empty_int32",
    "h5_dset_scalar_object_none",
    "h5_dset_0d_from_numpy_zerodim_int", # Using a numpy tricky input
    "h5_dset_numpy_object_array_mixed",  # Using a numpy tricky input
    "h5_dset_all_zeros_chunked",
    "h5_dset_all_nans_compressed",
    "h5_dset_large_compressible_data",

    # Dataset objects - Shapes & Layout
    "h5_dset_high_rank",
    "h5_dset_one_dim_zero_size",
    "h5_dset_resizable_unlimited",
    "h5_dset_chunked_weird_shape", # Chunk shape not aligned or tiny
    "h5_dset_f_contiguous_source",

    # Dataset objects - Special dtypes
    "h5_dset_vlen_string_utf8",
    "h5_dset_vlen_bytes",
    "h5_dset_vlen_int_array",
    "h5_dset_enum_simple",
    "h5_dset_fixed_string_with_nulls",
    "h5_dset_structured_numpy_simple", # Using a numpy tricky input
    "h5_dset_structured_nested_numpy", # Using a numpy tricky input
    "h5_dset_object_references",
    "h5_dset_region_references",

    # Dataset objects - Features
    "h5_dset_with_fillvalue_nan",
    "h5_dset_with_fillvalue_tuple_struct", # Fillvalue for structured array
    "h5_dset_no_chunking_but_resizable", # Potentially problematic
    "h5_dset_scaleoffset_int16",
    "h5_dset_track_times_true",

    # AttributeManager objects (via a group)
    "h5_attrs_on_group_various_types",
    "h5_attrs_on_group_vlen_string",
    "h5_attrs_on_group_empty_numpy_array",

    # Datatype objects
    "h5_datatype_committed_vlen_str",
    "h5_datatype_committed_enum",
    "h5_datatype_from_structured_numpy", # Datatype object from a tricky numpy dtype

    # Links
    "h5_softlink_dangling",
    "h5_hardlink_to_dataset",

    # References (raw, not in datasets yet, might be less useful directly)
    "h5_ref_to_group",
    "h5_ref_to_dataset",
    "h5_regionref_on_dataset_slice",

    # Objects related to a specific file instance
    "h5_main_file_object_itself", # The main h5py.File instance

# Additions to tricky_h5py_names for File Configurations
    # Basic modes and states
    "h5_file_core_w_no_backing",          # 'w' mode, core, no backing
    "h5_file_core_r_no_backing_nonexist", # 'r' mode, core, no backing, non-existent (will be None after creation attempt)
    "h5_file_core_r_plus_with_backing",   # 'r+' mode, core, with backing (after creating it)
    "h5_file_core_w_minus_exclusive",     # 'w-' mode, core, no backing
    "h5_file_core_append_no_backing",     # 'a' mode, core, no backing
    "h5_file_closed_after_create",        # A file object that has been closed

    # Drivers and their options
    "h5_file_driver_stdio",               # Stdio driver (posix only)
    "h5_file_driver_sec2",                # Sec2 driver (posix only)
    "h5_file_driver_core_block_lg",       # Core, no backing, large block_size
    "h5_file_driver_core_backing_true",   # Core, with backing_store=True
    # "h5_file_driver_split",             # Split driver (creates multiple files, harder for self-contained) -  Might defer or handle carefully
    "h5_file_driver_fileobj",             # Uses an in-memory tempfile.TemporaryFile()

    # Libver settings
    "h5_file_libver_earliest_v108",
    "h5_file_libver_v110_latest",
    "h5_file_libver_latest_strict",       # ('latest', 'latest')

    # Userblock
    "h5_file_userblock_512",
    "h5_file_userblock_8192",
    # For testing errors:
    "h5_file_path_for_userblock_append_test", # A path to a file created with a userblock
    "h5_file_obj_for_userblock_append_test",  # The actual file object for the above

    # File Space Strategy & Page Buffering (some combinations)
    "h5_file_fs_page_persist_thresh",
    "h5_file_fs_page_with_page_buffer",
    "h5_file_fs_fsm",
    "h5_file_fs_aggregate",

    # SWMR
    "h5_file_swmr_enabled_latest",

    # Locking (basic presence, actual locking behavior is complex)
    "h5_file_locking_true",
    "h5_file_locking_best_effort",

    # Path types
    "h5_path_object_for_file_creation",   # A pathlib.Path object
    "h5_str_path_for_unicode_file_TEMP",  # A string path with unicode (temp file on disk)

    # For error testing with modes
    "h5_path_to_non_hdf5_file_TEMP",      # Path to a temp file with garbage data
    "h5_path_to_readonly_hdf5_file_TEMP", # Path to a temp HDF5 file made OS-readonly

# Additions to tricky_h5py_names for Core Dataset Creation Parameters
    "h5_dset_scalar_int",
    "h5_dset_shape_none_null_dataspace", # dtype only, shape=None
    "h5_dset_shape_zero_dim_1d",         # shape=(0,)
    "h5_dset_shape_zero_dim_2d",         # shape=(5,0)
    "h5_dset_autochunk_large_elements",  # chunks=True with large dtype to force small chunk tuple
    "h5_dset_chunked_oversized_chunks",  # Chunks larger than shape (error case)
    "h5_dset_chunked_irregular",         # Chunks=(7,13) for shape=(100,100)
    "h5_dset_no_chunks_but_maxshape",    # Error: chunks=False, maxshape=(None,)
    "h5_dset_fillvalue_custom_int",
    "h5_dset_fillvalue_float_nan",
    "h5_dset_filltime_never_float",      # Read uninitialized data
    "h5_dset_filltime_alloc_int",
    "h5_dset_compress_gzip_high",
    "h5_dset_compress_lzf",
    # "h5_dset_compress_szip_ec16", # Requires SZip to be available
    "h5_dset_compress_shuffle_gzip",
    "h5_dset_compress_fletcher32",
    "h5_dset_compress_scaleoffset_int_auto", # scaleoffset=True
    "h5_dset_compress_scaleoffset_int_bits", # scaleoffset=<nbits>
    "h5_dset_compress_scaleoffset_float_factor_chunked", # scaleoffset=<factor_int>
    "h5_dset_resizable_1d_unlimited",    # maxshape=(None,)
    "h5_dset_resizable_2d_mixed",      # maxshape=(100, None)
    "h5_dset_initially_zero_resizable",  # shape=(0,5), maxshape=(None,5)
    "h5_dset_track_times_false",
    "h5_dset_created_from_data_implicit_shape",
    "h5_dset_created_from_data_reshaped",
    "h5_dset_created_with_h5py_empty",

# Additions to tricky_h5py_names for Advanced/Tricky Dataset Datatypes
    "h5_dset_fixed_ascii_S10_with_nulls",
    "h5_dset_fixed_utf8_len20_special_chars", # Using h5py.string_dtype
    "h5_dset_vlen_ascii_basic",
    "h5_dset_vlen_utf8_mixed_scripts",
    "h5_dset_vlen_int32_array",
    "h5_dset_vlen_float16_array",
    "h5_dset_vlen_bool_array",
    "h5_dset_2d_vlen_int_variable_lengths",
    "h5_dset_enum_rgb_int8",
    "h5_dset_enum_status_str_keys_int_vals", # Enum with string keys
    "h5_dset_compound_basic_mixed_types",
    "h5_dset_compound_with_array_field",    # e.g., ('sensor_readings', '(10,)f4')
    "h5_dset_compound_with_vlen_str_field",
    "h5_dset_compound_with_vlen_int_field",
    "h5_dset_compound_nested_compound",
    "h5_dset_compound_with_ref_field",      # Field of h5py.ref_dtype
    "h5_dset_compound_with_regionref_field",
    "h5_dset_array_dtype_3x2_int16",
    "h5_dset_object_references_standalone", # Dataset of just h5py.Reference
    "h5_dset_region_references_standalone", # Dataset of just h5py.RegionReference
    "h5_dset_from_committed_compound_type",
    "h5_dset_from_committed_vlen_type",
    "h5_dset_empty_vlen_str",             # Dataset with VLEN str dtype but no elements
    "h5_dset_empty_compound",             # Dataset with Compound dtype but no elements
# Additions to tricky_h5py_names for Dataset Operations
    "h5_dset_for_read_direct_source",       # A dataset with known data to read from
    "h5_dset_for_write_direct_dest_simple", # A simple dataset to be a target for write_direct
    "h5_dset_for_fancy_indexing_setitem", # Shape suitable for arr[:, [idx], ...] =
    "h5_dset_for_iteration_2d",
    "h5_dset_scalar_for_iteration_error",
    "h5_dset_for_astype_simple_int",
    "h5_dset_for_asstr_fixed_ascii",
    "h5_dset_chunked_for_iter_chunks",
    "h5_dset_for_comparisons_float",
    # Views returned by methods could also be added if "deep diving" is implemented
    # e.g., "h5_dataset_fields_view_from_compound" (though these are harder to pre-define)
]

tricky_h5py_code = """
import uuid # For unique names where needed
import h5py

from fusil.python.tricky_weird import tricky_h5py_names

# Keep file objects alive globally within the execution of this code string
# The fuzzer's generated script will then hold references to objects from h5py_tricky_objects,
# implicitly keeping these files alive if objects are still bound.
_h5_internal_files_to_keep_open_ = []
h5py_tricky_objects = {}
h5py_runtime_objects = {}

def _h5_unique_name(base="item"):
    return f"{base}_{uuid.uuid4().hex[:8]}"

def _h5_create_core_file(name_suffix="", mode='a', **kwargs):
    # Create a new in-memory HDF5 file for each call to avoid name clashes
    # and to allow testing different file properties.
    fname = f"tricky_h5_core_{name_suffix}_{uuid.uuid4().hex}.h5"
    try:
        file_obj = h5py.File(fname, mode=mode, driver='core', backing_store=False, **kwargs)
        _h5_internal_files_to_keep_open_.append(file_obj)
        return file_obj
    except Exception as e:
        print(f"H5PY_TRICKY_WARN: Failed to create in-memory HDF5 file {fname} with mode {mode}: {e}", file=sys.stderr)
        return None

# --- Main file for most objects, created with 'a' mode ---
_h5_main_file = _h5_create_core_file(name_suffix="main")
h5py_tricky_objects['h5_main_file_object_itself'] = _h5_main_file

# --- Other File Objects ---
try:
    h5py_tricky_objects['h5_file_readonly_core'] = _h5_create_core_file(name_suffix="readonly_setup", mode='w')
    if h5py_tricky_objects['h5_file_readonly_core']:
        h5py_tricky_objects['h5_file_readonly_core'].create_dataset("dummy", data=1)
        h5py_tricky_objects['h5_file_readonly_core'].close() # Close it
        # Reopen in read-only. The original object is closed. We need a new one.
        _ro_fname = _h5_internal_files_to_keep_open_[-1].name # Get the unique name
        h5py_tricky_objects['h5_file_readonly_core'] = h5py.File(_ro_fname, mode='r', driver='core', backing_store=False)
        _h5_internal_files_to_keep_open_.append(h5py_tricky_objects['h5_file_readonly_core']) # Keep new handle
    else: # Fallback
         h5py_tricky_objects['h5_file_readonly_core'] = None
except Exception as e:
    print(f"H5PY_TRICKY_WARN: readonly_core setup failed: {e}", file=sys.stderr)
    h5py_tricky_objects['h5_file_readonly_core'] = None

try:
    h5py_tricky_objects['h5_file_libver_earliest'] = _h5_create_core_file(name_suffix="libver_early", libver='earliest')
except Exception as e:
    h5py_tricky_objects['h5_file_libver_earliest'] = None

try:
    _temp_closed_file = _h5_create_core_file(name_suffix="toclose")
    if _temp_closed_file:
        h5py_tricky_objects['h5_file_already_closed'] = _temp_closed_file
        _temp_closed_file.close() # Now the object in the dict is a closed file
    else:
        h5py_tricky_objects['h5_file_already_closed'] = None
except Exception as e:
    h5py_tricky_objects['h5_file_already_closed'] = None


if _h5_main_file:
    # --- Group Objects ---
    try:
        _g_deep_path = '/'.join([_h5_unique_name(f'g{i}') for i in range(10)]) # 10 levels deep
        h5py_tricky_objects['h5_group_deeply_nested'] = _h5_main_file.create_group(_g_deep_path)
    except Exception as e: h5py_tricky_objects['h5_group_deeply_nested'] = None
    try:
        _long_name = 'g_' + 'x' * 250
        h5py_tricky_objects['h5_group_with_long_name'] = _h5_main_file.create_group(_long_name)
    except Exception as e: h5py_tricky_objects['h5_group_with_long_name'] = None
    try:
        _unicode_name = _h5_unique_name('g_😀_你好_অ')
        h5py_tricky_objects['h5_group_with_unicode_name'] = _h5_main_file.create_group(_unicode_name)
    except Exception as e: h5py_tricky_objects['h5_group_with_unicode_name'] = None

    try:
        _g_many_attrs_name = _h5_unique_name('g_many_attrs')
        _g_many_attrs = _h5_main_file.create_group(_g_many_attrs_name)
        for i in range(50): _g_many_attrs.attrs[f'attr_{i}'] = i
        h5py_tricky_objects['h5_group_with_many_attrs'] = _g_many_attrs
    except Exception as e: h5py_tricky_objects['h5_group_with_many_attrs'] = None

    try:
        _g_cycle_name = _h5_unique_name('g_cycle')
        _g_cycle = _h5_main_file.create_group(_g_cycle_name)
        _g_cycle['link_to_self'] = h5py.SoftLink(f'/{_g_cycle_name}')
        h5py_tricky_objects['h5_group_with_cycle_softlink'] = _g_cycle
    except Exception as e: h5py_tricky_objects['h5_group_with_cycle_softlink'] = None


    # --- Dataset Objects - Basic & Tricky Data ---
    try:
        h5py_tricky_objects['h5_dset_empty_int32'] = _h5_main_file.create_dataset(_h5_unique_name('dset_empty_i32'), data=numpy.array([], dtype=numpy.int32))
    except Exception as e: h5py_tricky_objects['h5_dset_empty_int32'] = None
    try:
        h5py_tricky_objects['h5_dset_scalar_object_none'] = _h5_main_file.create_dataset(_h5_unique_name('dset_scalar_obj_none'), data=numpy.array(None, dtype=object))
    except Exception as e: h5py_tricky_objects['h5_dset_scalar_object_none'] = None
    try: # Assumes numpy_zerodim_int is defined by tricky_numpy code
        h5py_tricky_objects['h5_dset_0d_from_numpy_zerodim_int'] = _h5_main_file.create_dataset(_h5_unique_name('dset_0d_np_0d'), data=numpy_zerodim_int)
    except Exception as e: h5py_tricky_objects['h5_dset_0d_from_numpy_zerodim_int'] = None
    try: # Assumes numpy_object_array_mixed is defined
        h5py_tricky_objects['h5_dset_numpy_object_array_mixed'] = _h5_main_file.create_dataset(_h5_unique_name('dset_np_obj_mix'), data=numpy_object_array_mixed)
    except Exception as e: h5py_tricky_objects['h5_dset_numpy_object_array_mixed'] = None
    try:
        _d_zeros_name = _h5_unique_name('dset_zeros_chunk')
        h5py_tricky_objects['h5_dset_all_zeros_chunked'] = _h5_main_file.create_dataset(_d_zeros_name, shape=(100,100), dtype=numpy.int8, chunks=(10,10), fillvalue=0)
    except Exception as e: h5py_tricky_objects['h5_dset_all_zeros_chunked'] = None
    try:
        _d_nans_name = _h5_unique_name('dset_nans_gz')
        _data_nans = numpy.full((50,50), numpy.nan, dtype=numpy.float32)
        h5py_tricky_objects['h5_dset_all_nans_compressed'] = _h5_main_file.create_dataset(_d_nans_name, data=_data_nans, compression='gzip')
    except Exception as e: h5py_tricky_objects['h5_dset_all_nans_compressed'] = None
    try:
        _d_large_comp_name = _h5_unique_name('dset_large_comp')
        _data_large_comp = numpy.zeros(1024*1024, dtype=numpy.int64) # 8MB of zeros
        _data_large_comp[::100] = numpy.arange(len(_data_large_comp[::100])) # Some non-zero data
        h5py_tricky_objects['h5_dset_large_compressible_data'] = _h5_main_file.create_dataset(_d_large_comp_name, data=_data_large_comp, compression='lzf', chunks=(1024,))
    except Exception as e: h5py_tricky_objects['h5_dset_large_compressible_data'] = None

    # --- Dataset Objects - Shapes & Layout ---
    try:
        h5py_tricky_objects['h5_dset_high_rank'] = _h5_main_file.create_dataset(_h5_unique_name('dset_high_rank'), shape=(2,2,2,2,2,2), dtype='i1') # Rank 6
    except Exception as e: h5py_tricky_objects['h5_dset_high_rank'] = None
    try:
        h5py_tricky_objects['h5_dset_one_dim_zero_size'] = _h5_main_file.create_dataset(_h5_unique_name('dset_dim_zero'), shape=(10,0,10), dtype='f4')
    except Exception as e: h5py_tricky_objects['h5_dset_one_dim_zero_size'] = None
    try:
        _d_resize_name = _h5_unique_name('dset_resize')
        h5py_tricky_objects['h5_dset_resizable_unlimited'] = _h5_main_file.create_dataset(_d_resize_name, shape=(10,), maxshape=(None,), dtype='i2', chunks=(5,))
    except Exception as e: h5py_tricky_objects['h5_dset_resizable_unlimited'] = None
    try:
        _d_chunk_weird_name = _h5_unique_name('dset_chunk_weird')
        h5py_tricky_objects['h5_dset_chunked_weird_shape'] = _h5_main_file.create_dataset(_d_chunk_weird_name, shape=(100,100), dtype='u1', chunks=(7, 13)) # Chunks not divisors
    except Exception as e: h5py_tricky_objects['h5_dset_chunked_weird_shape'] = None
    try:
        _data_f_contig = numpy.array(numpy.arange(12).reshape(3,4), order='F')
        h5py_tricky_objects['h5_dset_f_contiguous_source'] = _h5_main_file.create_dataset(_h5_unique_name('dset_f_contig'), data=_data_f_contig)
    except Exception as e: h5py_tricky_objects['h5_dset_f_contiguous_source'] = None


    # --- Dataset Objects - Special dtypes ---
    try:
        _vlen_str_type = h5py.special_dtype(vlen=str)
        _data_vlen_str = numpy.array(['short', 'medium string', 'a very long string with unicode 😀你好অ'], dtype=_vlen_str_type)
        h5py_tricky_objects['h5_dset_vlen_string_utf8'] = _h5_main_file.create_dataset(_h5_unique_name('dset_vlen_str'), data=_data_vlen_str)
    except Exception as e: h5py_tricky_objects['h5_dset_vlen_string_utf8'] = None
    try:
        _vlen_bytes_type = h5py.special_dtype(vlen=bytes)
        _data_vlen_bytes = numpy.array([b'short', b'medium bytes', b'a\\x00very long\\xff'], dtype=_vlen_bytes_type)
        h5py_tricky_objects['h5_dset_vlen_bytes'] = _h5_main_file.create_dataset(_h5_unique_name('dset_vlen_bytes'), data=_data_vlen_bytes)
    except Exception as e: h5py_tricky_objects['h5_dset_vlen_bytes'] = None
    try:
        _vlen_int_array_type = h5py.special_dtype(vlen=numpy.dtype('i4'))
        _data_vlen_int = numpy.empty(3, dtype=_vlen_int_array_type)
        _data_vlen_int[0] = numpy.array([1,2,3])
        _data_vlen_int[1] = numpy.array([])
        _data_vlen_int[2] = numpy.arange(100)
        h5py_tricky_objects['h5_dset_vlen_int_array'] = _h5_main_file.create_dataset(_h5_unique_name('dset_vlen_intarr'), data=_data_vlen_int)
    except Exception as e: h5py_tricky_objects['h5_dset_vlen_int_array'] = None
    try:
        _enum_type = h5py.enum_dtype({'RED':0, 'GREEN':1, 'BLUE':2}, basetype='i1')
        _data_enum = numpy.array([0,1,2,0,1], dtype=_enum_type)
        h5py_tricky_objects['h5_dset_enum_simple'] = _h5_main_file.create_dataset(_h5_unique_name('dset_enum'), data=_data_enum)
    except Exception as e: h5py_tricky_objects['h5_dset_enum_simple'] = None
    try:
        _fixed_str_dt = h5py.string_dtype(encoding='ascii', length=10)
        _data_fixed_str = numpy.array(['abc\\0def', 'next'], dtype=_fixed_str_dt)
        h5py_tricky_objects['h5_dset_fixed_string_with_nulls'] = _h5_main_file.create_dataset(_h5_unique_name('dset_fixed_str_null'), data=_data_fixed_str)
    except Exception as e: h5py_tricky_objects['h5_dset_fixed_string_with_nulls'] = None
    try: # Assumes numpy_structured_array_simple defined by tricky_numpy
        h5py_tricky_objects['h5_dset_structured_numpy_simple'] = _h5_main_file.create_dataset(_h5_unique_name('dset_np_struct_simple'), data=numpy_structured_array_simple)
    except Exception as e: h5py_tricky_objects['h5_dset_structured_numpy_simple'] = None
    try: # Assumes numpy_structured_array_nested defined
        h5py_tricky_objects['h5_dset_structured_nested_numpy'] = _h5_main_file.create_dataset(_h5_unique_name('dset_np_struct_nested'), data=numpy_structured_array_nested)
    except Exception as e: h5py_tricky_objects['h5_dset_structured_nested_numpy'] = None

    _ref_target_group = _h5_main_file.create_group(_h5_unique_name('ref_target_group'))
    _ref_target_dset = _h5_main_file.create_dataset(_h5_unique_name('ref_target_dset'), data=numpy.arange(10))
    try:
        _obj_ref_dt = h5py.ref_dtype
        _data_obj_ref = numpy.array([_ref_target_group.ref, _ref_target_dset.ref, None], dtype=_obj_ref_dt) # None for null ref
        h5py_tricky_objects['h5_dset_object_references'] = _h5_main_file.create_dataset(_h5_unique_name('dset_obj_refs'), data=_data_obj_ref)
    except Exception as e: h5py_tricky_objects['h5_dset_object_references'] = None
    try:
        _reg_ref_dt = h5py.regionref_dtype
        _data_reg_ref = numpy.empty((2,), dtype=_reg_ref_dt)
        _data_reg_ref[0] = _ref_target_dset.regionref[0:5]
        _data_reg_ref[1] = _ref_target_dset.regionref[...] # Full dataset
        h5py_tricky_objects['h5_dset_region_references'] = _h5_main_file.create_dataset(_h5_unique_name('dset_reg_refs'), data=_data_reg_ref)
    except Exception as e: h5py_tricky_objects['h5_dset_region_references'] = None


    # --- Dataset Objects - Features ---
    try:
        h5py_tricky_objects['h5_dset_with_fillvalue_nan'] = _h5_main_file.create_dataset(_h5_unique_name('dset_fill_nan'), shape=(10,10), dtype='f4', fillvalue=numpy.nan)
    except Exception as e: h5py_tricky_objects['h5_dset_with_fillvalue_nan'] = None
    try:
        _struct_dt_for_fill = numpy.dtype([('a', 'i4'), ('b', 'f8')])
        _fill_tuple = (numpy.iinfo('i4').min, numpy.finfo('f8').max) # Min int, max float
        h5py_tricky_objects['h5_dset_with_fillvalue_tuple_struct'] = _h5_main_file.create_dataset(_h5_unique_name('dset_fill_struct'), shape=(5,), dtype=_struct_dt_for_fill, fillvalue=_fill_tuple)
    except Exception as e: h5py_tricky_objects['h5_dset_with_fillvalue_tuple_struct'] = None
    try: # Create resizable without chunks (allowed, but might be edge case for some operations)
        h5py_tricky_objects['h5_dset_no_chunking_but_resizable'] = _h5_main_file.create_dataset(_h5_unique_name('dset_resize_nochunks'), shape=(10,), maxshape=(None,), chunks=None)
    except Exception as e: h5py_tricky_objects['h5_dset_no_chunking_but_resizable'] = None
    try:
        h5py_tricky_objects['h5_dset_scaleoffset_int16'] = _h5_main_file.create_dataset(_h5_unique_name('dset_scaleoffset'), shape=(100,), dtype='i2', scaleoffset=3, chunks=(10,)) # scaleoffset needs chunks
    except Exception as e: h5py_tricky_objects['h5_dset_scaleoffset_int16'] = None
    try:
        h5py_tricky_objects['h5_dset_track_times_true'] = _h5_main_file.create_dataset(_h5_unique_name('dset_track_times'), data=[1,2,3], track_times=True)
    except Exception as e: h5py_tricky_objects['h5_dset_track_times_true'] = None


    # --- AttributeManager objects (via a group) ---
    _g_for_attrs = _h5_main_file.create_group(_h5_unique_name('g_for_attrs'))
    h5py_tricky_objects['h5_attrs_on_group_various_types'] = _g_for_attrs.attrs
    try:
        _g_for_attrs.attrs['attr_int'] = 100
        _g_for_attrs.attrs['attr_float'] = 3.14
        _g_for_attrs.attrs['attr_str'] = "hello attribute"
        _g_for_attrs.attrs['attr_bool'] = True
        _g_for_attrs.attrs['attr_numpy_scalar'] = numpy.int64(12345)
        _g_for_attrs.attrs['attr_numpy_array'] = numpy.arange(5)
        _g_for_attrs.attrs['attr_empty_str'] = ""
        _g_for_attrs.attrs['attr_bytes'] = b"byte_attr\\x00"
    except Exception as e: pass # Errors in attr creation are part of the fuzz
    try:
        _vlen_str_attr_type = h5py.special_dtype(vlen=str)
        _g_for_attrs.attrs.create('attr_vlen_str', data="vlen attribute string", dtype=_vlen_str_attr_type)
        h5py_tricky_objects['h5_attrs_on_group_vlen_string'] = _g_for_attrs.attrs # Re-assign
    except Exception as e: h5py_tricky_objects['h5_attrs_on_group_vlen_string'] = None # Fallback if create fails
    try:
        _g_for_attrs.attrs['attr_empty_numpy_array'] = numpy.array([])
        h5py_tricky_objects['h5_attrs_on_group_empty_numpy_array'] = _g_for_attrs.attrs # Re-assign
    except Exception as e: h5py_tricky_objects['h5_attrs_on_group_empty_numpy_array'] = None


    # --- Datatype objects ---
    try:
        _committed_vlen_str_dt = h5py.special_dtype(vlen=str)
        _h5_main_file[_h5_unique_name('type_vlen_str')] = _committed_vlen_str_dt
        h5py_tricky_objects['h5_datatype_committed_vlen_str'] = _committed_vlen_str_dt
    except Exception as e: h5py_tricky_objects['h5_datatype_committed_vlen_str'] = None
    try:
        _committed_enum_dt = h5py.enum_dtype({'X':10, 'Y':20, 'Z':-1}, basetype='i2')
        _h5_main_file[_h5_unique_name('type_enum')] = _committed_enum_dt
        h5py_tricky_objects['h5_datatype_committed_enum'] = _committed_enum_dt
    except Exception as e: h5py_tricky_objects['h5_datatype_committed_enum'] = None
    try: # Assumes numpy_structured_array_nested is defined
        _dt_from_numpy = h5py.Datatype(numpy_structured_array_nested.dtype)
        _h5_main_file[_h5_unique_name('type_from_np')] = _dt_from_numpy
        h5py_tricky_objects['h5_datatype_from_structured_numpy'] = _dt_from_numpy
    except Exception as e: h5py_tricky_objects['h5_datatype_from_structured_numpy'] = None


    # --- Links ---
    try:
        _h5_main_file[_h5_unique_name('softlink_dangling')] = h5py.SoftLink('/does/not/exist')
        h5py_tricky_objects['h5_softlink_dangling'] = _h5_main_file[_h5_unique_name('softlink_dangling')]
    except Exception as e: h5py_tricky_objects['h5_softlink_dangling'] = None
    try:
        _target_for_hardlink = _h5_main_file.create_dataset(_h5_unique_name('dset_for_hardlink'), data=42)
        _h5_main_file[_h5_unique_name('hardlink')] = _target_for_hardlink # Creates a hardlink
        h5py_tricky_objects['h5_hardlink_to_dataset'] = _h5_main_file[_h5_unique_name('hardlink')]
    except Exception as e: h5py_tricky_objects['h5_hardlink_to_dataset'] = None


    # --- References (raw h5py.Reference objects) ---
    try:
        h5py_tricky_objects['h5_ref_to_group'] = _ref_target_group.ref if _ref_target_group else None
    except Exception as e: h5py_tricky_objects['h5_ref_to_group'] = None
    try:
        h5py_tricky_objects['h5_ref_to_dataset'] = _ref_target_dset.ref if _ref_target_dset else None
    except Exception as e: h5py_tricky_objects['h5_ref_to_dataset'] = None
    try:
        h5py_tricky_objects['h5_regionref_on_dataset_slice'] = _ref_target_dset.regionref[1:3] if _ref_target_dset else None
    except Exception as e: h5py_tricky_objects['h5_regionref_on_dataset_slice'] = None

else: # Fallback if _h5_main_file is None
    print("H5PY_TRICKY_ERROR: Main HDF5 file for tricky objects could not be created. Most h5py objects will be None.", file=sys.stderr)
    for name in tricky_h5py_names:
        if name not in h5py_tricky_objects: # Avoid overwriting file objects if they were attempted
            h5py_tricky_objects[name] = None


# --- Additions to tricky_h5py_code for File Configurations ---

import h5py
import numpy
import uuid
import sys
import os
import stat
import tempfile
import pathlib

# _h5_internal_files_to_keep_open_ and h5py_tricky_objects assumed to be defined
# _h5_create_core_file(name_suffix="", mode='a', **kwargs) assumed to be defined

# Helper to create a temporary file on disk for specific tests
_h5_temp_files_created_on_disk_ = []
def _h5_create_disk_temp_file(suffix='.h5', content=None):
    fd, fname = tempfile.mkstemp(suffix=suffix, prefix="h5py_fuzz_temp_")
    os.close(fd)
    if content is not None:
        with open(fname, 'wb') as f:
            f.write(content)
    _h5_temp_files_created_on_disk_.append(fname) # Track for cleanup
    return fname

# --- Basic modes and states ---
try:
    h5py_tricky_objects["h5_file_core_w_no_backing"] = _h5_create_core_file(name_suffix="core_w_nb", mode='w', backing_store=False)
except Exception as e: h5py_tricky_objects["h5_file_core_w_no_backing"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    # Attempting to open a non-existent file in 'r' mode will fail. Store None.
    # The fuzzer can try to use this path with h5py.File(path, 'r')
    _non_existent_path = f"non_existent_core_{uuid.uuid4().hex}.h5"
    h5py_tricky_objects["h5_file_core_r_no_backing_nonexist"] = _non_existent_path # Store the path
except Exception as e: h5py_tricky_objects["h5_file_core_r_no_backing_nonexist"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    _fname_r_plus_backing = _h5_create_disk_temp_file(suffix="_r_plus_backing.h5") # Needs a real file for r+
    with h5py.File(_fname_r_plus_backing, 'w') as f_init: f_init.create_group("init_group") # Ensure it's a valid HDF5
    # We store the path, fuzzer will try to open it. Or we open and store handle.
    # For consistency, let's store an open handle if possible, using core driver.
    # However, 'r+' typically implies an existing file on disk.
    # Let's store the path, and the fuzzer can try h5py.File(path, 'r+')
    # For an in-memory with 'r+' like behavior, we'd open 'a' or 'w' then use it.
    # The original 'tricky_h5py_code' makes one main in-memory file.
    # To test 'r+' properly, it implies an *existing* file.
    # Let's make a file that's intended to be reopened.
    _file_for_rplus = _h5_create_core_file(name_suffix="for_rplus", mode='w', backing_store=True) # backing_store=True means it *could* be flushed
    if _file_for_rplus: _file_for_rplus.create_dataset("data", data=123)
    # The tricky object could be the name of this file, or a handle reopened in r+
    # For now, let's assume the fuzzer will use this object (which is in r/w) and test r+ semantics.
    # Or, more directly for testing 'r+':
    if _file_for_rplus:
         _file_for_rplus.flush()
         _file_for_rplus.close() # Close it
         # Now try to reopen it in 'r+' mode using its name
         h5py_tricky_objects["h5_file_core_r_plus_with_backing"] = h5py.File(_file_for_rplus.name, 'r+', driver='core')
         _h5_internal_files_to_keep_open_.append(h5py_tricky_objects["h5_file_core_r_plus_with_backing"])
    else:
        h5py_tricky_objects["h5_file_core_r_plus_with_backing"] = None
except Exception as e: h5py_tricky_objects["h5_file_core_r_plus_with_backing"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)


try:
    h5py_tricky_objects["h5_file_core_w_minus_exclusive"] = _h5_create_core_file(name_suffix="core_w_excl", mode='w-', backing_store=False)
    # Second attempt with same name (if _h5_create_core_file doesn't guarantee unique names for this test)
    # This is tricky because _h5_create_core_file uses UUID. This test would be better with fixed name.
    # For now, this object is simply one created with 'w-'. The fuzzer can try creating another with same logical name.
except Exception as e: h5py_tricky_objects["h5_file_core_w_minus_exclusive"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    h5py_tricky_objects["h5_file_core_append_no_backing"] = _h5_create_core_file(name_suffix="core_a_nb", mode='a', backing_store=False)
except Exception as e: h5py_tricky_objects["h5_file_core_append_no_backing"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    _closed_f = _h5_create_core_file(name_suffix="closed_temp", mode='w')
    if _closed_f:
        _closed_f.create_group("test")
        _closed_f.close() # Explicitly close
        h5py_tricky_objects["h5_file_closed_after_create"] = _closed_f # Store the closed handle
    else:
        h5py_tricky_objects["h5_file_closed_after_create"] = None
except Exception as e: h5py_tricky_objects["h5_file_closed_after_create"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

# --- Drivers ---
_is_posix = os.name == 'posix'
try:
    if _is_posix:
        h5py_tricky_objects["h5_file_driver_stdio"] = _h5_create_core_file(name_suffix="drv_stdio", mode='w', driver='stdio') # stdio needs real file
    else: h5py_tricky_objects["h5_file_driver_stdio"] = None # Placeholder
except Exception as e: h5py_tricky_objects["h5_file_driver_stdio"] = None; print(f"H5_A_WARN: stdio driver {e}", file=sys.stderr)
try:
    if _is_posix:
        h5py_tricky_objects["h5_file_driver_sec2"] = _h5_create_core_file(name_suffix="drv_sec2", mode='w', driver='sec2')
    else: h5py_tricky_objects["h5_file_driver_sec2"] = None # Placeholder
except Exception as e: h5py_tricky_objects["h5_file_driver_sec2"] = None; print(f"H5_A_WARN: sec2 driver {e}", file=sys.stderr)

try:
    h5py_tricky_objects["h5_file_driver_core_block_lg"] = _h5_create_core_file(name_suffix="core_lg_block", mode='w', driver='core', backing_store=False, block_size=65536)
except Exception as e: h5py_tricky_objects["h5_file_driver_core_block_lg"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    h5py_tricky_objects["h5_file_driver_core_backing_true"] = _h5_create_core_file(name_suffix="core_backing_t", mode='w', driver='core', backing_store=True)
except Exception as e: h5py_tricky_objects["h5_file_driver_core_backing_true"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    _temp_file_for_fileobj = tempfile.TemporaryFile() # This is an OS file handle
    h5py_tricky_objects["h5_file_driver_fileobj"] = h5py.File(_temp_file_for_fileobj, 'w') # H5py takes ownership if mode is w/a
    _h5_internal_files_to_keep_open_.append(h5py_tricky_objects["h5_file_driver_fileobj"]) # Keep it alive
except Exception as e: h5py_tricky_objects["h5_file_driver_fileobj"] = None; print(f"H5_A_WARN: fileobj driver {e}", file=sys.stderr)


# --- Libver settings ---
try:
    h5py_tricky_objects["h5_file_libver_earliest_v108"] = _h5_create_core_file(name_suffix="libver_e_108", mode='w', libver=('earliest', 'v108'))
except Exception as e: h5py_tricky_objects["h5_file_libver_earliest_v108"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    h5py_tricky_objects["h5_file_libver_v110_latest"] = _h5_create_core_file(name_suffix="libver_110_l", mode='w', libver=('v110', 'latest'))
except Exception as e: h5py_tricky_objects["h5_file_libver_v110_latest"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    h5py_tricky_objects["h5_file_libver_latest_strict"] = _h5_create_core_file(name_suffix="libver_l_l", mode='w', libver='latest') # equivalent to ('latest', 'latest')
except Exception as e: h5py_tricky_objects["h5_file_libver_latest_strict"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

# --- Userblock ---
try:
    h5py_tricky_objects["h5_file_userblock_512"] = _h5_create_core_file(name_suffix="ub_512", mode='w', userblock_size=512)
except Exception as e: h5py_tricky_objects["h5_file_userblock_512"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    h5py_tricky_objects["h5_file_userblock_8192"] = _h5_create_core_file(name_suffix="ub_8192", mode='w', userblock_size=8192)
except Exception as e: h5py_tricky_objects["h5_file_userblock_8192"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    _ub_append_fname_temp = _h5_create_disk_temp_file(suffix="_ub_append.h5")
    _f_ub_append = h5py.File(_ub_append_fname_temp, 'w', userblock_size=1024)
    _f_ub_append.close()
    h5py_tricky_objects["h5_file_path_for_userblock_append_test"] = _ub_append_fname_temp # Store path
    # Store an open version if needed, or fuzzer tries to open path with 'a' and different userblock
    h5py_tricky_objects["h5_file_obj_for_userblock_append_test"] = h5py.File(_ub_append_fname_temp, 'a', userblock_size=1024) # Correct open
    _h5_internal_files_to_keep_open_.append(h5py_tricky_objects["h5_file_obj_for_userblock_append_test"])
except Exception as e:
    h5py_tricky_objects["h5_file_path_for_userblock_append_test"] = None
    h5py_tricky_objects["h5_file_obj_for_userblock_append_test"] = None
    print(f"H5_A_WARN: userblock append setup {e}", file=sys.stderr)


# --- File Space Strategy & Page Buffering ---
try:
    h5py_tricky_objects["h5_file_fs_page_persist_thresh"] = _h5_create_core_file(name_suffix="fs_page_pt", mode='w', fs_strategy="page", fs_persist=True, fs_threshold=128)
except Exception as e: h5py_tricky_objects["h5_file_fs_page_persist_thresh"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    # Page buffering requires fs_strategy='page'. fs_page_size might be needed if pbs is small.
    _pbs = 16 * 1024
    _fsp = 4 * 1024 # Page buffer size should be >= file space page size for some HDF5 versions
    h5py_tricky_objects["h5_file_fs_page_with_page_buffer"] = _h5_create_core_file(
        name_suffix="fs_page_pb", mode='w', fs_strategy="page", fs_page_size=_fsp,
        page_buf_size=_pbs, min_meta_keep=10, min_raw_keep=10
    )
except Exception as e: h5py_tricky_objects["h5_file_fs_page_with_page_buffer"] = None; print(f"H5_A_WARN: page_buffer {e}", file=sys.stderr)

try:
    h5py_tricky_objects["h5_file_fs_fsm"] = _h5_create_core_file(name_suffix="fs_fsm", mode='w', fs_strategy="fsm")
except Exception as e: h5py_tricky_objects["h5_file_fs_fsm"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    h5py_tricky_objects["h5_file_fs_aggregate"] = _h5_create_core_file(name_suffix="fs_agg", mode='w', fs_strategy="aggregate")
except Exception as e: h5py_tricky_objects["h5_file_fs_aggregate"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)


# --- SWMR ---
try:
    _f_swmr = _h5_create_core_file(name_suffix="swmr", mode='w', libver='latest')
    if _f_swmr:
        _f_swmr.swmr_mode = True
        h5py_tricky_objects["h5_file_swmr_enabled_latest"] = _f_swmr
    else: h5py_tricky_objects["h5_file_swmr_enabled_latest"] = None
except Exception as e: h5py_tricky_objects["h5_file_swmr_enabled_latest"] = None; print(f"H5_A_WARN: swmr {e}", file=sys.stderr)

# --- Locking ---
try:
    h5py_tricky_objects["h5_file_locking_true"] = _h5_create_core_file(name_suffix="lock_t", mode='w', locking=True)
except Exception as e: h5py_tricky_objects["h5_file_locking_true"] = None; print(f"H5_A_WARN: locking=True {e}", file=sys.stderr)
try:
    h5py_tricky_objects["h5_file_locking_best_effort"] = _h5_create_core_file(name_suffix="lock_be", mode='w', locking='best-effort')
except Exception as e: h5py_tricky_objects["h5_file_locking_best_effort"] = None; print(f"H5_A_WARN: locking=best-effort {e}", file=sys.stderr)

# --- Path types ---
try:
    _temp_path_for_pathlib = _h5_create_disk_temp_file(suffix="_pathlib.h5")
    h5py_tricky_objects["h5_path_object_for_file_creation"] = pathlib.Path(_temp_path_for_pathlib) # Store Path obj
except Exception as e: h5py_tricky_objects["h5_path_object_for_file_creation"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)
try:
    # Filename with unicode chars - relies on filesystem support
    # For fuzzing, this is more about h5py.File(unicode_path_str) than the object itself
    _unicode_fname_str = _h5_create_disk_temp_file(prefix="h5py_fuzz_你好_অ_", suffix=".h5")
    h5py_tricky_objects["h5_str_path_for_unicode_file_TEMP"] = _unicode_fname_str # Store the path
except Exception as e: h5py_tricky_objects["h5_str_path_for_unicode_file_TEMP"] = None; print(f"H5_A_WARN: unicode path {e}", file=sys.stderr)


# --- For error testing with modes ---
try:
    _non_hdf5_path = _h5_create_disk_temp_file(suffix="_not_hdf5.h5", content=b"This is not an HDF5 file.")
    h5py_tricky_objects["h5_path_to_non_hdf5_file_TEMP"] = _non_hdf5_path
except Exception as e: h5py_tricky_objects["h5_path_to_non_hdf5_file_TEMP"] = None; print(f"H5_A_WARN: {e}", file=sys.stderr)

try:
    _readonly_hdf5_path = _h5_create_disk_temp_file(suffix="_readonly.h5")
    with h5py.File(_readonly_hdf5_path, 'w') as f_ro_init: f_ro_init.create_group("data")
    os.chmod(_readonly_hdf5_path, stat.S_IREAD) # Make OS read-only
    h5py_tricky_objects["h5_path_to_readonly_hdf5_file_TEMP"] = _readonly_hdf5_path
    # Note: Need to ensure this file can be cleaned up later by making it writable again.
    # The general test teardown should handle this if it rmtree's the temp dir.
except Exception as e: h5py_tricky_objects["h5_path_to_readonly_hdf5_file_TEMP"] = None; print(f"H5_A_WARN: readonly HDF5 path {e}", file=sys.stderr)

# Cleanup function for disk temp files (optional, if test framework doesn't already do it)
# def _h5_cleanup_disk_temp_files():
#     for fname_to_del in _h5_temp_files_created_on_disk_:
#         try:
#             if os.path.exists(fname_to_del) and not os.access(fname_to_del, os.W_OK): # If readonly
#                 os.chmod(fname_to_del, stat.S_IWRITE | stat.S_IREAD)
#             os.remove(fname_to_del)
#         except Exception as e_clean:
#             print(f"H5_A_WARN: Error cleaning up temp file {fname_to_del}: {e_clean}", file=sys.stderr)
# # Consider calling this at the end of the *entire* generated fuzzing script if needed.


# --- Additions to tricky_h5py_code for Core Dataset Creation Parameters ---
# Assumes _h5_main_file is a valid, open h5py.File object
# Assumes _h5_unique_name(base) function is defined

if _h5_main_file:
    try:
        h5py_tricky_objects["h5_dset_scalar_int"] = _h5_main_file.create_dataset(_h5_unique_name('d_scalar_i'), shape=(), dtype='i4', data=42)
    except Exception as e: h5py_tricky_objects["h5_dset_scalar_int"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_shape_none_null_dataspace"] = _h5_main_file.create_dataset(_h5_unique_name('d_null_space'), shape=None, dtype='f8')
    except Exception as e: h5py_tricky_objects["h5_dset_shape_none_null_dataspace"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_shape_zero_dim_1d"] = _h5_main_file.create_dataset(_h5_unique_name('d_zero_1d'), shape=(0,), dtype='i1')
    except Exception as e: h5py_tricky_objects["h5_dset_shape_zero_dim_1d"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_shape_zero_dim_2d"] = _h5_main_file.create_dataset(_h5_unique_name('d_zero_2d'), shape=(5,0), dtype='f4')
    except Exception as e: h5py_tricky_objects["h5_dset_shape_zero_dim_2d"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

    try:
        _large_element_dtype = numpy.dtype('S1000') # Large elements
        h5py_tricky_objects["h5_dset_autochunk_large_elements"] = _h5_main_file.create_dataset(_h5_unique_name('d_autochunk_lge'), shape=(10,), dtype=_large_element_dtype, chunks=True)
    except Exception as e: h5py_tricky_objects["h5_dset_autochunk_large_elements"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

    # Error case for oversized chunks - this dataset itself won't be created.
    # The fuzzer's dynamic creation part would test this. Not adding a None object for it here.

    try:
        h5py_tricky_objects["h5_dset_chunked_irregular"] = _h5_main_file.create_dataset(_h5_unique_name('d_chunk_irreg'), shape=(100,100), chunks=(7,13), dtype='i2')
    except Exception as e: h5py_tricky_objects["h5_dset_chunked_irregular"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

    # Error case for no_chunks_but_maxshape - dynamic test for fuzzer.

    try:
        h5py_tricky_objects["h5_dset_fillvalue_custom_int"] = _h5_main_file.create_dataset(_h5_unique_name('d_fill_int'), shape=(10,), dtype='i4', fillvalue=-99)
    except Exception as e: h5py_tricky_objects["h5_dset_fillvalue_custom_int"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_fillvalue_float_nan"] = _h5_main_file.create_dataset(_h5_unique_name('d_fill_nan'), shape=(10,), dtype='f8', fillvalue=numpy.nan)
    except Exception as e: h5py_tricky_objects["h5_dset_fillvalue_float_nan"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_filltime_never_float"] = _h5_main_file.create_dataset(_h5_unique_name('d_ftime_never'), shape=(10,), dtype='f4', fillvalue=1.23, fill_time='never')
    except Exception as e: h5py_tricky_objects["h5_dset_filltime_never_float"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_filltime_alloc_int"] = _h5_main_file.create_dataset(_h5_unique_name('d_ftime_alloc'), shape=(10,), dtype='i2', fillvalue=7, fill_time='alloc')
    except Exception as e: h5py_tricky_objects["h5_dset_filltime_alloc_int"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

    if 'gzip' in h5py.filters.encode:
        try:
            h5py_tricky_objects["h5_dset_compress_gzip_high"] = _h5_main_file.create_dataset(_h5_unique_name('d_gz_high'), shape=(100,100), dtype='i8', compression='gzip', compression_opts=9)
        except Exception as e: h5py_tricky_objects["h5_dset_compress_gzip_high"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
        try:
            h5py_tricky_objects["h5_dset_compress_shuffle_gzip"] = _h5_main_file.create_dataset(_h5_unique_name('d_shuf_gz'), shape=(50,50), dtype='f4', shuffle=True, compression='gzip')
        except Exception as e: h5py_tricky_objects["h5_dset_compress_shuffle_gzip"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    else: # Fallbacks if gzip not available
        h5py_tricky_objects["h5_dset_compress_gzip_high"] = None
        h5py_tricky_objects["h5_dset_compress_shuffle_gzip"] = None

    if 'lzf' in h5py.filters.encode:
        try:
            h5py_tricky_objects["h5_dset_compress_lzf"] = _h5_main_file.create_dataset(_h5_unique_name('d_lzf'), shape=(100,50), dtype='u2', compression='lzf')
        except Exception as e: h5py_tricky_objects["h5_dset_compress_lzf"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    else: h5py_tricky_objects["h5_dset_compress_lzf"] = None

    # SZip might not be commonly available or might have licensing issues for some builds
    # if 'szip' in h5py.filters.encode:
    #     try:
    #         h5py_tricky_objects["h5_dset_compress_szip_ec16"] = _h5_main_file.create_dataset(_h5_unique_name('d_szip'), shape=(30,30), dtype='f8', compression='szip', compression_opts=('ec', 16))
    #     except Exception as e: h5py_tricky_objects["h5_dset_compress_szip_ec16"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    # else: h5py_tricky_objects["h5_dset_compress_szip_ec16"] = None

    if 'fletcher32' in h5py.filters.encode:
        try:
            h5py_tricky_objects["h5_dset_compress_fletcher32"] = _h5_main_file.create_dataset(_h5_unique_name('d_f32'), shape=(20,20), dtype='i4', fletcher32=True, chunks=(5,5))
        except Exception as e: h5py_tricky_objects["h5_dset_compress_fletcher32"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    else: h5py_tricky_objects["h5_dset_compress_fletcher32"] = None

    if 'scaleoffset' in h5py.filters.encode:
        try:
            h5py_tricky_objects["h5_dset_compress_scaleoffset_int_auto"] = _h5_main_file.create_dataset(_h5_unique_name('d_so_int_auto'), shape=(100,), dtype='i2', scaleoffset=True, chunks=(10,))
        except Exception as e: h5py_tricky_objects["h5_dset_compress_scaleoffset_int_auto"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
        try:
            h5py_tricky_objects["h5_dset_compress_scaleoffset_int_bits"] = _h5_main_file.create_dataset(_h5_unique_name('d_so_int_bits'), shape=(100,), dtype='i4', scaleoffset=10, chunks=(10,)) # 10 bits precision
        except Exception as e: h5py_tricky_objects["h5_dset_compress_scaleoffset_int_bits"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
        try:
            h5py_tricky_objects["h5_dset_compress_scaleoffset_float_factor_chunked"] = _h5_main_file.create_dataset(_h5_unique_name('d_so_float'), shape=(100,), dtype='f4', scaleoffset=2, chunks=(10,)) # factor of 10^2
        except Exception as e: h5py_tricky_objects["h5_dset_compress_scaleoffset_float_factor_chunked"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    else: # Fallbacks if scaleoffset not available
        h5py_tricky_objects["h5_dset_compress_scaleoffset_int_auto"] = None
        h5py_tricky_objects["h5_dset_compress_scaleoffset_int_bits"] = None
        h5py_tricky_objects["h5_dset_compress_scaleoffset_float_factor_chunked"] = None

    try:
        h5py_tricky_objects["h5_dset_resizable_1d_unlimited"] = _h5_main_file.create_dataset(_h5_unique_name('d_resize_1d'), shape=(10,), dtype='i1', maxshape=(None,), chunks=(5,))
    except Exception as e: h5py_tricky_objects["h5_dset_resizable_1d_unlimited"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_resizable_2d_mixed"] = _h5_main_file.create_dataset(_h5_unique_name('d_resize_2d'), shape=(5,10), dtype='u2', maxshape=(100, None), chunks=(5,5))
    except Exception as e: h5py_tricky_objects["h5_dset_resizable_2d_mixed"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_initially_zero_resizable"] = _h5_main_file.create_dataset(_h5_unique_name('d_init_zero_resize'), shape=(0,5), dtype='f8', maxshape=(None,5), chunks=(1,5))
    except Exception as e: h5py_tricky_objects["h5_dset_initially_zero_resizable"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

    try:
        h5py_tricky_objects["h5_dset_track_times_false"] = _h5_main_file.create_dataset(_h5_unique_name('d_track_times_f'), shape=(3,), dtype='i4', track_times=False)
    except Exception as e: h5py_tricky_objects["h5_dset_track_times_false"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

    try:
        h5py_tricky_objects["h5_dset_created_from_data_implicit_shape"] = _h5_main_file.create_dataset(_h5_unique_name('d_from_data_impl'), data=numpy.arange(20, dtype='u1'))
    except Exception as e: h5py_tricky_objects["h5_dset_created_from_data_implicit_shape"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        _data_for_reshape = numpy.arange(30, dtype='i8')
        h5py_tricky_objects["h5_dset_created_from_data_reshaped"] = _h5_main_file.create_dataset(_h5_unique_name('d_from_data_resh'), shape=(10,3), data=_data_for_reshape)
    except Exception as e: h5py_tricky_objects["h5_dset_created_from_data_reshaped"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_created_with_h5py_empty"] = _h5_main_file.create_dataset(_h5_unique_name('d_h5empty'), data=h5py.Empty(dtype='f2'))
    except Exception as e: h5py_tricky_objects["h5_dset_created_with_h5py_empty"] = None; print(f"H5_B_WARN: {e}", file=sys.stderr)

else:
    print(f"H5_B_ERROR: _h5_main_file was not created. Cannot add Category B dataset objects.", file=sys.stderr)
    # Populate all relevant keys with None if the main file isn't available
    _b_names_to_none = [
        "h5_dset_scalar_int", "h5_dset_shape_none_null_dataspace", "h5_dset_shape_zero_dim_1d",
        "h5_dset_shape_zero_dim_2d", "h5_dset_autochunk_large_elements", "h5_dset_chunked_irregular",
        "h5_dset_fillvalue_custom_int", "h5_dset_fillvalue_float_nan", "h5_dset_filltime_never_float",
        "h5_dset_filltime_alloc_int", "h5_dset_compress_gzip_high", "h5_dset_compress_lzf",
        "h5_dset_compress_shuffle_gzip", "h5_dset_compress_fletcher32",
        "h5_dset_compress_scaleoffset_int_auto", "h5_dset_compress_scaleoffset_int_bits",
        "h5_dset_compress_scaleoffset_float_factor_chunked", "h5_dset_resizable_1d_unlimited",
        "h5_dset_resizable_2d_mixed", "h5_dset_initially_zero_resizable", "h5_dset_track_times_false",
        "h5_dset_created_from_data_implicit_shape", "h5_dset_created_from_data_reshaped",
        "h5_dset_created_with_h5py_empty"
    ]
    for _name in _b_names_to_none: h5py_tricky_objects[_name] = None


# --- Additions to tricky_h5py_code for Advanced/Tricky Dataset Datatypes ---
# Assumes _h5_main_file, _h5_unique_name, h5py, numpy, uuid, sys are available.
# Assumes tricky_numpy_* objects are available if used as data.

if _h5_main_file:
    # --- Committed Datatypes (for reuse) ---
    try:
        _committed_vlen_utf8_type_name = _h5_unique_name('type_vlen_utf8')
        _h5_main_file[_committed_vlen_utf8_type_name] = h5py.string_dtype(encoding='utf-8')
        h5py_tricky_objects['h5_datatype_committed_vlen_str'] = _h5_main_file[_committed_vlen_utf8_type_name]
    except Exception as e: h5py_tricky_objects['h5_datatype_committed_vlen_str'] = None; print(f"H5_C_WARN: {_committed_vlen_utf8_type_name} {e}", file=sys.stderr)

    try:
        _rgb_enum_dict = {'R': 1, 'G': 2, 'B': 3, 'TRANSPARENT': 0}
        _committed_enum_type_name = _h5_unique_name('type_enum_rgb')
        _h5_main_file[_committed_enum_type_name] = h5py.enum_dtype(_rgb_enum_dict, basetype='u1')
        h5py_tricky_objects['h5_datatype_committed_enum'] = _h5_main_file[_committed_enum_type_name]
    except Exception as e: h5py_tricky_objects['h5_datatype_committed_enum'] = None; print(f"H5_C_WARN: {_committed_enum_type_name} {e}", file=sys.stderr)

    try:
        _simple_compound_dt = numpy.dtype([('id', 'i4'), ('value', 'f8'), ('tag', 'S5')])
        _committed_compound_type_name = _h5_unique_name('type_compound_simple')
        _h5_main_file[_committed_compound_type_name] = _simple_compound_dt
        h5py_tricky_objects['h5_datatype_from_structured_numpy'] = _h5_main_file[_committed_compound_type_name]
    except Exception as e: h5py_tricky_objects['h5_datatype_from_structured_numpy'] = None; print(f"H5_C_WARN: {_committed_compound_type_name} {e}", file=sys.stderr)


    # --- String Datasets ---
    try:
        _dt_s10 = h5py.string_dtype(encoding='ascii', length=10)
        _data_s10 = numpy.array([b'hello\\0   ', b'world\\0   ', b'a\\0b\\0c\\0d\\0e\\0'], dtype=_dt_s10)
        h5py_tricky_objects["h5_dset_fixed_ascii_S10_with_nulls"] = _h5_main_file.create_dataset(_h5_unique_name('d_s10ascii'), data=_data_s10)
    except Exception as e: h5py_tricky_objects["h5_dset_fixed_ascii_S10_with_nulls"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_u20 = h5py.string_dtype(encoding='utf-8', length=20) # Length is num bytes for utf-8 fixed
        _data_u20 = numpy.array(['你好世界', 'test😀', 'αβγ\\0δε'], dtype=_dt_u20)
        h5py_tricky_objects["h5_dset_fixed_utf8_len20_special_chars"] = _h5_main_file.create_dataset(_h5_unique_name('d_u20utf8'), data=_data_u20)
    except Exception as e: h5py_tricky_objects["h5_dset_fixed_utf8_len20_special_chars"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_vlen_ascii = h5py.string_dtype(encoding='ascii')
        _data_vlen_ascii = numpy.array([b"abc", b"defghij", b""], dtype=_dt_vlen_ascii)
        h5py_tricky_objects["h5_dset_vlen_ascii_basic"] = _h5_main_file.create_dataset(_h5_unique_name('d_vlenasc'), data=_data_vlen_ascii)
    except Exception as e: h5py_tricky_objects["h5_dset_vlen_ascii_basic"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_vlen_utf8 = h5py_tricky_objects.get('h5_datatype_committed_vlen_str') or h5py.string_dtype(encoding='utf-8') # Reuse committed or default
        _data_vlen_utf8 = numpy.array(["نص عربي", "😀", "Ленинград", ""], dtype=_dt_vlen_utf8)
        h5py_tricky_objects["h5_dset_vlen_utf8_mixed_scripts"] = _h5_main_file.create_dataset(_h5_unique_name('d_vlenutf8'), data=_data_vlen_utf8)
    except Exception as e: h5py_tricky_objects["h5_dset_vlen_utf8_mixed_scripts"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # --- VLEN Datasets (non-string) ---
    try:
        _dt_vlen_i32 = h5py.vlen_dtype(numpy.int32)
        _data_vlen_i32 = numpy.empty(3, dtype=object)
        _data_vlen_i32[0] = numpy.array([1,2,3], dtype=numpy.int32)
        _data_vlen_i32[1] = numpy.array([], dtype=numpy.int32)
        _data_vlen_i32[2] = numpy.arange(10, dtype=numpy.int32)
        h5py_tricky_objects["h5_dset_vlen_int32_array"] = _h5_main_file.create_dataset(_h5_unique_name('d_vleni32'), data=_data_vlen_i32, dtype=_dt_vlen_i32)
    except Exception as e: h5py_tricky_objects["h5_dset_vlen_int32_array"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try: # float16 may not be present on all numpy builds
        _dt_vlen_f16 = h5py.vlen_dtype(numpy.float16)
        _data_vlen_f16 = numpy.empty(2, dtype=object)
        _data_vlen_f16[0] = numpy.array([1.0, 0.5, -2.75], dtype=numpy.float16)
        _data_vlen_f16[1] = numpy.array([numpy.nan, numpy.inf], dtype=numpy.float16)
        h5py_tricky_objects["h5_dset_vlen_float16_array"] = _h5_main_file.create_dataset(_h5_unique_name('d_vlenf16'), data=_data_vlen_f16, dtype=_dt_vlen_f16)
    except (AttributeError, TypeError, Exception) as e: h5py_tricky_objects["h5_dset_vlen_float16_array"] = None; print(f"H5_C_WARN: vlenf16 {e}", file=sys.stderr) # Catch if float16 itself is an issue
    try:
        _dt_vlen_bool = h5py.vlen_dtype(numpy.bool_)
        _data_vlen_bool = numpy.empty(2, dtype=object); _data_vlen_bool[0]=[True,False]; _data_vlen_bool[1]=[True]
        h5py_tricky_objects["h5_dset_vlen_bool_array"] = _h5_main_file.create_dataset(_h5_unique_name('d_vlenbool'), data=_data_vlen_bool, dtype=_dt_vlen_bool)
    except Exception as e: h5py_tricky_objects["h5_dset_vlen_bool_array"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_2d_vlen = h5py.vlen_dtype(numpy.int32)
        _data_2d_vlen = numpy.empty((2,2), dtype=object)
        _data_2d_vlen[0,0] = [1]; _data_2d_vlen[0,1] = [1,2]; _data_2d_vlen[1,0] = []; _data_2d_vlen[1,1] = [1,2,3,4,5]
        h5py_tricky_objects["h5_dset_2d_vlen_int_variable_lengths"] = _h5_main_file.create_dataset(_h5_unique_name('d_2dvlen'), data=_data_2d_vlen, dtype=_dt_2d_vlen)
    except Exception as e: h5py_tricky_objects["h5_dset_2d_vlen_int_variable_lengths"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # --- Enum Datasets ---
    try:
        _enum_rgb_dt = h5py_tricky_objects.get('h5_datatype_committed_enum') or h5py.enum_dtype({'R':1,'G':2,'B':3}, basetype='i1')
        _data_enum_rgb = numpy.array([1,2,3,1,0], dtype=_enum_rgb_dt) # 0 might be an undefined value if dict doesn't map it
        h5py_tricky_objects["h5_dset_enum_rgb_int8"] = _h5_main_file.create_dataset(_h5_unique_name('d_enumrgb'), data=_data_enum_rgb)
    except Exception as e: h5py_tricky_objects["h5_dset_enum_rgb_int8"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _enum_status_dt = h5py.enum_dtype({'PASS':10, 'FAIL':20, 'SKIP':30, 'UNDEFINED':0}, basetype=numpy.int32)
        _data_enum_status = numpy.array([10,20,0,30,99], dtype=_enum_status_dt) # 99 is undefined
        h5py_tricky_objects["h5_dset_enum_status_str_keys_int_vals"] = _h5_main_file.create_dataset(_h5_unique_name('d_enumstat'), data=_data_enum_status)
    except Exception as e: h5py_tricky_objects["h5_dset_enum_status_str_keys_int_vals"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # --- Compound Datasets ---
    try:
        _dt_compound_basic = h5py_tricky_objects.get('h5_datatype_from_structured_numpy') or numpy.dtype([('id', 'i4'), ('val', 'f8'), ('name', 'S10')])
        _data_compound_basic = numpy.array([(1, 3.14, b'rec1'), (2, 6.28, b'record2')], dtype=_dt_compound_basic)
        h5py_tricky_objects["h5_dset_compound_basic_mixed_types"] = _h5_main_file.create_dataset(_h5_unique_name('d_compbasic'), data=_data_compound_basic)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_basic_mixed_types"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_compound_arr = numpy.dtype([('timestamp', 'f8'), ('readings', '(5,2)i2')])
        _data_compound_arr = numpy.zeros(2, dtype=_dt_compound_arr)
        _data_compound_arr[0] = (123.45, numpy.arange(10).reshape(5,2))
        _data_compound_arr[1] = (678.90, numpy.ones((5,2), dtype='i2')*5)
        h5py_tricky_objects["h5_dset_compound_with_array_field"] = _h5_main_file.create_dataset(_h5_unique_name('d_comparr'), data=_data_compound_arr)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_with_array_field"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_vlen_str_field = h5py.string_dtype(encoding='utf-8') # VLEN UTF-8
        _dt_compound_vlen_str = numpy.dtype([('id', 'u4'), ('comment', _dt_vlen_str_field)])
        _data_compound_vlen_str = numpy.array([(100, "First comment 😀"), (101, "Second, much longer comment with more Unicode characters like 你好")], dtype=_dt_compound_vlen_str)
        h5py_tricky_objects["h5_dset_compound_with_vlen_str_field"] = _h5_main_file.create_dataset(_h5_unique_name('d_compvlenstr'), data=_data_compound_vlen_str)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_with_vlen_str_field"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_vlen_int_field = h5py.vlen_dtype(numpy.int16)
        _dt_compound_vlen_int = numpy.dtype([('event_id', 'i8'), ('values', _dt_vlen_int_field)])
        _data_compound_vlen_int = numpy.empty(2, dtype=_dt_compound_vlen_int)
        _data_compound_vlen_int[0] = (1234567890, numpy.array([1,2,3,4,5], dtype=numpy.int16))
        _data_compound_vlen_int[1] = (9876543210, numpy.array([-10, -20], dtype=numpy.int16))
        h5py_tricky_objects["h5_dset_compound_with_vlen_int_field"] = _h5_main_file.create_dataset(_h5_unique_name('d_compvlenint'), data=_data_compound_vlen_int)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_with_vlen_int_field"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _inner_dt = numpy.dtype([('x', 'f4'), ('y', 'f4')])
        _outer_dt = numpy.dtype([('id', 'S3'), ('coords', _inner_dt), ('flag', '?')])
        _data_nested = numpy.array([ (b'P01', (1.0, -1.0), True), (b'P02', (-2.5, 2.5), False) ], dtype=_outer_dt)
        h5py_tricky_objects["h5_dset_compound_nested_compound"] = _h5_main_file.create_dataset(_h5_unique_name('d_compnest'), data=_data_nested)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_nested_compound"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # For ref_dtype and regionref_dtype, we need target objects
    _ref_target_group_c = _h5_main_file.require_group(_h5_unique_name('ref_target_g_c'))
    _ref_target_dset_c = _h5_main_file.require_dataset(_h5_unique_name('ref_target_d_c'), shape=(10,), dtype='i4', data=numpy.arange(10))
    try:
        _dt_compound_ref = numpy.dtype([('idx', 'i4'), ('obj_ref', h5py.ref_dtype)])
        _data_compound_ref = numpy.array([(1, _ref_target_group_c.ref), (2, _ref_target_dset_c.ref)], dtype=_dt_compound_ref)
        h5py_tricky_objects["h5_dset_compound_with_ref_field"] = _h5_main_file.create_dataset(_h5_unique_name('d_comprefo'), data=_data_compound_ref)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_with_ref_field"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_compound_regref = numpy.dtype([('name', 'S8'), ('region', h5py.regionref_dtype)])
        _data_compound_regref = numpy.empty(1, dtype=_dt_compound_regref)
        _data_compound_regref[0] = (b'slice1', _ref_target_dset_c.regionref[2:5])
        h5py_tricky_objects["h5_dset_compound_with_regionref_field"] = _h5_main_file.create_dataset(_h5_unique_name('d_compregref'), data=_data_compound_regref)
    except Exception as e: h5py_tricky_objects["h5_dset_compound_with_regionref_field"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)


    # --- Array Datasets ---
    try:
        _dt_arr = numpy.dtype('(3,2)i2') # Array of 3x2 int16
        _data_arr = numpy.arange(6*2, dtype='i2').reshape(2,3,2) # Data for 2 elements
        h5py_tricky_objects["h5_dset_array_dtype_3x2_int16"] = _h5_main_file.create_dataset(_h5_unique_name('d_arrdt'), shape=(2,), dtype=_dt_arr, data=_data_arr)
    except Exception as e: h5py_tricky_objects["h5_dset_array_dtype_3x2_int16"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # --- Standalone Reference Datasets ---
    try:
        _data_obj_refs_standalone = numpy.array([_ref_target_group_c.ref, _ref_target_dset_c.ref, _h5_main_file.ref, None], dtype=h5py.ref_dtype)
        h5py_tricky_objects["h5_dset_object_references_standalone"] = _h5_main_file.create_dataset(_h5_unique_name('d_refs_stdalone'), data=_data_obj_refs_standalone)
    except Exception as e: h5py_tricky_objects["h5_dset_object_references_standalone"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _data_reg_refs_standalone = numpy.empty(2, dtype=h5py.regionref_dtype)
        _data_reg_refs_standalone[0] = _ref_target_dset_c.regionref[0:5:2]
        _data_reg_refs_standalone[1] = _ref_target_dset_c.regionref[...] # Full dataset
        h5py_tricky_objects["h5_dset_region_references_standalone"] = _h5_main_file.create_dataset(_h5_unique_name('d_regrefs_stdalone'), data=_data_reg_refs_standalone)
    except Exception as e: h5py_tricky_objects["h5_dset_region_references_standalone"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # --- Datasets from Committed Types ---
    try:
        _committed_type = h5py_tricky_objects.get('h5_datatype_from_structured_numpy')
        if _committed_type:
            h5py_tricky_objects["h5_dset_from_committed_compound_type"] = _h5_main_file.create_dataset(_h5_unique_name('d_from_comm_comp'), shape=(5,), dtype=_committed_type)
        else: h5py_tricky_objects["h5_dset_from_committed_compound_type"] = None
    except Exception as e: h5py_tricky_objects["h5_dset_from_committed_compound_type"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _committed_vlen = h5py_tricky_objects.get('h5_datatype_committed_vlen_str')
        if _committed_vlen:
            h5py_tricky_objects["h5_dset_from_committed_vlen_type"] = _h5_main_file.create_dataset(_h5_unique_name('d_from_comm_vlen'), shape=(3,), dtype=_committed_vlen)
        else: h5py_tricky_objects["h5_dset_from_committed_vlen_type"] = None
    except Exception as e: h5py_tricky_objects["h5_dset_from_committed_vlen_type"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

    # --- Empty datasets with complex dtypes ---
    try:
        _dt_vlen_str_empty = h5py.string_dtype(encoding='utf-8')
        h5py_tricky_objects["h5_dset_empty_vlen_str"] = _h5_main_file.create_dataset(_h5_unique_name('d_empty_vlen_str'), shape=(0,), dtype=_dt_vlen_str_empty)
    except Exception as e: h5py_tricky_objects["h5_dset_empty_vlen_str"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)
    try:
        _dt_compound_empty = numpy.dtype([('id', 'i4'), ('val', 'f8')])
        h5py_tricky_objects["h5_dset_empty_compound"] = _h5_main_file.create_dataset(_h5_unique_name('d_empty_compound'), shape=(0,2), dtype=_dt_compound_empty)
    except Exception as e: h5py_tricky_objects["h5_dset_empty_compound"] = None; print(f"H5_C_WARN: {e}", file=sys.stderr)

else:
    print(f"H5_C_ERROR: _h5_main_file was not created. Cannot add Category C dataset objects.", file=sys.stderr)
    # Populate all relevant keys with None if the main file isn't available
    _c_names_to_none = [name for name in tricky_h5py_names if name.startswith("h5_dset_") and ("vlen" in name or "enum" in name or "compound" in name or "array_dtype" in name or "ref" in name or "commit" in name or "empty_" in name) or name.startswith("h5_datatype_")]
    for _name in _c_names_to_none:
         if _name not in h5py_tricky_objects: h5py_tricky_objects[_name] = None
         

# --- Additions to tricky_h5py_code for Dataset Operations ---
# Assumes _h5_main_file, _h5_unique_name, h5py, numpy, uuid, sys are available.

if _h5_main_file:
    try:
        _data_rd_src = numpy.arange(100, dtype='i4').reshape(10,10)
        h5py_tricky_objects["h5_dset_for_read_direct_source"] = _h5_main_file.create_dataset(_h5_unique_name('d_rd_src'), data=_data_rd_src)
    except Exception as e: h5py_tricky_objects["h5_dset_for_read_direct_source"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_for_write_direct_dest_simple"] = _h5_main_file.create_dataset(_h5_unique_name('d_wd_dest'), shape=(20,20), dtype='i4', fillvalue=-1)
    except Exception as e: h5py_tricky_objects["h5_dset_for_write_direct_dest_simple"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_for_fancy_indexing_setitem"] = _h5_main_file.create_dataset(_h5_unique_name('d_fancyidx'), shape=(5,10,2), dtype=numpy.uint8)
    except Exception as e: h5py_tricky_objects["h5_dset_for_fancy_indexing_setitem"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_for_iteration_2d"] = _h5_main_file.create_dataset(_h5_unique_name('d_iter_2d'), data=numpy.arange(15).reshape(5,3))
    except Exception as e: h5py_tricky_objects["h5_dset_for_iteration_2d"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_scalar_for_iteration_error"] = _h5_main_file.create_dataset(_h5_unique_name('d_iter_scalar'), data=100)
    except Exception as e: h5py_tricky_objects["h5_dset_scalar_for_iteration_error"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_for_astype_simple_int"] = _h5_main_file.create_dataset(_h5_unique_name('d_astype_src'), data=numpy.arange(10, dtype='i2'))
    except Exception as e: h5py_tricky_objects["h5_dset_for_astype_simple_int"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        _dt_fixed_ascii = h5py.string_dtype('ascii', 5)
        h5py_tricky_objects["h5_dset_for_asstr_fixed_ascii"] = _h5_main_file.create_dataset(_h5_unique_name('d_asstr_src'), data=numpy.array([b'Hello', b'World'], dtype=_dt_fixed_ascii))
    except Exception as e: h5py_tricky_objects["h5_dset_for_asstr_fixed_ascii"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_chunked_for_iter_chunks"] = _h5_main_file.create_dataset(_h5_unique_name('d_iterchunks'), shape=(20,30), chunks=(7,11), dtype='f4')
    except Exception as e: h5py_tricky_objects["h5_dset_chunked_for_iter_chunks"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)
    try:
        h5py_tricky_objects["h5_dset_for_comparisons_float"] = _h5_main_file.create_dataset(_h5_unique_name('d_compare_f'), data=numpy.random.rand(10)*10, dtype='f8')
    except Exception as e: h5py_tricky_objects["h5_dset_for_comparisons_float"] = None; print(f"H5_D_WARN: {e}", file=sys.stderr)

else:
    print(f"H5_D_ERROR: _h5_main_file was not created. Cannot add Category D dataset objects.", file=sys.stderr)
    # Populate relevant keys with None
    _d_names_to_none = [name for name in tricky_h5py_names if "h5_dset_for_" in name or "h5_dset_scalar_for_" in name]
    for _name in _d_names_to_none:
         if _name not in h5py_tricky_objects: h5py_tricky_objects[_name] = None



# Ensure all names in tricky_h5py_names have a corresponding (even if None) entry in h5py_tricky_objects
for name in tricky_h5py_names:
    if name not in h5py_tricky_objects:
        print(f"H5PY_TRICKY_DEV_WARN: '{name}' was in tricky_h5py_names but not added to h5py_tricky_objects dict. Setting to None.", file=sys.stderr)
        h5py_tricky_objects[name] = None
"""
