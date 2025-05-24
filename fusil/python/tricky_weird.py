"""
Tricky and Weird Objects for Python Fuzzing

This module defines problematic Python objects, classes, and edge cases designed to
trigger bugs during fuzzing. It contains boundary values like maximum integers,
weird class hierarchies with custom metaclasses, circular references, and other
pathological objects that can expose vulnerabilities in Python code and C extensions.
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
# dicts = [Counter, OrderedDict, dict]
dicts = [OrderedDict, dict]
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
    if cls not in (float, complex):
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
all_types = [t for t in all_types if not issubclass(t, BaseException)]
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
    # "tricky_list",
    "tricky_mappingproxy",
    "tricky_module",
    "tricky_module2",
    "tricky_property",
    "tricky_simplenamespace",
    "tricky_staticmethod",
    "tricky_traceback",
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
tricky_genericalias = types.GenericAlias(tricky_capsule, (tricky_cell,))
tricky_dict = {tricky_capsule: tricky_cell, tricky_module: tricky_genericalias}
tricky_dict["tricky_dict"] = tricky_dict
tricky_mappingproxy = types.MappingProxyType(tricky_dict)


def tricky_function(*args, **kwargs):
    return tricky_function(*args, **kwargs)


tricky_lambda = lambda *args, **kwargs: tricky_lambda(*args, **kwargs)
tricky_classmethod = classmethod(tricky_lambda)
tricky_staticmethod = staticmethod(tricky_lambda)
tricky_property = property(tricky_lambda)
tricky_code = tricky_lambda.__code__
tricky_closure = tricky_code.co_freevars
tricky_classmethod_descriptor = types.ClassMethodDescriptorType


class TrickyDescriptor:
    def __get__(self, obj, objtype=None):
        return self

    def __set__(self, obj, value):
        obj.__dict__["_value"] = value

    def __delete__(self, obj):
        del obj.__dict__["_value"]


class TrickyMeta(type):
    @property
    def __signature__(self):
        raise AttributeError("Signature denied")


class TrickyClass(metaclass=TrickyMeta):
    tricky_descriptor = TrickyDescriptor()

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        self._value = None

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


tricky_instance = TrickyClass()
tricky_frame = inspect.currentframe()
tricky_frame.f_builtins.update(tricky_dict)
tricky_frame.f_globals.update(tricky_dict)
tricky_frame.f_locals.update(tricky_dict)

try:
    1 / 0
except ZeroDivisionError as e:
    tricky_traceback = e.__traceback__

# tricky_generator = (x for x in itertools.count())  # Triggers too many free-threading segfaults
tricky_list = [[]] * 6 + []
tricky_list[0].append(tricky_list)
tricky_list[-1].append(tricky_list)
tricky_list.append(tricky_list)
tricky_list[0][0].append(tricky_list)
"""
type_names = ("list", "tuple", "dict")
tricky_numpy_names = [
    "numpy_zeros",
    "numpy_nan",
    "numpy_very_large_int",
    "numpy_very_large_float",
    "numpy_sys_max_float",
    "numpy_sys_min_float",
]
tricky_numpy = """
import sys
from math import factorial

import numpy

numpy_zeros = numpy.zeros((2000, 2000))
numpy_nan = numpy.array([[numpy.nan] * 1000 for n in range(1000)])
numpy_very_large_int = numpy.array([factorial(x) for x in range(150, 250)])
numpy_very_large_float = numpy.array([factorial(x) for x in range(250, 350)], dtype=numpy.float128)
numpy_sys_max_float =  numpy.array([sys.float_info.max] * 100)
numpy_sys_min_float =  numpy.array([sys.float_info.min] * 100)
"""
