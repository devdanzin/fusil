# FUSIL_BOILERPLATE_START

from gc import collect
from random import choice, randint, random, sample, seed
from sys import stderr, path as sys_path
from os.path import dirname
import ast
import inspect
import io
import math
import operator
import time
import sys
from threading import Thread
from unittest.mock import MagicMock
import asyncio
seed(946466063)

print("Importing target module: fakemod", file=stderr)
try:
    import fakemod
except ImportError as _fusil_import_error:
    print("FUSIL: target module fakemod not importable (skipping):", repr(_fusil_import_error), file=stderr)
    raise SystemExit(0)

TRIVIAL_TYPES = {int, str, float, bool, bytes, tuple, list, dict, set, type(None),}
def skip_trivial_type(obj_instance_or_class):
    if type(obj_instance_or_class) in TRIVIAL_TYPES:
        return True
    return False


import sys
from _collections import OrderedDict, deque
from abc import ABCMeta
from collections import Counter
from queue import Queue
from random import randint
from string import printable

try:
    from _decimal import Decimal

    has__decimal = True
except ImportError:
    from decimal import Decimal

    has__decimal = False

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

tricky_strs = (
    chr(0),
    chr(127),
    chr(255),
    chr(0x10FFFF),
    "𝒜",
    "\\x00" * 10,
    "A" * (2**16),
    "💻" * 2**10,
)

# We cannot create a Decimal larger than 10 ** 4300 with _pydecimal, only with _decimal
max_str_digits_adjustment = 1 if has__decimal else -1
big_int_for_decimal = 10 ** (sys.int_info.default_max_str_digits + max_str_digits_adjustment)

for cls in sequences:
    weird_instances[f"weird_{cls.__name__}_single"] = weird_classes[f"weird_{cls.__name__}"]("a")
    weird_instances[f"weird_{cls.__name__}_range"] = weird_classes[f"weird_{cls.__name__}"](
        range(20)
    )
    weird_instances[f"weird_{cls.__name__}_types"] = weird_classes[f"weird_{cls.__name__}"](bases)
    weird_instances[f"weird_{cls.__name__}_printable"] = weird_classes[f"weird_{cls.__name__}"](
        printable
    )
    weird_instances[f"weird_{cls.__name__}_special"] = weird_classes[f"weird_{cls.__name__}"](
        tricky_strs
    )
for cls in bytes_:
    weird_instances[f"weird_{cls.__name__}_bytes"] = weird_classes[f"weird_{cls.__name__}"](
        b"abcdefgh_" * 10
    )
for cls in numbers:
    weird_instances[f"weird_{cls.__name__}_sys_maxsize"] = weird_classes[f"weird_{cls.__name__}"](
        sys.maxsize
    )
    weird_instances[f"weird_{cls.__name__}_sys_maxsize_minus_one"] = weird_classes[
        f"weird_{cls.__name__}"
    ](sys.maxsize - 1)
    weird_instances[f"weird_{cls.__name__}_sys_maxsize_plus_one"] = weird_classes[
        f"weird_{cls.__name__}"
    ](sys.maxsize + 1)
    weird_instances[f"weird_{cls.__name__}_neg_sys_maxsize"] = weird_classes[
        f"weird_{cls.__name__}"
    ](-sys.maxsize)
    weird_instances[f"weird_{cls.__name__}_2**63-1"] = weird_classes[f"weird_{cls.__name__}"](
        2**63 - 1
    )
    weird_instances[f"weird_{cls.__name__}_2**63"] = weird_classes[f"weird_{cls.__name__}"](2**63)
    weird_instances[f"weird_{cls.__name__}_2**63+1"] = weird_classes[f"weird_{cls.__name__}"](
        2**63 + 1
    )
    weird_instances[f"weird_{cls.__name__}_-2**63+1"] = weird_classes[f"weird_{cls.__name__}"](
        -(2**63) + 1
    )
    weird_instances[f"weird_{cls.__name__}_-2**63"] = weird_classes[f"weird_{cls.__name__}"](
        -(2**63)
    )
    weird_instances[f"weird_{cls.__name__}_-2**63-1"] = weird_classes[f"weird_{cls.__name__}"](
        -(2**63) - 1
    )
    weird_instances[f"weird_{cls.__name__}_2**31-1"] = weird_classes[f"weird_{cls.__name__}"](
        2**31 - 1
    )
    weird_instances[f"weird_{cls.__name__}_2**31"] = weird_classes[f"weird_{cls.__name__}"](2**31)
    weird_instances[f"weird_{cls.__name__}_2**31+1"] = weird_classes[f"weird_{cls.__name__}"](
        2**31 + 1
    )
    weird_instances[f"weird_{cls.__name__}_-2**31+1"] = weird_classes[f"weird_{cls.__name__}"](
        -(2**31) + 1
    )
    weird_instances[f"weird_{cls.__name__}_-2**31"] = weird_classes[f"weird_{cls.__name__}"](
        -(2**31)
    )
    weird_instances[f"weird_{cls.__name__}_-2**31-1"] = weird_classes[f"weird_{cls.__name__}"](
        -(2**31) - 1
    )
    if cls not in (float, complex) and hasattr(sys, "int_info"):
        weird_instances[f"weird_{cls.__name__}_10**default_max_str_digits+1"] = weird_classes[
            f"weird_{cls.__name__}"
        ](big_int_for_decimal)
for cls in dicts:
    weird_instances[f"weird_{cls.__name__}_basic"] = weird_classes[f"weird_{cls.__name__}"](
        {a: a for a in range(100)}
    )
    weird_instances[f"weird_{cls.__name__}_tricky_strs"] = weird_classes[f"weird_{cls.__name__}"](
        {a: a for a in tricky_strs}
    )


# Class with a __del__ side effect to attack the JIT optimizer
class FrameModifier:
    def __init__(self, var_name, new_value):
        # Store the name of the variable to target and its new value.
        self.var_name = var_name
        self.new_value = new_value
        # Announce creation for debugging the generated script
        print(f"  [FrameModifier created to target '{self.var_name}']", file=sys.stderr)

    def __del__(self):
        try:
            # On destruction, get the calling frame (1 level up).
            frame = sys._getframe(1)
            # Maliciously modify the local variable in that frame.
            print(
                f"  [Side Effect] In __del__: Modifying '{self.var_name}' to {self.new_value!r}",
                file=sys.stderr,
            )
            if self.var_name in frame.f_locals:
                frame.f_locals[self.var_name] = self.new_value
            elif (
                self.var_name.split(".")[0] in frame.f_locals and self.var_name.count(".") == 1
            ):  # instance_or_class.attribute
                instance_or_class_str, attr_str = self.var_name.split(".")
                setattr(frame.f_locals[instance_or_class_str], attr_str, self.new_value)
            else:  # module.instance_or_class.attribute
                module_str, instance_or_class_str, attr_str = self.var_name.split(".")
                instance_or_class = getattr(frame.f_locals[module_str], instance_or_class_str)
                setattr(instance_or_class, attr_str, self.new_value)
        except Exception as e:
            # Frame inspection can be tricky; don't crash in __del__.
            print(f"  [Side Effect] Error in FrameModifier.__del__: {e}", file=sys.stderr)


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

all_types = (
    abc_types
    + builtins_types
    + collections_abc_types
    + collections_types
    + itertools_types
    + types_types
    + typing_types
)
all_types = [t for t in all_types if not (isinstance(t, type) and issubclass(t, BaseException))]
big_union = reduce(or_, all_types, int)


import inspect
import types

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
if tricky_capsule:
    tricky_dict[tricky_capsule] = tricky_cell
if tricky_module:
    tricky_dict[tricky_module] = tricky_genericalias
tricky_dict["tricky_dict"] = tricky_dict
tricky_mappingproxy = types.MappingProxyType(tricky_dict)


def tricky_function(*args, **kwargs):
    if len(args) > 150:
        raise RecursionError("Fuzzer controlled depth")
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
tricky_classmethod_descriptor = types.ClassMethodDescriptorType  # This is the type itself


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
        # return super().__mro_entries__(bases)


class TrickyClass(metaclass=TrickyMeta):
    tricky_descriptor = TrickyDescriptor()

    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, *args, **kwargs):
        self._value_init = None

    def __getattr__(self, name):
        if name == "crash_on_getattr":
            raise ValueError("getattr manipulated")
        return self


tricky_instance = TrickyClass()
try:
    tricky_frame = inspect.currentframe()
    if tricky_frame:  # currentframe() can be None
        # tricky_frame.f_builtins.update(tricky_dict)
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


"""Exception-bomb objects: the protocol-level analogue of the OOM (allocation-failure) mode.

The OOM allocator hook makes *allocations* fail deterministically; a bomb object makes a
*dunder callback* fail -- exercising the large class of C code that calls a Python protocol
slot (``__hash__``, ``__eq__``, ``__index__``, ``__len__``, ``__iter__``, ``__repr__``, ...)
and then does an unguarded ``PyErr_Clear()`` or assumes the slot succeeded.

Two knobs, both randomised at construction so repeated use across a run walks a wide slice of
program state (the windowed-failure insight of the OOM sequence mode applied to protocol slots):

* **delay** — succeed a random number of times, *then* raise. Delay 0 means "raise on first
  use"; delay N means "corrupt/observe state for N calls, then fail" (the cross-call
  "succeeded during insert, fails during lookup" shape that surfaces swallowed exceptions).
* **exception** — the targeted bombs raise ``MemoryError`` (the highest-value target for the
  unguarded-error-path bug class), while ``SuperBomb`` raises a *random* exception from a wide
  set: spray-and-pray coverage of every protocol slot at once.

This module is embedded verbatim into generated fuzzing scripts, so it must stay
self-contained (only ``random`` + builtins) and import-safe.
"""

# Import the random *module* under a private alias. The generated script's boilerplate does
# ``from random import ..., random``, which rebinds the bare name ``random`` to the random()
# *function*; a private alias keeps this embedded code reaching the module's randint/choice.
import random as _bomb_random

# Weighted toward MemoryError (the unguarded-PyErr_Clear / swallowed-error bug class) but
# spanning the exceptions C code is most likely to mishandle when a slot raises unexpectedly.
_BOMB_EXCEPTIONS = (
    MemoryError,
    MemoryError,
    MemoryError,
    RecursionError,
    OverflowError,
    ValueError,
    TypeError,
    RuntimeError,
    KeyError,
    IndexError,
    StopIteration,
    SystemError,
    KeyboardInterrupt,
)


def _bomb_exc(exc=None):
    return exc if exc is not None else _bomb_random.choice(_BOMB_EXCEPTIONS)


class _BombBase:
    """Succeed a random ``delay`` (0..max_delay) times, then raise ``exc`` from armed slots."""

    def __init__(self, max_delay=3, exc=MemoryError):
        self._calls = 0
        self._delay = _bomb_random.randint(0, max_delay)
        self._exc = exc

    def _fire(self):
        self._calls += 1
        if self._calls > self._delay:
            raise _bomb_exc(self._exc)("fusil bomb")


class HashBomb(_BombBase):
    """__hash__ raises after the delay -- hits dict/set insert & lookup error paths."""

    def __hash__(self):
        self._fire()
        return 42

    def __eq__(self, other):
        return self is other


class EqBomb(_BombBase):
    """Comparison raises; stays hashable and looks sequence-ish to pass pre-checks."""

    def __eq__(self, other):
        self._fire()
        return NotImplemented

    def __ne__(self, other):
        self._fire()
        return NotImplemented

    def __hash__(self):
        return 0

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0


class IndexBomb(_BombBase):
    """Numeric coercion raises -- hits sequence-index / int-conversion error paths."""

    def __index__(self):
        self._fire()
        return 1

    def __int__(self):
        self._fire()
        return 1

    def __float__(self):
        self._fire()
        return 1.0


class LenBomb(_BombBase):
    """__len__ raises but __iter__ works -- length-then-iterate mismatch."""

    def __len__(self):
        self._fire()
        return 3

    def __iter__(self):
        return iter([1, 2, 3])


class LyingLen:
    """__len__ reports a huge size (over-allocation) but yields few items."""

    def __len__(self):
        return 1_000_000

    def __iter__(self):
        return iter([1, 2, 3])


class ReprBomb(_BombBase):
    """__repr__/__str__ raise -- hits error-formatting and logging paths in C."""

    def __repr__(self):
        self._fire()
        return "<ReprBomb>"

    __str__ = __repr__


class FailingIterator:
    """Yields a random few items, then raises mid-iteration (partial-mutation on
    extend/update/list()/dict-from-pairs)."""

    def __init__(self, max_items=4, exc=None):
        self._i = 0
        self._n = _bomb_random.randint(0, max_items)
        self._exc = exc

    def __iter__(self):
        return self

    def __next__(self):
        if self._i >= self._n:
            raise _bomb_exc(self._exc)("fusil iter bomb")
        self._i += 1
        return self._i


# --- SuperBomb: every protocol slot is a landmine ----------------------------------------
#
# Spray-and-pray. A metaclass installs a raising method for a broad set of dunders; each one
# raises a random exception, either on first use or after a per-instance random delay. The
# attribute/lifecycle dunders (__init__/__new__/__getattribute__/__setattr__/__del__/...) are
# deliberately left working so the object can be constructed and passed around to reach deep
# call sites before it detonates.

_SUPERBOMB_DUNDERS = (
    "__hash__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__call__",
    "__len__",
    "__length_hint__",
    "__bool__",
    "__contains__",
    "__int__",
    "__float__",
    "__index__",
    "__complex__",
    "__round__",
    "__trunc__",
    "__repr__",
    "__str__",
    "__format__",
    "__bytes__",
    "__fspath__",
    "__iter__",
    "__next__",
    "__reversed__",
    "__getitem__",
    "__setitem__",
    "__delitem__",
    "__missing__",
    "__add__",
    "__radd__",
    "__iadd__",
    "__sub__",
    "__rsub__",
    "__mul__",
    "__rmul__",
    "__mod__",
    "__divmod__",
    "__pow__",
    "__truediv__",
    "__floordiv__",
    "__matmul__",
    "__neg__",
    "__pos__",
    "__abs__",
    "__invert__",
    "__and__",
    "__or__",
    "__xor__",
    "__lshift__",
    "__rshift__",
    "__enter__",
    "__exit__",
    "__get__",
    "__set__",
    "__delete__",
    "__aiter__",
    "__anext__",
    "__await__",
    "__ceil__",
    "__floor__",
)


def _make_superbomb_slot(name):
    def _slot(self, *args, **kwargs):
        counts = self._bomb_calls
        counts[name] = counts.get(name, 0) + 1
        if counts[name] > self._bomb_delay:
            raise _bomb_exc()("fusil superbomb via %s" % name)

    _slot.__name__ = name
    return _slot


class _SuperBombMeta(type):
    def __new__(mcls, cname, bases, namespace):
        for _name in _SUPERBOMB_DUNDERS:
            namespace.setdefault(_name, _make_superbomb_slot(_name))
        return super().__new__(mcls, cname, bases, namespace)


class SuperBomb(metaclass=_SuperBombMeta):
    """Every protocol dunder raises a random exception on first use or after a random delay."""

    def __init__(self, max_delay=3):
        # object.__setattr__: __setattr__ itself is not armed, but keep construction robust
        # regardless of what a subclass/metaclass does.
        object.__setattr__(self, "_bomb_calls", {})
        object.__setattr__(self, "_bomb_delay", _bomb_random.randint(0, max_delay))


# --- File-like bombs (target the common "try fd, else .read()" C pattern) ----------------


class ReadBomb(_BombBase):
    """A file-like whose read()/readline() succeed a random few times, then raise -- the
    delayed mid-parse failure that surfaces partial-read error handling."""

    def read(self, *args, **kwargs):
        self._fire()
        return b""

    def readline(self, *args, **kwargs):
        self._fire()
        return b""

    def readlines(self, *args, **kwargs):
        self._fire()
        return []

    def __iter__(self):
        return iter((b"line\n",))

    def seek(self, *args, **kwargs):
        return 0

    def tell(self):
        return 0

    def close(self):
        pass


class WrongTypeFile:
    """read() returns the wrong type (int, not bytes/str) -- targets C code that assumes the
    return of read() is a buffer."""

    def read(self, *args, **kwargs):
        return 123456

    def readline(self, *args, **kwargs):
        return 123456

    def close(self):
        pass


class FilenoBomb:
    """fileno() raises (looks like a bad/again fd) while read() keeps working -- targets the
    'try obj.fileno(), fall back to obj.read()' branch and its error handling."""

    def fileno(self):
        raise _bomb_exc()("fusil fileno bomb")

    def read(self, *args, **kwargs):
        return b""

    def readable(self):
        return True

    def close(self):
        pass


# --- Metaclass / descriptor bombs (target attribute-access C paths) ----------------------


class _HiddenNameMeta(type):
    """Metaclass whose attribute access raises for the identity names C code reads unchecked
    (``Py_TYPE(obj)->tp_name`` analogues via ``PyObject_GetAttrString(cls, "__name__")``)."""

    def __getattribute__(cls, name):
        if name in ("__name__", "__qualname__", "__module__"):
            raise _bomb_exc()("fusil hidden name: %s" % name)
        return super().__getattribute__(name)


class HiddenNameType(metaclass=_HiddenNameMeta):
    """A *class* (pass it, don't instantiate) whose __name__/__qualname__/__module__ raise."""


class _RaisingGet:
    """A data descriptor whose __get__/__set__ raise -- hits unguarded PyErr_Clear in getattr
    fallbacks when installed on a commonly-probed attribute name."""

    def __get__(self, obj, objtype=None):
        raise _bomb_exc()("fusil descriptor get")

    def __set__(self, obj, value):
        raise _bomb_exc()("fusil descriptor set")


class DescriptorBomb:
    """An instance whose class carries raising data-descriptors on attribute names C code
    commonly probes."""

    value = _RaisingGet()
    name = _RaisingGet()
    read = _RaisingGet()
    __wrapped__ = _RaisingGet()


class _StatefulHashMeta(type):
    """Metaclass hash that succeeds at first (registration) then raises after a random delay --
    targets type-keyed registries (``PyDict_GetItem`` on a class key that changes hashability)."""

    def __new__(mcls, name, bases, namespace):
        cls = super().__new__(mcls, name, bases, namespace)
        # list cell so __hash__ can mutate without triggering __setattr__ machinery
        cls._bomb_hash_state = [0, _bomb_random.randint(0, 3)]
        return cls

    def __hash__(cls):
        state = super().__getattribute__("_bomb_hash_state")
        state[0] += 1
        if state[0] > state[1]:
            raise _bomb_exc()("fusil stateful hash")
        return 0


class StatefulHashType(metaclass=_StatefulHashMeta):
    """A *class* (pass it, don't instantiate) whose hash works, then arms and starts raising."""


# Names the argument generator instantiates (as ``Name()``); every class constructs with no
# required arguments and self-randomises its delay/exception.
BOMB_CLASS_NAMES = [
    "HashBomb",
    "EqBomb",
    "IndexBomb",
    "LenBomb",
    "LyingLen",
    "ReprBomb",
    "FailingIterator",
    "SuperBomb",
    "ReadBomb",
    "WrongTypeFile",
    "FilenoBomb",
    "DescriptorBomb",
]

# Names the argument generator passes *as the class object itself* (not instantiated) -- the
# bomb is the type: a metaclass turns attribute/hash access on the class into a landmine.
BOMB_TYPE_NAMES = [
    "HiddenNameType",
    "StatefulHashType",
]


def errback(*args, **kw):
    raise ValueError('errback called')


class Liar1:
    def __eq__(self, other):
        return True

class Liar2:
    def __eq__(self, other):
        return False

liar1, liar2 = Liar1(), Liar2()

class Evil:
    def __eq__(self, other):
        for attr in dir(other):
            try: other.__dict__[attr] = errback
            except: pass

evil = Evil()


# Define a custom exception to distinguish our check from others.
class JITCorrectnessError(AssertionError): pass

# Helper for correctness testing that handles NaN, lambdas, and complex numbers.
import math
import types
def compare_results(a, b):
    if isinstance(a, types.FunctionType) and a.__name__ == '<lambda>' and \
       isinstance(b, types.FunctionType) and b.__name__ == '<lambda>':
        return True # Treat two lambdas as equal for our purposes
    if isinstance(a, complex) and isinstance(b, complex):
        a_real_nan = math.isnan(a.real)
        b_real_nan = math.isnan(b.real)
        a_imag_nan = math.isnan(a.imag)
        b_imag_nan = math.isnan(b.imag)
        real_match = (a.real == b.real) or (a_real_nan and b_real_nan)
        imag_match = (a.imag == b.imag) or (a_imag_nan and b_imag_nan)
        return real_match and imag_match
    if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
        return True
    if isinstance(a, object) and isinstance(b, object):
        return True
    if isinstance(a, tuple) and isinstance(b, tuple) and len(a) == len(b):
        return all(compare_results(x, y) for x, y in zip(a, b))
    return a == b

SENTINEL_VALUE = object()

def callMethod(prefix, obj_to_call, method_name, *arguments, verbose=True):
    func_display_name = f"fakemod.{method_name}()" if obj_to_call is fakemod else f"{obj_to_call.__class__.__name__}.{method_name}()"
    message = f"[{prefix}] {func_display_name}"
    if verbose:
        print(message, file=stderr)
    result = SENTINEL_VALUE
    try:
        func_to_run = getattr(obj_to_call, method_name)
        for _ in range(int(3)):
            result = func_to_run(*arguments)
    except (Exception, SystemExit, KeyboardInterrupt) as err:
        try:
            errmsg = repr(err)
        except Exception as e_repr:
            errmsg = f'Error during repr: {e_repr.__class__.__name__}'
        errmsg = errmsg.encode('ASCII', 'replace').decode('ASCII')
        if verbose:
            print(f"[{prefix}] {func_display_name} => EXCEPTION: {err.__class__.__name__}: {errmsg}", file=stderr)
        result = SENTINEL_VALUE
    if verbose:
        print(f"[{prefix}] -explicit garbage collection-", file=stderr)
    collect()
    return result

def callFunc(prefix, func_name_str, *arguments, verbose=True):
    return callMethod(prefix, fakemod, func_name_str, *arguments, verbose=verbose)

fuzz_target_module = fakemod



# FUSIL_BOILERPLATE_END


import sys
from random import choice, randint, random, sample
from sys import stderr, path as sys_path


print("--- Fuzzing 2 functions in fakemod ---", file=stderr)
res_f1 = callFunc("f1", "func_a",
verbose=True)


res_f2 = callFunc("f2", "func_a",
verbose=True)


res_f3 = callFunc("f3", "func_a",
    None,
verbose=True)



print("--- Fuzzing 1 classes in fakemod ---", file=stderr)
print("[c1] Attempting to instantiate class: Widget", file=stderr)
instance_c1_widget = None # Initialize instance variable
try:
    instance_c1_widget = callFunc('c1_init', 'Widget',
      )
except Exception as e_instantiate:
    instance_c1_widget = None
    print("[c1] Failed to instantiate Widget: {e_instantiate.__class__.__name__} {e_instantiate}", file=stderr)
    instance_c1_widget = None

try:
    print(f"--- (Depth 0) Dispatching Fuzz for: { instance_c1_widget!r } (hint: Widget, prefix: c1_widget_ops) ---", file=stderr)
except Exception as e:
    print(f"--- (Depth 0) Error calling repr() prefix: c1_widget_ops) ---", file=stderr)
if instance_c1_widget is not None:
    if skip_trivial_type(instance_c1_widget):
        print(f'Skipping deep diving on instance_c1_widget {type(instance_c1_widget)}', file=stderr)
    try:
        print(f'Instance { instance_c1_widget!r } (actual type {type(instance_c1_widget).__name__}) has no specific fuzzer type, doing generic calls.', file=stderr)
    except Exception as e:
        print(f'Error printing instance repr() { e } (actual type {type(instance_c1_widget).__name__}) has no specific fuzzer type, doing generic calls.', file=stderr)
    if skip_trivial_type(instance_c1_widget):
        print(f'Skipping deep diving on instance_c1_widget {type(instance_c1_widget)}', file=stderr)
    else:
        print(f'Instance instance_c1_widget (type {type(instance_c1_widget).__name__}) has no specific fuzzer, doing generic calls.', file=stderr)
        c1_widget_ops_generic_methods = []
        try:
            for c1_widget_ops_generic_attr_name in dir(instance_c1_widget):
                if c1_widget_ops_generic_attr_name.startswith('_'): continue
                try:
                    c1_widget_ops_generic_attr_val = getattr(instance_c1_widget, c1_widget_ops_generic_attr_name)
                    if callable(c1_widget_ops_generic_attr_val) and not c1_widget_ops_generic_attr_val.__name__ in ('wait', '_rehash'): c1_widget_ops_generic_methods.append((c1_widget_ops_generic_attr_name, c1_widget_ops_generic_attr_val))
                except Exception: pass
        except Exception: c1_widget_ops_generic_methods = [] # Failed to get methods
        if c1_widget_ops_generic_methods:
            print(f'Found {len(c1_widget_ops_generic_methods)} callable methods for generic fuzzing of instance_c1_widget', file=stderr)
            for _i_c1_widget_ops_generic in range(min(len(c1_widget_ops_generic_methods), 2)):
                c1_widget_ops_generic_method_name_to_call, c1_widget_ops_generic_method_obj_to_call = choice(c1_widget_ops_generic_methods)
                # Conceptual call to generic method fuzzer
                if c1_widget_ops_generic_method_name_to_call not in ('wait', '_rehash'): callMethod(f'c1_widget_ops_generic_gen{_i_c1_widget_ops_generic}', instance_c1_widget, c1_widget_ops_generic_method_name_to_call)

if instance_c1_widget is not None and instance_c1_widget is not SENTINEL_VALUE:
    print(f"--- Fuzzing instance: instance_c1_widget (type hint: Widget, prefix: c1m) ---", file=stderr)
    if skip_trivial_type(instance_c1_widget):
        print(f'Skipping deep diving on instance_c1_widget {type(instance_c1_widget)}', file=stderr)
    # General method fuzzing for instance_c1_widget
    res_c1m1 = callMethod("c1m1", instance_c1_widget, "method_two",
        list[weird_classes['weird_OrderedDict']] | weird_classes['weird_set'] | big_union,
    verbose=True)


    res_c1m2 = callMethod("c1m2", instance_c1_widget, "method_one",
    verbose=True)


    print(f"--- Finished fuzzing instance: instance_c1_widget ---", file=stderr)

    del instance_c1_widget # Cleanup instance
    print("[c1] -explicit garbage collection for class instance-", file=stderr)
    collect()



