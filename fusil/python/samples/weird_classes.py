import sys
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
