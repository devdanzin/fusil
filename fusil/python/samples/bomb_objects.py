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
    # Only Exception subclasses belong here. BaseException types (KeyboardInterrupt,
    # SystemExit, GeneratorExit) escape the generated `except Exception` handlers, so a bomb
    # raising one aborts the whole session (SIGINT / nonzero exit) as a false crash rather
    # than exercising the target's error handling.
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


# --- Reentrant-mutation bombs: MUTATE the container mid-operation (not just raise) --------
#
# The exception bombs above make a protocol slot RAISE; these make it MUTATE the very
# container the running C operation is iterating -- the reentrancy / use-after-free class.
# When a C sequence/mapping routine borrows a container's internal storage (``ob_item`` array,
# hash-table ``entries``) and then calls back into Python -- to compare (``__eq__``/``__lt__``),
# hash (``__hash__``), or convert (``__index__``) an element -- clearing or resizing that
# container from inside the callback frees/reallocates the borrowed pointer mid-loop. Core
# CPython's own list/dict routines mostly re-check the size after each callback, but a great
# deal of C-EXTENSION code (and less-trodden CPython C paths) caches the raw pointer once and
# indexes it, so these objects are the protocol-slot analogue of an OOM injection aimed at the
# reentrancy error path rather than the allocation-failure one. The mutation is DELAYED a few
# calls (like the exception bombs) so a partially-consumed C loop is holding a live borrowed
# pointer when it fires, rather than emptying the container before the loop starts.


class _ClearParent:
    """An element that clears the container holding it, from inside a comparison/hash/index
    callback. Seeded into ``ReentrantClearList`` / ``ReentrantClearDict``; not used directly."""

    def __init__(self, parent, max_delay=2):
        self._parent = parent
        self._calls = 0
        self._delay = _bomb_random.randint(0, max_delay)

    def _maybe_pull(self):
        self._calls += 1
        if self._calls > self._delay:
            parent = self._parent
            try:
                parent.clear()
            except Exception:
                try:
                    del parent[:]
                except Exception:
                    pass

    def __eq__(self, other):
        self._maybe_pull()
        return False

    def __lt__(self, other):
        self._maybe_pull()
        return True

    def __gt__(self, other):
        self._maybe_pull()
        return False

    def __hash__(self):
        self._maybe_pull()
        return 0

    def __index__(self):
        self._maybe_pull()
        return 0

    __int__ = __index__


class ReentrantClearList(list):
    """A pre-armed ``list``: it contains a self-clearing element, so any C op that compares,
    hashes, or index-converts its items -- ``x in l`` / ``l.index(x)`` / ``l.sort()`` /
    ``min(l)`` / ``max(l)`` / ``set(l)`` / ``bytes(l)``, or a C-extension routine iterating a
    list argument -- can free the item array mid-loop (reentrant use-after-free)."""

    def __init__(self):
        super().__init__()
        head = _bomb_random.randint(1, 4)
        self.extend(range(head))
        self.append(_ClearParent(self))
        self.extend(range(head, head + _bomb_random.randint(2, 6)))


class ReentrantClearDict(dict):
    """A pre-armed ``dict``: a stored VALUE clears the dict from inside a comparison, so a C op
    that compares the mapping's values -- ``d == other`` / dict richcompare, or a C-extension
    routine walking a dict argument's values -- can free the entry table mid-walk."""

    def __init__(self):
        super().__init__()
        for i in range(_bomb_random.randint(1, 3)):
            self[i] = i
        self["_fusil_pull"] = _ClearParent(self)
        for i in range(_bomb_random.randint(1, 3)):
            self["k%d" % i] = i


class MutatingIterable:
    """A hostile iterable whose ``__length_hint__`` lies (huge / zero / negative) and whose
    iterator mutates its own backing store mid-iteration. C consumers that PRESIZE a buffer
    from the hint and then fill it by iterating -- ``list()`` / ``tuple()`` / ``bytes()`` /
    ``b"".join()`` / ``set()`` / ``[*it]`` / ``PySequence_Tuple`` / ``_PyList_Extend`` -- can
    over-read or write past the presized buffer when the real yield count disagrees."""

    def __init__(self):
        self._data = list(range(_bomb_random.randint(4, 16)))
        # A lie about the yield count: 0/1 (undersize -> grow path), -1 (negative -> the
        # unguarded-negative presize/ValueError vector), and a large-but-not-guaranteed-OOM
        # over-report (8 MB presize, not 8 TB -- a sprayed bomb must not just raise MemoryError).
        self._hint = _bomb_random.choice([0, 1, -1, 1 << 16, 1 << 20])

    def __length_hint__(self):
        return self._hint

    def __iter__(self):
        data = self._data

        def _gen():
            for i, value in enumerate(list(data)):
                if i == 1:
                    data.clear()
                elif i == 2:
                    data.extend(range(1 << 10))
                yield value

        return _gen()


# --- Stateful / lying bombs: the protocol slot SUCCEEDS but returns an INCONSISTENT answer ---
#
# The exception bombs raise; the reentrant bombs mutate a container. These lie *quietly*: a slot
# returns a value that is internally inconsistent across calls (or with a sibling slot), so C
# code that reads it once to size/plan and then trusts it -- preallocating a buffer from __len__,
# storing under a cached __hash__, specializing on the first element's type -- writes past the
# buffer, lands in the wrong hash bucket, or trips a type fast-path. The lie is DELAYED (like the
# other bombs) so the C routine has already committed to the first answer when it changes.


class GrowingLen:
    """__len__ under-reports on its first read (small presize) then reports a much larger size,
    while __getitem__ / __iter__ yield up to the larger count. C code that presizes a buffer from
    the first __len__ and then fills by index/iteration can write past it (the __len__-lies-small
    buffer-preallocation class; complements LyingLen, which only over-reports)."""

    def __init__(self):
        self._calls = 0
        self._small = _bomb_random.choice([0, 1, 2])
        self._big = _bomb_random.choice([64, 256, 4096])

    def __len__(self):
        self._calls += 1
        return self._small if self._calls <= 1 else self._big

    def __getitem__(self, index):
        if not isinstance(index, int) or index >= self._big or index < 0:
            raise IndexError(index)
        return index

    def __iter__(self):
        return iter(range(self._big))


class MutatingHash:
    """__hash__ is constant for a few calls -- long enough to be stored as a dict/set key -- then
    starts returning different values, violating hash-constancy while the object is a live key.
    A C hash table that cached the original hash now finds the key in the wrong bucket (lookup
    miss / KeyError, or a corrupted probe sequence in a less-hardened C-extension mapping)."""

    def __init__(self):
        self._calls = 0
        self._delay = _bomb_random.randint(1, 3)

    def __hash__(self):
        self._calls += 1
        if self._calls <= self._delay:
            return 0
        return _bomb_random.randrange(1 << 60)

    def __eq__(self, other):
        return self is other


class TypeFlipIterator:
    """Yields a consistent type (ints) for a few items, then flips to an incompatible type
    (str / None / float / a bare object) mid-stream, feeding C reducers that may specialize on
    the first element's type -- max() / min() / sum() / sorted() / bytes() / b"".join() / heapq --
    a wrong type after the fast-path has committed."""

    def __init__(self):
        self._i = 0
        self._n = _bomb_random.randint(2, 8)
        self._flip = _bomb_random.choice(["str", "none", "float", "obj"])

    def __iter__(self):
        return self

    def __next__(self):
        self._i += 1
        if self._i > self._n + 4:
            raise StopIteration
        if self._i <= self._n:
            return self._i  # a consistent run of ints
        return {"str": "x", "none": None, "float": 1.5, "obj": object()}[self._flip]


# --- Lying-equality bombs: hashable + storable, but == / identity lie -------------------------
#
# The stateful/lying bombs above lie about size/type; these lie about EQUALITY. They are cheap
# to hash and store (a stable, colliding hash) so a C container accepts them as a key/member,
# but their __eq__ then contradicts identity -- claiming equal to a value they are not, or giving
# a different answer on each call. C code that assumes `a == b` implies interchangeability, caches
# a slot after one comparison, or maintains its own hash table (a C-extension mapping) can probe
# the wrong bucket, double-store, or read a stale entry. On core dict/set this desyncs values;
# in a less-hardened C-extension container it can corrupt the table.


class LyingEq:
    """Hashes like the int ``1`` (a deliberate collision) and claims __eq__ equality with 1 and
    every small int, and __index__/__int__ return 1 -- yet it is a distinct object that is not 1.
    Used as a dict key / set member / sequence index it desyncs "equal-but-not-identical": stored
    and found under hash(1), but not actually interchangeable with the ints it claims to equal."""

    def __eq__(self, other):
        return other == 1 or (isinstance(other, int) and -5 <= other <= 256)

    def __hash__(self):
        return hash(1)

    def __index__(self):
        return 1

    __int__ = __index__


class ShiftyEq:
    """__eq__ flips its answer every few calls, so a single C routine that compares this object
    more than once (insert-then-lookup in a hash table, a membership scan, a sort) sees the
    equality relation change underneath it. __hash__ stays constant so it remains storable."""

    def __init__(self):
        self._calls = 0
        self._period = _bomb_random.randint(2, 4)

    def __eq__(self, other):
        self._calls += 1
        return (self._calls // self._period) % 2 == 0

    def __hash__(self):
        return 0


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
    # reflected binary ops (right-hand operand) -- reached when the LEFT operand returns
    # NotImplemented, a callback an alternative interpreter may .unwrap() unguarded.
    "__rmod__",
    "__rdivmod__",
    "__rpow__",
    "__rtruediv__",
    "__rfloordiv__",
    "__rmatmul__",
    "__rand__",
    "__ror__",
    "__rxor__",
    "__rlshift__",
    "__rrshift__",
    # in-place ops (augmented assignment) -- a distinct set of number-protocol slots.
    "__imul__",
    "__isub__",
    "__imod__",
    "__ipow__",
    "__itruediv__",
    "__ifloordiv__",
    "__imatmul__",
    "__iand__",
    "__ior__",
    "__ixor__",
    "__ilshift__",
    "__irshift__",
    # buffer protocol (PEP 688) -- a raising __buffer__ detonates a native buffer acquisition
    # (memoryview(...), struct/array/C-level readbuffer), an error path C code often skips.
    "__buffer__",
    "__release_buffer__",
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
    # Reentrant-mutation bombs: MUTATE the container mid-C-operation (reentrancy / UAF class),
    # rather than raising. Self-contained, built with no required args, arg-injectable like the rest.
    "ReentrantClearList",
    "ReentrantClearDict",
    "MutatingIterable",
    # Stateful / lying bombs: a slot SUCCEEDS but returns an inconsistent answer across calls
    # (__len__ grows, __hash__ changes while keyed, iterator flips element type mid-stream).
    "GrowingLen",
    "MutatingHash",
    "TypeFlipIterator",
    # Lying-equality bombs: hashable + storable, but __eq__ / identity lie (claim equal to a
    # value they are not, or flip the answer on each call) -- desyncs C hash tables.
    "LyingEq",
    "ShiftyEq",
]

# Names the argument generator passes *as the class object itself* (not instantiated) -- the
# bomb is the type: a metaclass turns attribute/hash access on the class into a landmine.
BOMB_TYPE_NAMES = [
    "HiddenNameType",
    "StatefulHashType",
]
