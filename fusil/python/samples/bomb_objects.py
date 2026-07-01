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

import random

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
    return exc if exc is not None else random.choice(_BOMB_EXCEPTIONS)


class _BombBase:
    """Succeed a random ``delay`` (0..max_delay) times, then raise ``exc`` from armed slots."""

    def __init__(self, max_delay=3, exc=MemoryError):
        self._calls = 0
        self._delay = random.randint(0, max_delay)
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
        self._n = random.randint(0, max_items)
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
        object.__setattr__(self, "_bomb_delay", random.randint(0, max_delay))


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
]
