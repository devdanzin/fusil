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
# Writing f_locals is a CPython frame detail (PEP 667 in 3.13); on interpreters where
# it is a read-only snapshot the .update() can raise TypeError/AttributeError, not just
# RuntimeError -- catch broadly so this best-effort frame pollution never aborts the script.
except Exception:
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


# --- Recursion-shape probes: map the unguarded-native-recursion crash class (RustPython #2796).
# Each object re-enters a protocol on a PARTNER object, so the recursion crosses object boundaries
# (mutual recursion, harder to short-circuit than plain self-recursion). CPython raises
# RecursionError on the protocol call; an interpreter without a recursion guard on that native
# path overflows its C/Rust stack -> segfault. Construction is cheap -- the recursion fires only
# when the fuzzer exercises the named protocol (hash/eq/getitem/iter/repr/call) on the object.
class _TrickyRecur:
    def __init__(self, name):
        self.name = name
        self.partner = self  # rebound to a partner below for mutual recursion

    def __hash__(self):
        return hash(self.partner)

    def __eq__(self, other):
        return self.partner == other

    def __getitem__(self, key):
        return self.partner[key]

    def __iter__(self):
        return iter(self.partner)

    def __repr__(self):
        return repr(self.partner)

    def __call__(self, *args, **kwargs):
        return self.partner(*args, **kwargs)


tricky_recur_a = _TrickyRecur("a")
tricky_recur_b = _TrickyRecur("b")
tricky_recur_a.partner = tricky_recur_b
tricky_recur_b.partner = tricky_recur_a

# Deep generic-alias nesting list[list[...list[T]...]] bottomed on a TypeVar so the parameter walk
# actually recurses to collect it -- exercises the genericalias parameter-walk native path
# (RustPython segfaulted in genericalias::make_parameters_from_slice). Bounded depth so construction
# + a CPython repr stay well under the recursion limit; the native walk (and __getitem__
# substitution) is the target. Falls back to a plain nested alias if TypeVar is unavailable.
try:
    from typing import TypeVar as _TrickyTypeVar

    _TrickyGAT = _TrickyTypeVar("_TrickyGAT")
    _tricky_ga = _TrickyGAT
except Exception:
    _tricky_ga = list
try:
    for _ in range(80):
        _tricky_ga = list[_tricky_ga]
    tricky_deep_genericalias = _tricky_ga
except Exception:
    tricky_deep_genericalias = None
