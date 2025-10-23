"""
This module generates tricky inputs for fuzzing cereggii.AtomicDict.

It focuses on creating objects with non-standard, malicious, or unstable
__hash__ and __eq__ methods to probe the robustness of the hash table's
C implementation.
"""

import cereggii
import itertools
import random
import collections.abc
import sys

# --- 1. Imports from other tricky modules ---
# We gather a wide range of pre-existing tricky objects to use as keys/values.
# This is wrapped in try-except to allow this module to run standalone.
try:
    from fusil.python.samples import tricky_objects, weird_classes  # , tricky_numpy

    _HAS_DEPS = True
except ImportError:
    _HAS_DEPS = False
    print(
        "Warning: Sibling tricky modules not found. Key/value variety will be limited.",
        file=sys.stderr,
    )


# --- 2. Malicious Classes for Hashing & Equality Hell ---
# This suite of classes is designed to violate the core contracts of Python's
# hashing and equality, targeting the underlying assumptions of any hash table.

_unstable_hash_counter = itertools.count()


class UnstableHash:
    """
    An object whose hash value changes every time it is requested.
    This violates the rule that an object's hash must be constant during its
    lifetime if it is in a hash-based collection.
    """

    def __init__(self):
        # Store the initial hash to have a stable representation, even if the
        # internal hash is unstable.
        self._initial_hash = next(_unstable_hash_counter)

    def __hash__(self):
        return next(_unstable_hash_counter)

    def __eq__(self, other):
        return (
            isinstance(other, UnstableHash)
            and self._initial_hash == other._initial_hash
        )

    def __repr__(self):
        return f"<UnstableHash initial_hash={self._initial_hash}>"


class AlwaysEqualButRandomHash:
    """
    An object that claims to be equal to everything, but provides a different
    random hash each time. This forces hash collisions to be resolved by __eq__,
    stressing the collision resolution path.
    """

    def __hash__(self):
        return random.randint(-sys.maxsize - 1, sys.maxsize)

    def __eq__(self, other):
        return True

    def __repr__(self):
        return "<AlwaysEqualButRandomHash>"


class AlwaysUnequalConstantHash:
    """
    An object that is never equal to anything (even itself, unless via identity),
    but always has the same hash. This is designed to create a massive number
    of hash collisions in a single bucket, forcing the C implementation to
    traverse a long probe sequence.
    """

    def __hash__(self):
        return 42  # A classic constant hash value

    def __eq__(self, other):
        return False  # Never equal

    def __repr__(self):
        return f"<AlwaysUnequalConstantHash id={id(self)}>"


class ExceptionRaiser:
    """
    A base for objects that raise exceptions from within __hash__ or __eq__.
    This allows us to test C-level exception handling during core dict operations.
    """

    def __init__(self, exc_type=ValueError, msg="fuzzer-induced exception"):
        self.exc_type = exc_type
        self.msg = msg
        # A simple unique identifier for repr
        self._id = next(_unstable_hash_counter)

    def _raise(self):
        raise self.exc_type(self.msg)

    def __repr__(self):
        return (
            f"<{self.__class__.__name__} raises={self.exc_type.__name__} id={self._id}>"
        )


class HashRaisesException(ExceptionRaiser):
    """An object that raises an exception when its hash is computed."""

    def __hash__(self):
        self._raise()

    def __eq__(self, other):
        return self is other  # Should not be reached if hash fails


class EqRaisesException(ExceptionRaiser):
    """An object with a constant hash that raises an exception on equality check."""

    def __hash__(self):
        return 101  # Another constant hash

    def __eq__(self, other):
        self._raise()


class EqReturnsWrongType:
    """
    An object with a constant hash whose __eq__ method returns a non-boolean value.
    This tests the C code's handling of unexpected return types from comparisons.
    """

    def __init__(self, return_value):
        self.return_value = return_value

    def __hash__(self):
        return 255  # Yet another constant hash

    def __eq__(self, other):
        return self.return_value

    def __repr__(self):
        return f"<EqReturnsWrongType returns={self.return_value!r}>"


# --- Sanity Check ---
print("Defined malicious classes for hashing and equality.")


# --- 3. Aggregate Tricky Hashable Keys ---
# A comprehensive dictionary of objects that are technically hashable but are
# designed to stress the hash table implementation. This serves as a rich
# pool of keys for fuzzing operations.

tricky_hashable_keys = {}

# Instantiate our malicious classes
for i in range(5):
    tricky_hashable_keys[f"unstable_hash_{i}"] = UnstableHash()
    tricky_hashable_keys[f"always_equal_random_hash_{i}"] = AlwaysEqualButRandomHash()
for i in range(20):  # More of these to create collisions
    tricky_hashable_keys[f"always_unequal_constant_hash_{i}"] = (
        AlwaysUnequalConstantHash()
    )

# Instances that raise various exceptions from __hash__ or __eq__
for exc in [
    ValueError,
    TypeError,
    AttributeError,
    RecursionError,
    IndexError,
    KeyError,
]:
    tricky_hashable_keys[f"hash_raises_{exc.__name__}"] = HashRaisesException(exc)
    tricky_hashable_keys[f"eq_raises_{exc.__name__}"] = EqRaisesException(exc)

# Instances that return non-boolean values from __eq__
for ret_val in [None, 0, 1, "not a boolean", (1, 2), AlwaysUnequalConstantHash()]:
    tricky_hashable_keys[f"eq_returns_{type(ret_val).__name__}"] = EqReturnsWrongType(
        ret_val
    )

# Add fundamental edge-case hashables
tricky_hashable_keys["none"] = None
tricky_hashable_keys["true"] = True
tricky_hashable_keys["false"] = False
tricky_hashable_keys["float_nan"] = float("nan")
tricky_hashable_keys["float_inf"] = float("inf")
tricky_hashable_keys["empty_tuple"] = ()
tricky_hashable_keys["empty_frozenset"] = frozenset()

# Gather all hashable objects from our other tricky modules
if _HAS_DEPS:
    all_tricky_sources = {
        "tricky_obj": tricky_objects.__dict__,
        "weird_cls": weird_classes.weird_instances,
        # "tricky_np": tricky_numpy.__dict__,
    }
    for source_name, source_dict in all_tricky_sources.items():
        for name, obj in source_dict.items():
            if isinstance(name, str) and not name.startswith("_"):
                try:
                    if isinstance(obj, collections.abc.Hashable):
                        tricky_hashable_keys[f"{source_name}_{name}"] = obj
                except Exception:
                    # Some objects might fail even on isinstance checks
                    continue


# --- 4. Pre-populated Malicious AtomicDict Instances ---
# A collection of AtomicDicts that are already initialized with problematic
# keys and structures. These serve as ready-made targets for fuzzing operations
# like get, set, delete, reduce, etc.

tricky_atomic_dicts = {}

# "Collision Hell": A dict with many keys that have the same hash but are not equal.
# This forces the C implementation to traverse a long probe sequence.
collision_hell_dict = cereggii.AtomicDict()
for i in range(50):
    collision_hell_dict[AlwaysUnequalConstantHash()] = i
tricky_atomic_dicts["atomicdict_collision_hell"] = collision_hell_dict

# "Unstable Hash": A dict populated with keys whose hash value changes.
unstable_hash_dict = cereggii.AtomicDict()
for i in range(10):
    unstable_hash_dict[UnstableHash()] = i
tricky_atomic_dicts["atomicdict_unstable_hash"] = unstable_hash_dict

# "Weird Keys": A dict populated with a diverse sample of weird but hashable keys.
weird_keys_dict = cereggii.AtomicDict()
# Take a sample of our tricky keys to populate the dict
sample_keys = list(tricky_hashable_keys.values())
random.shuffle(sample_keys)
for i, key in enumerate(sample_keys[:50]):  # Populate with up to 50 weird keys
    try:
        weird_keys_dict[key] = i
    except Exception:  # Some keys might fail insertion, which is fine
        continue
tricky_atomic_dicts["atomicdict_weird_keys"] = weird_keys_dict

# "Recursive Dict": A dict that contains a reference to itself.
recursive_dict = cereggii.AtomicDict()
recursive_dict["self_ref"] = recursive_dict
tricky_atomic_dicts["atomicdict_self_recursive"] = recursive_dict

# "Cross-Recursive Dicts": Two dicts that reference each other.
cross_recursive_dict1 = cereggii.AtomicDict()
cross_recursive_dict2 = cereggii.AtomicDict()
cross_recursive_dict1["other"] = cross_recursive_dict2
cross_recursive_dict2["other"] = cross_recursive_dict1
tricky_atomic_dicts["atomicdict_cross_recursive_1"] = cross_recursive_dict1
tricky_atomic_dicts["atomicdict_cross_recursive_2"] = cross_recursive_dict2

# An AtomicDict initialized from a standard recursive Python dict
try:
    std_recursive_dict = {}
    std_recursive_dict["self"] = std_recursive_dict
    tricky_atomic_dicts["atomicdict_from_std_recursive"] = cereggii.AtomicDict(
        std_recursive_dict
    )
except Exception:
    pass  # This might raise RecursionError, which is fine

# --- Sanity Check ---
print(f"Aggregated {len(tricky_hashable_keys)} tricky hashable keys.")
print(
    f"Created {len(tricky_atomic_dicts)} pre-populated malicious AtomicDict instances."
)
