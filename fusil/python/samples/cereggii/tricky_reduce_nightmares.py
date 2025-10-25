"""
This module creates a collection of malicious inputs ("nightmares") specifically
designed to break the `cereggii.AtomicDict.reduce` family of methods.

The attacks focus on three areas:
1.  Malicious Iterables: Iterators that misbehave during iteration.
2.  Malicious Aggregate Functions: Callbacks for `reduce()` that violate
    the expected contract (e.g., by raising exceptions, returning wrong types,
    or causing re-entrant modifications).
3.  Problematic Datasets: Data with types that are invalid for the specialized
    `reduce_*` methods (e.g., non-numeric data for `reduce_sum`).
"""

import cereggii
import time
import itertools
import sys

# --- 1. Imports ---
try:
    from fusil.python.samples.cereggii import tricky_atomicdict
except ImportError:
    tricky_atomicdict = None
    print("Warning: 'tricky_atomicdict.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples.weird_classes import weird_instances as _weird_instances
except ImportError:
    _weird_instances = None
    print("Warning: 'weird_classes.py' not found.", file=sys.stderr)


# --- 2. Malicious Iterables ---
# These classes produce iterators that violate the contract of a well-behaved
# iterable, testing the C-level error handling of the reduce loop.


class IterableRaiser:
    """An iterator that raises a specified exception after N successful yields."""

    def __init__(self, exception_to_raise, valid_yields=2):
        self.exception_to_raise = exception_to_raise
        self.valid_yields = valid_yields
        self.yield_count = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.yield_count < self.valid_yields:
            self.yield_count += 1
            return (f"key_{self.yield_count}", self.yield_count)
        raise self.exception_to_raise


class MalformedItemIterable:
    """An iterator that yields items that are not valid (key, value) 2-tuples."""

    def __init__(self):
        self.items = [
            None,
            123,
            ("a", "b", "c"),  # 3-tuple
            "just a string",
        ]
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.items):
            item = self.items[self.index]
            self.index += 1
            return item
        raise StopIteration


class NonHashableKeyIterable:
    """An iterator that yields a tuple with a non-hashable key."""

    def __iter__(self):
        # A list is not hashable
        yield (["a", "list", "key"], 1)


class ReentrantIterable:
    """
    A malicious iterator that attempts to modify the dictionary it is being
    used on *during* iteration. This is a re-entrancy attack.
    """

    def __init__(self, target_dict):
        self.target_dict = target_dict
        self.calls = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.calls += 1
        if self.calls == 1:
            return ("initial_key", 1)
        if self.calls == 2:
            # Side effect: Mutate the dictionary mid-iteration
            try:
                del self.target_dict["initial_key"]
            except KeyError:
                pass  # It might have been processed already
            return ("second_key", 2)
        raise StopIteration


malicious_iterables = {
    "iter_raises_value_error": IterableRaiser(ValueError("Error during iteration")),
    "iter_raises_stop_iteration_early": IterableRaiser(StopIteration, valid_yields=1),
    "iter_malformed_items": MalformedItemIterable(),
    "iter_non_hashable_key": NonHashableKeyIterable(),
    # The re-entrant iterable needs to be created with the target dict,
    # so we provide a factory function.
    "factory_reentrant_iterable": ReentrantIterable,
}


# --- 3. Malicious Aggregate Functions (for general `reduce`) ---
# These functions are designed to be used as the `aggregate` callback for
# the general-purpose `reduce()` method.


class ReentrantAggregator:
    """A malicious callable that modifies the dict as a side-effect."""

    def __init__(self, target_dict):
        self.target_dict = target_dict

    def __call__(self, key, current, new):
        # Side effect: re-entrant modification
        self.target_dict[f"re-entrant-write-{key}"] = "corrupted"
        # Then proceed as normal
        if current is cereggii.NOT_FOUND:
            return new
        return current + new if isinstance(current, type(new)) else new


malicious_aggregates = {
    "agg_ret_forbidden_not_found": lambda k, c, n: cereggii.NOT_FOUND,
    "agg_ret_forbidden_any": lambda k, c, n: cereggii.ANY,
    "agg_ret_wrong_type_string": lambda k, c, n: "a string",
    "agg_ret_wrong_type_float": lambda k, c, n: 1.2345,
    "agg_raise_zerodivision": lambda k, c, n: 1 // 0,
    "agg_raise_type_error": lambda k, c, n: (_ for _ in ()).throw(
        TypeError("from aggregate")
    ),
    "agg_sleeper": lambda k, c, n: time.sleep(0.01)
    or (c if c is not cereggii.NOT_FOUND else n),
    # Factory for the re-entrant aggregator
    "factory_reentrant_aggregator": ReentrantAggregator,
}


# --- 4. Problematic Datasets for Specialized `reduce_*` Methods ---
# These iterables contain data types that should cause errors in the
# specialized, optimized `reduce_*` methods.


class BoolRaiser:
    """An object whose boolean representation raises an exception."""

    def __bool__(self):
        raise ValueError("Cannot determine truthiness!")


_non_hashable_key = (
    _weird_instances.get("weird_list_empty", []) if _weird_instances else []
)

specialized_breakers = {
    "for_sum_non_numeric": [("a", "b")],
    "for_max_min_incompatible_types": [("key", 1), ("key", "string")],
    "for_and_or_bool_raiser": [("key", BoolRaiser())],
    "for_count_non_hashable": [_non_hashable_key],
}

# --- 5. Aggregate All Assets ---
reduce_nightmares_collection = {
    "malicious_iterables": malicious_iterables,
    "malicious_aggregates": malicious_aggregates,
    "specialized_breakers": specialized_breakers,
}

# --- Final Sanity Check ---
print(f"Generated {len(malicious_iterables)} malicious iterables/factories.")
print(f"Generated {len(malicious_aggregates)} malicious aggregate functions/factories.")
print(
    f"Generated {len(specialized_breakers)} problematic datasets for specialized methods."
)
