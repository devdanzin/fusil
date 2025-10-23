"""
This module provides callable, multi-step scenarios for fuzzing
`cereggii.AtomicDict`.

Unlike single-method fuzzing, these scenarios test the state machine of the
dictionary by executing a sequence of operations (insertions, deletions, lookups)
that can get the C-level implementation into a complex or fragile state before
the final, potentially crashing, operation occurs.
"""

import cereggii
import random
import collections.abc
import sys
import inspect

# --- Step 2.1: Imports and Input Aggregation ---
# We make imports optional to allow modules to be used somewhat independently.
_PREFIX = "fusil.python.samples."

_MODULE_NAMES = [
    "tricky_objects",
    "weird_classes",
    "tricky_numpy",
    "cereggii.tricky_atomicint64",
    "cereggii.tricky_atomicdict",
    "cereggii.tricky_recursive_cereggii",
    "cereggii.tricky_weird_cereggii",
    "cereggii.tricky_colliding_keys",
]
_MODULES = {}
for name in _MODULE_NAMES:
    try:
        _MODULES[name] = __import__(_PREFIX + name)
    except ImportError:
        print(f"Warning: Failed to import fuzzing module '{name}'.", file=sys.stderr)


def _aggregate_instances(filter_func=None):
    """Helper to collect all object instances from our tricky modules."""
    instances = []
    for name, mod in _MODULES.items():
        # Iterate through the module's members
        for member_name, member_val in inspect.getmembers(mod):
            if member_name.startswith("_"):
                continue  # Skip private/internal members

            # We want object instances, not classes, functions, modules, etc.
            if (
                inspect.isclass(member_val)
                or inspect.isfunction(member_val)
                or inspect.ismodule(member_val)
            ):
                continue

            # Apply the filter if one is provided
            if filter_func is None or filter_func(member_val):
                instances.append(member_val)
    return instances


print("Aggregating tricky inputs for stateful scenarios...")

# Aggregate all hashable objects to use as keys
_ALL_TRICKY_KEYS = _aggregate_instances(
    filter_func=lambda obj: isinstance(obj, collections.abc.Hashable)
)
# Manually add some fundamental hashable types
_ALL_TRICKY_KEYS.extend(
    [None, True, False, (), frozenset(), float("nan"), float("inf")]
)

# Aggregate all objects to use as values
_ALL_TRICKY_VALUES = _aggregate_instances()
_ALL_TRICKY_VALUES.extend([None, True, False, 1, 0, -1, "value"])

if not _ALL_TRICKY_KEYS:
    print(
        "Warning: No tricky keys were collected. Scenarios may be less effective.",
        file=sys.stderr,
    )
    _ALL_TRICKY_KEYS = [1, "key", (1, 2)]  # Fallback
if not _ALL_TRICKY_VALUES:
    _ALL_TRICKY_VALUES = [1, "value", None]  # Fallback

print(
    f"Collected {len(_ALL_TRICKY_KEYS)} tricky keys and {len(_ALL_TRICKY_VALUES)} tricky values."
)


# --- Step 2.2: Define `scenario_grow_shrink_and_reuse` ---
def scenario_grow_shrink_and_reuse(num_items=500):
    """
    Tests the dictionary's ability to handle mass insertion (growth),
    mass deletion (creating tombstones), and then re-insertion (reusing slots).
    """
    d = cereggii.AtomicDict()

    # 1. Grow
    for i in range(num_items):
        d[i] = i

    # 2. Shrink (by deletion)
    for i in range(num_items):
        del d[i]

    # 3. Reuse
    for i in range(num_items):
        # Use a different set of keys to ensure we are not just updating
        d[i + num_items] = i

    final_len = len(d)
    if final_len != num_items:
        print(
            f"WARNING (grow_shrink_reuse): Final length mismatch! Expected {num_items}, got {final_len}",
            file=sys.stderr,
        )

    return True  # Survived without crashing


# --- Step 2.3: Define `scenario_hammer_colliding_bucket` ---
def scenario_hammer_colliding_bucket():
    """
    Finds a set of keys known to collide and performs a sequence of
    insertions, deletions, and lookups on that single bucket.
    """
    colliding_keys_mod = _MODULES.get("tricky_colliding_keys")
    if not colliding_keys_mod:
        print(
            "Skipping scenario_hammer_colliding_bucket: tricky_colliding_keys module not found.",
            file=sys.stderr,
        )
        return False

    # Find a suitable list of colliding keys
    key_set = colliding_keys_mod.colliding_key_sets.get("log_size_6")
    if not key_set or not key_set.get(0):
        print(
            "Skipping scenario_hammer_colliding_bucket: No colliding keys generated.",
            file=sys.stderr,
        )
        return False

    keys_to_hammer = key_set[0]
    d = cereggii.AtomicDict()

    # 1. Insert all colliding keys
    for key in keys_to_hammer:
        d[key] = key

    # 2. Randomly delete about half of them
    keys_to_delete = random.sample(keys_to_hammer, k=len(keys_to_hammer) // 2)
    deleted_set = set(keys_to_delete)
    for key in keys_to_delete:
        del d[key]

    # 3. Verify all original keys
    for key in keys_to_hammer:
        try:
            val = d[key]
            if key in deleted_set:
                print(
                    f"ERROR (hammer_colliding_bucket): Found key {key} that should have been deleted.",
                    file=sys.stderr,
                )
            elif val != key:
                print(
                    f"ERROR (hammer_colliding_bucket): Value mismatch for key {key}.",
                    file=sys.stderr,
                )
        except KeyError:
            if key not in deleted_set:
                print(
                    f"ERROR (hammer_colliding_bucket): Key {key} was not found but should exist.",
                    file=sys.stderr,
                )

    return True  # Survived without crashing


# --- Step 2.4: Define `scenario_random_ops` ---
def scenario_random_ops(num_steps=50):
    """
    Performs a random sequence of operations on an AtomicDict and a standard
    dict side-by-side to check for behavioral consistency (e.g., length).
    """
    d = cereggii.AtomicDict()
    model = {}  # A standard dict to act as a ground-truth model

    operations = ["setitem", "getitem", "delitem", "len"]

    for step in range(num_steps):
        op = random.choice(operations)
        key = random.choice(_ALL_TRICKY_KEYS)

        try:
            if op == "setitem":
                value = random.choice(_ALL_TRICKY_VALUES)
                d[key] = value
                model[key] = value
            elif op == "getitem":
                _ = d[key]
                _ = model[key]
            elif op == "delitem":
                del d[key]
                del model[key]
            elif op == "len":
                _ = len(d)
                _ = len(model)

        except (KeyError, TypeError) as e:
            # These exceptions are expected if a key doesn't exist or isn't hashable.
            # We verify our model raised the same exception.
            try:
                if op == "getitem":
                    _ = model[key]
                elif op == "delitem":
                    del model[key]
                # If the model *didn't* raise an error, that's a problem.
                print(
                    f"ERROR (random_ops): AtomicDict raised {type(e)} but model dict did not.",
                    file=sys.stderr,
                )
            except Exception as model_e:
                if type(e) is not type(model_e):
                    print(
                        f"ERROR (random_ops): Mismatched exception types! AtomicDict: {type(e)}, model: {type(model_e)}",
                        file=sys.stderr,
                    )

        # After every operation, check for length consistency
        if len(d) != len(model):
            print(
                f"FATAL (random_ops): Length mismatch after step {step} ({op} op)! AtomicDict: {len(d)}, model: {len(model)}",
                file=sys.stderr,
            )
            return False  # Failure

    return True  # Survived and stayed consistent


# --- Step 2.5: Aggregate and Export Scenarios ---
stateful_scenarios = {
    "scenario_grow_shrink_and_reuse": scenario_grow_shrink_and_reuse,
    "scenario_hammer_colliding_bucket": scenario_hammer_colliding_bucket,
    "scenario_random_ops": scenario_random_ops,
}

print("-" * 50)
print(f"Generated {len(stateful_scenarios)} stateful fuzzing scenarios.")
print("-" * 50)
