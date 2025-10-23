"""
This module provides a callable, high-contention scenario for fuzzing
`cereggii.AtomicRef`.

The scenario is designed to be a "Complex Object Lifecycle Hell", stress-testing
the C implementation's reference counting (`Py_INCREF`/`Py_DECREF`) by forcing
it to manage a wide variety of complex, cyclical, and malicious Python objects
under intense concurrent pressure.
"""

import random
import sys
import types
import collections.abc
import cereggii

# --- Step 1.1: Imports and Setup ---
# We make imports of our other tricky modules optional to allow for modularity.
_MODULES_TO_AGGREGATE = []
try:
    from fusil.python.samples import tricky_objects

    _MODULES_TO_AGGREGATE.append(tricky_objects)
    print("Successfully imported tricky_objects.")
except ImportError:
    print("Warning: Could not import tricky_objects.", file=sys.stderr)

try:
    from fusil.python.samples import tricky_numpy

    _MODULES_TO_AGGREGATE.append(tricky_numpy)
    print("Successfully imported tricky_numpy.")
except ImportError:
    print("Warning: Could not import tricky_numpy.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_atomicint64

    _MODULES_TO_AGGREGATE.append(tricky_atomicint64)
    print("Successfully imported tricky_atomicint64.")
except ImportError:
    print("Warning: Could not import tricky_atomicint64.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_atomicdict

    _MODULES_TO_AGGREGATE.append(tricky_atomicdict)
    print("Successfully imported tricky_atomicdict.")
except ImportError:
    print("Warning: Could not import tricky_atomicdict.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_recursive_cereggii

    _MODULES_TO_AGGREGATE.append(tricky_recursive_cereggii)
    print("Successfully imported tricky_recursive_cereggii.")
except ImportError:
    print("Warning: Could not import tricky_recursive_cereggii.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_weird_cereggii

    _MODULES_TO_AGGREGATE.append(tricky_weird_cereggii)
    print("Successfully imported tricky_weird_cereggii.")
except ImportError:
    print("Warning: Could not import tricky_weird_cereggii.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_threadhandle

    _MODULES_TO_AGGREGATE.append(tricky_threadhandle)
    print("Successfully imported tricky_threadhandle.")
except ImportError:
    print("Warning: Could not import tricky_threadhandle.", file=sys.stderr)


# --- Step 1.2: Aggregate the "Ammunition" - All Tricky Objects ---
def _aggregate_instances_from_modules(modules_list):
    """
    Iterates through a list of modules and collects all object instances
    found in their global namespace.
    """
    all_objects = []
    for module in modules_list:
        for name, value in vars(module).items():
            if isinstance(name, str) and name.startswith("_"):
                continue  # Skip private variables
            # We want instances, not classes, functions, or modules
            if not isinstance(
                value, (type, collections.abc.Callable, types.ModuleType)
            ):
                all_objects.append(value)
    return all_objects


# Create the comprehensive master list of all tricky objects.
_ALL_TRICKY_OBJECTS = _aggregate_instances_from_modules(_MODULES_TO_AGGREGATE)

# Manually append fundamental Python singletons and simple types.
_ALL_TRICKY_OBJECTS.extend(
    [
        None,
        True,
        False,
        ...,  # Ellipsis
        0,
        1,
        -1,
        1.0,
        0.0,
        -3.14,
        "",
        "a",
        b"",
        b"a",
    ]
)

print("-" * 50)
print(
    f"Collected {len(_ALL_TRICKY_OBJECTS)} diverse tricky objects for AtomicRef Hell."
)
print("-" * 50)


# --- Step 1.3: Define the `scenario_complex_object_lifecycle_hell` ---
def scenario_complex_object_lifecycle_hell(
    num_threads=16, num_refs=4, num_ops_per_thread=500
):
    """
    The primary torture test for AtomicRef.

    Spawns multiple threads to concurrently hammer a shared pool of AtomicRef
    instances with compare-and-set operations, using an extremely diverse
    and hostile set of Python objects as values.
    """
    if not _ALL_TRICKY_OBJECTS:
        print(
            "Warning: No tricky objects were collected. Lifecycle Hell cannot run.",
            file=sys.stderr,
        )
        return False

    # 1. Create the shared pool of AtomicRef instances.
    ref_pool = [
        cereggii.AtomicRef(random.choice(_ALL_TRICKY_OBJECTS)) for _ in range(num_refs)
    ]

    # 2. Define the worker function for each thread.
    def worker():
        for _ in range(num_ops_per_thread):
            try:
                # Randomly select a target ref from the shared pool.
                target_ref = random.choice(ref_pool)

                # Get its current value to use as the `expected` parameter.
                # This increases the chances of a successful swap, which is
                # what we want to test (the success path's refcounting).
                expected_value = target_ref.get()

                # Randomly select a new, malicious object to be the `desired` value.
                desired_value = random.choice(_ALL_TRICKY_OBJECTS)

                # Execute the core attack.
                target_ref.compare_and_set(expected_value, desired_value)

            except Exception as e:
                # We expect many "normal" exceptions like TypeError when comparing
                # incompatible objects. The goal is to survive these without a
                # segfault, which would indicate a memory management bug.
                pass

    # 3. Orchestrate the concurrent execution.
    thread_set = cereggii.ThreadSet.repeat(num_threads)(worker)
    thread_set.start_and_join()

    return True  # Survived without crashing


# --- Step 1.4: Aggregate and Export the Scenario ---
atomicref_scenarios = {
    "scenario_complex_object_lifecycle_hell": scenario_complex_object_lifecycle_hell,
}

print(f"Total scenarios for AtomicRef: {len(atomicref_scenarios)}")
print("-" * 50)
