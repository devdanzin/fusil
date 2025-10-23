"""
This module provides a suite of "torture tests" for cereggii.AtomicRef.

The goal is to stress test the C implementation's handling of reference
counting, memory management, and concurrent access with a wide variety of
problematic Python objects and race conditions.
"""

import cereggii
import threading
import gc
import time
import random
import sys
import types

# --- 1. Imports ---
# Import all our existing tricky modules to build a comprehensive library of
# malicious objects to store and swap in the AtomicRef.

_IMPORTED_MODULES = {}
try:
    from fusil.python.samples import tricky_objects

    _IMPORTED_MODULES["tricky_objects"] = tricky_objects
except ImportError:
    print("Warning: 'tricky_objects.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples import tricky_numpy

    _IMPORTED_MODULES["tricky_numpy"] = tricky_numpy
except (ImportError, ModuleNotFoundError):  # numpy might not be installed
    print(
        "Warning: 'tricky_numpy.py' not found or numpy is not installed.",
        file=sys.stderr,
    )

try:
    from fusil.python.samples.cereggii import tricky_atomicint64

    _IMPORTED_MODULES["tricky_atomicint64"] = tricky_atomicint64
except ImportError:
    print("Warning: 'tricky_atomicint64.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_atomicdict

    _IMPORTED_MODULES["tricky_atomicdict"] = tricky_atomicdict
except ImportError:
    print("Warning: 'tricky_atomicdict.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_recursive_cereggii

    _IMPORTED_MODULES["tricky_recursive_cereggii"] = tricky_recursive_cereggii
except ImportError:
    print("Warning: 'tricky_recursive_cereggii.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_weird_cereggii

    _IMPORTED_MODULES["tricky_weird_cereggii"] = tricky_weird_cereggii
except ImportError:
    print("Warning: 'tricky_weird_cereggii.py' not found.", file=sys.stderr)


# --- 2. Aggregate All Tricky Objects ---


def _collect_instances_from_module(module):
    """Inspects a module and returns a list of all its public object instances."""
    instances = []
    if not module:
        return instances
    for name, obj in module.__dict__.items():
        if isinstance(name, str) and name.startswith("_"):
            continue
        # Filter out modules, functions, classes, etc. We only want the data instances.
        if isinstance(obj, (types.ModuleType, types.FunctionType, type)):
            continue
        instances.append(obj)
    return instances


# Ammunition for our race condition tests: a giant list of tricky objects.
all_tricky_objects_for_ref = [None, True, False, 0, 1, "hello", b"world", (), []]
for name, module in _IMPORTED_MODULES.items():
    print(f"Collecting tricky object instances from {name}...")
    collected = _collect_instances_from_module(module)
    # Some modules might return dicts of objects, flatten them.
    if isinstance(collected, list) and collected and isinstance(collected[0], dict):
        for d in collected:
            if isinstance(d, dict):
                all_tricky_objects_for_ref.extend(d.values())
    else:
        all_tricky_objects_for_ref.extend(collected)

# Ensure the list is not empty, providing a fallback.
if len(all_tricky_objects_for_ref) <= 10:
    all_tricky_objects_for_ref.extend([list(range(i)) for i in range(100)])

# --- 3. Pre-Populated AtomicRef Instances ---
tricky_atomicref_instances = {}

# Pick a few representative tricky objects to initialize AtomicRefs with.
# The fuzzer can use these as starting points for its operations.
try:
    ref_rec_list = cereggii.AtomicRef(tricky_objects.tricky_list_with_cycle)
    tricky_atomicref_instances["ref_holding_recursive_list"] = ref_rec_list
except (AttributeError, NameError):
    pass

try:
    weird_instance = next(
        iter(tricky_weird_cereggii.tricky_weird_cereggii_objects.values())
    )
    ref_weird_subclass = cereggii.AtomicRef(weird_instance)
    tricky_atomicref_instances["ref_holding_weird_subclass"] = ref_weird_subclass
except (AttributeError, NameError, StopIteration):
    pass

try:
    ref_frame = cereggii.AtomicRef(tricky_objects.tricky_frame)
    tricky_atomicref_instances["ref_holding_frame"] = ref_frame
except (AttributeError, NameError):
    pass

# A simple one for good measure
tricky_atomicref_instances["ref_holding_none"] = cereggii.AtomicRef(None)

# --- 4. Callable Torture Test Scenarios ---
callable_torture_tests = {}


def high_frequency_cas_race(num_threads=4, duration_sec=0.1):
    """
    Spawns multiple threads to hammer a single AtomicRef with compare_and_set
    operations using a wide variety of tricky objects. This is a pure stress
    test for the C implementation's reference counting.
    """
    ref = cereggii.AtomicRef(None)
    stop_event = threading.Event()
    errors = []

    def worker():
        while not stop_event.is_set():
            try:
                # Pick two random objects from our entire collection
                expected = random.choice(all_tricky_objects_for_ref)
                desired = random.choice(all_tricky_objects_for_ref)
                # The operation itself is what matters, not the result
                ref.compare_and_set(expected, desired)
            except Exception as e:
                # Catch Python-level errors so the thread doesn't die,
                # but store them to report a non-crash failure.
                errors.append(e)
                break

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    time.sleep(duration_sec)
    stop_event.set()
    for t in threads:
        t.join(timeout=1.0)

    if errors:
        raise RuntimeError(f"Thread failed during CAS race: {errors[0]}") from errors[0]

    return True  # Survived without crashing


callable_torture_tests["callable_high_frequency_cas_race"] = high_frequency_cas_race


def mutable_vs_container_race(num_threads=4, duration_sec=0.1):
    """
    Creates a race between threads modifying a mutable object's contents
    and threads swapping the AtomicRef to point to a new object entirely.
    """
    ref = cereggii.AtomicRef([1])
    stop_event = threading.Event()
    errors = []

    def content_modifier():
        while not stop_event.is_set():
            try:
                current_list = ref.get()
                if isinstance(current_list, list):
                    current_list.append(1)  # In-place modification
            except Exception as e:
                errors.append(e)
                break

    def container_swapper():
        while not stop_event.is_set():
            try:
                new_list = [random.randint(0, 100)]
                ref.set(new_list)
            except Exception as e:
                errors.append(e)
                break

    threads = []
    for i in range(num_threads):
        target = content_modifier if i % 2 == 0 else container_swapper
        threads.append(threading.Thread(target=target))

    for t in threads:
        t.start()
    time.sleep(duration_sec)
    stop_event.set()
    for t in threads:
        t.join(timeout=1.0)

    if errors:
        raise RuntimeError(
            f"Thread failed during mutable race: {errors[0]}"
        ) from errors[0]

    return True


callable_torture_tests["callable_mutable_vs_container_race"] = mutable_vs_container_race

# Re-expose the lifecycle race from the recursive module for direct use here.
try:
    from .tricky_recursive_cereggii import race_condition_ref_vs_gc

    callable_torture_tests["callable_lifecycle_gc_race"] = race_condition_ref_vs_gc
except (ImportError, NameError):
    pass

# --- 5. Aggregate Final Exports ---
tricky_atomicref_collection = {**tricky_atomicref_instances, **callable_torture_tests}

# --- Final Sanity Check ---
print(
    f"Collected {len(all_tricky_objects_for_ref)} tricky objects for AtomicRef tests."
)
print(
    f"Generated {len(tricky_atomicref_collection)} total AtomicRef torture objects and callables."
)
