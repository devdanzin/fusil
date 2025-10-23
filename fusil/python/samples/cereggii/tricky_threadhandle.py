"""
This module generates and orchestrates scenarios to abuse cereggii.ThreadHandle.

The primary goal is to violate its core contract: "a handle should only be
used by the thread that created it". We will test this via concurrency, and also
probe its robustness against wrapping tricky objects and handling object lifecycle
issues (use-after-free).
"""

import cereggii
import threading
import gc
import time
import sys
import types

# --- 1. Imports ---
# We need a diverse pool of objects to wrap in our handles. We'll pull from
# our previously created modules.

_ALL_TRICKY_OBJECTS = []
try:
    from fusil.python.samples.cereggii.tricky_atomicref import (
        all_tricky_objects_for_ref,
    )

    _ALL_TRICKY_OBJECTS.extend(all_tricky_objects_for_ref)
    print("Successfully imported objects from tricky_atomicref.")
except ImportError:
    print("Warning: 'tricky_atomicref.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_recursive_cereggii

    _ALL_TRICKY_OBJECTS.extend(
        tricky_recursive_cereggii.tricky_recursive_objects.values()
    )
except ImportError:
    print("Warning: 'tricky_recursive_cereggii.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples.cereggii import tricky_weird_cereggii

    _ALL_TRICKY_OBJECTS.extend(
        tricky_weird_cereggii.tricky_weird_cereggii_objects.values()
    )
except ImportError:
    print("Warning: 'tricky_weird_cereggii.py' not found.", file=sys.stderr)

try:
    from fusil.python.samples import tricky_objects

    _ALL_TRICKY_OBJECTS.append(tricky_objects.tricky_frame)
except ImportError:
    print("Warning: 'tricky_objects.py' not found.", file=sys.stderr)


# --- 2. Create a Collection of Tricky ThreadHandle Instances ---
# This dictionary holds pre-configured ThreadHandle instances that are already
# pointing to problematic or interesting objects.

tricky_thread_handles = {}

# Handle to a simple, common mutable object
tricky_thread_handles["handle_to_list"] = cereggii.ThreadHandle([1, 2, 3])

# Handle to an AtomicInt64, a common target for concurrent operations
tricky_thread_handles["handle_to_atomicint64"] = cereggii.ThreadHandle(
    cereggii.AtomicInt64(42)
)

# Handle that points to another handle, testing multi-layer proxying
try:
    nested_handle = cereggii.ThreadHandle(cereggii.ThreadHandle(["nested"]))
    tricky_thread_handles["handle_to_nested_handle"] = nested_handle
except Exception as e:
    print(f"Failed to create nested handle: {e}", file=sys.stderr)


# Handles wrapping some of our trickiest objects
try:
    # A handle to a dictionary that contains itself
    recursive_dict = tricky_recursive_cereggii.tricky_recursive_objects[
        "atomic_dict_self_ref"
    ]
    tricky_thread_handles["handle_to_recursive_dict"] = cereggii.ThreadHandle(
        recursive_dict
    )
except (KeyError, NameError):
    pass

try:
    # A handle to one of our weird, misbehaving subclasses
    weird_instance = next(
        iter(tricky_weird_cereggii.tricky_weird_cereggii_objects.values())
    )
    tricky_thread_handles["handle_to_weird_subclass"] = cereggii.ThreadHandle(
        weird_instance
    )
except (NameError, StopIteration):
    pass

try:
    # A handle to a C-level frame object
    tricky_thread_handles["handle_to_frame"] = cereggii.ThreadHandle(
        tricky_objects.tricky_frame
    )
except NameError:
    pass

# A special handle that wraps a volatile AtomicRef.
# This will be used in a callable scenario later to test races between
# direct access and proxied access.
_volatile_ref_for_handle = cereggii.AtomicRef(100)
tricky_thread_handles["handle_to_volatile_ref"] = cereggii.ThreadHandle(
    _volatile_ref_for_handle
)
tricky_thread_handles["_underlying_volatile_ref"] = (
    _volatile_ref_for_handle  # Expose for the test
)


# --- Sanity Check ---
print(
    f"Generated {len(tricky_thread_handles)} pre-configured tricky ThreadHandle instances."
)


# --- 3. Define Callable Torture Test Scenarios ---
# This dictionary will hold functions that, when called, execute a specific
# high-stress concurrent abuse pattern against a ThreadHandle.

callable_torture_tests = {}


def shared_handle_race(num_threads=4, num_operations=10000):
    """
    VIOLATES CONTRACT: Spawns multiple threads that all operate on the
    *exact same* ThreadHandle instance. This is the primary abuse case.
    """
    target = cereggii.AtomicInt64(0)
    shared_handle = cereggii.ThreadHandle(target)
    errors = []

    def worker():
        try:
            for _ in range(num_operations):
                # Perform an operation through the shared handle.
                # Using an AtomicInt64 is a good test because its methods
                # are also thread-safe, isolating the handle as the variable.
                shared_handle.increment_and_get()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    if errors:
        raise RuntimeError(
            f"A thread failed during the shared handle race: {errors[0]}"
        ) from errors[0]

    # The final value should be correct if AtomicInt64 works, but the main
    # goal is to check for crashes during the concurrent handle access.
    final_value = target.get()
    expected_value = num_threads * num_operations
    if final_value != expected_value:
        # This would be a failure, but not a crash. Still important to know.
        print(
            f"Warning: Race condition resulted in wrong value! Expected {expected_value}, got {final_value}",
            file=sys.stderr,
        )

    return True  # Survived without crashing


callable_torture_tests["callable_shared_handle_race"] = shared_handle_race


def stale_handle_lifecycle_test(delay_sec=0.01):
    """
    Creates a use-after-free scenario where one thread tries to use a handle
    to an object that another thread has just garbage collected.
    """
    target_object = [1, 2, 3]
    handle = cereggii.ThreadHandle(target_object)

    reaper_finished = threading.Event()
    user_exception = []

    def reaper():
        # Use a local variable to ensure we can delete the reference.
        nonlocal target_object
        del target_object
        # Give the 'user' thread a moment to potentially start using the handle
        time.sleep(delay_sec / 2.0)
        gc.collect()  # Attempt to force garbage collection
        reaper_finished.set()

    def user():
        reaper_finished.wait(timeout=2.0)
        try:
            # At this point, the underlying object should be gone.
            # Accessing it through the handle is the test.
            len(handle)
        except Exception as e:
            # A ReferenceError is the expected, safe outcome if weakrefs are used.
            # A crash (segfault) is the bug we are looking for.
            user_exception.append(e)

    reaper_thread = threading.Thread(target=reaper)
    user_thread = threading.Thread(target=user)

    reaper_thread.start()
    user_thread.start()
    reaper_thread.join(timeout=5.0)
    user_thread.join(timeout=5.0)

    if user_exception and not isinstance(user_exception[0], ReferenceError):
        raise RuntimeError(
            "Unexpected exception in stale handle test"
        ) from user_exception[0]

    return True  # Survived


callable_torture_tests["callable_stale_handle_lifecycle_test"] = (
    stale_handle_lifecycle_test
)


def handle_vs_direct_ref_swap_race(num_threads=4, duration_sec=0.1):
    """
    Creates a race between threads modifying an AtomicRef through a handle
    and threads modifying it directly.
    """
    # These are already created in the section above.
    ref = tricky_thread_handles["_underlying_volatile_ref"]
    handle = tricky_thread_handles["handle_to_volatile_ref"]
    stop_event = threading.Event()
    errors = []

    def handle_user():
        while not stop_event.is_set():
            try:
                handle.set(10)
                handle.compare_and_set(10, 20)
            except Exception as e:
                errors.append(e)
                break

    def direct_modifier():
        while not stop_event.is_set():
            try:
                ref.set(30)
                ref.compare_and_set(30, 40)
            except Exception as e:
                errors.append(e)
                break

    threads = []
    for i in range(num_threads):
        target = handle_user if i % 2 == 0 else direct_modifier
        threads.append(threading.Thread(target=target))

    for t in threads:
        t.start()
    time.sleep(duration_sec)
    stop_event.set()
    for t in threads:
        t.join(timeout=1.0)

    if errors:
        raise RuntimeError(
            f"Thread failed during direct vs handle race: {errors[0]}"
        ) from errors[0]

    return True


callable_torture_tests["callable_handle_vs_direct_ref_swap_race"] = (
    handle_vs_direct_ref_swap_race
)


# --- 4. Aggregate All Exports ---
# Combine the pre-made instances and the callable scenarios into a single
# collection for the fuzzer.
tricky_threadhandle_collection = {
    **tricky_thread_handles,
    **callable_torture_tests,
}

# --- Final Sanity Check ---
print(f"Generated {len(callable_torture_tests)} callable ThreadHandle torture tests.")
print(
    f"Total of {len(tricky_threadhandle_collection)} objects and callables in the collection."
)
