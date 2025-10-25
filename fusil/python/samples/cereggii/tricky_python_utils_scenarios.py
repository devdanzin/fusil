"""
Contains callable fuzzing scenarios targeting cereggii's Python-level utilities
like CountDownLatch, often by providing malicious inputs to their constructors
or methods to attack the underlying C implementations indirectly. Also includes
scenarios testing interactions between different utilities.
"""
import math

import cereggii
import sys
import random
import time

# REMOVED: import operator
import threading
import itertools  # ADDED for new scenario

# --- Imports for Tricky Objects ---
try:
    from fusil.python.samples import weird_classes as weird_classes_module

    print("Successfully imported weird_classes for Python utils scenarios.")
except ImportError:
    print("Warning: Could not import weird_classes.", file=sys.stderr)
    weird_classes_module = None

# REMOVED: try...except block for tricky_weird_cereggii


# --- Helper Definitions ---

# Collect integer-like weird objects for the poison constructor attack
_TRICKY_INTS_FOR_LATCH = []
if weird_classes_module:
    for name, instance in weird_classes_module.weird_instances.items():
        # Check if it inherits from int/number and isn't just a basic type instance
        if "weird_" in name and isinstance(
            instance, (int, float, complex)
        ):  # Approximation
            _TRICKY_INTS_FOR_LATCH.append(instance)
    print(
        f"Collected {len(_TRICKY_INTS_FOR_LATCH)} tricky int-like objects for CountDownLatch."
    )
else:
    # Fallback if weird_classes failed to import
    class MaliciousInt(int):
        def __ge__(self, other):
            raise ValueError("Malicious greater-equal")

        def __sub__(self, other):
            raise TypeError("Malicious subtraction")

    _TRICKY_INTS_FOR_LATCH.append(MaliciousInt(5))

# --- Scenario Definitions ---


# --- Part 1: CountDownLatch Poisoned Constructor Attack ---
def scenario_poison_countdownlatch(num_waiters=4, num_decrementers=4):
    """
    Attempts to initialize CountDownLatch with malicious integer-like objects
    to "poison" its internal AtomicInt64 state, then stresses it concurrently.
    """
    if not _TRICKY_INTS_FOR_LATCH:
        print(
            "Warning: No tricky int objects available for poison latch scenario.",
            file=sys.stderr,
        )
        return False

    all_survived = True
    for poison_object in _TRICKY_INTS_FOR_LATCH:
        latch = None
        try:
            # Attempt to create the latch with the malicious object
            latch = cereggii.CountDownLatch(poison_object)
            print(
                f"Successfully created CountDownLatch with {type(poison_object).__name__}, log10={math.log10(poison_object)}"
            )
        except AssertionError:
            continue  # Expected failure for negative values etc.
        except Exception as e:
            # Catching creation failures is also interesting
            print(
                f"Failed to create CountDownLatch with {type(poison_object).__name__}: {e}",
                file=sys.stderr,
            )
            continue  # Move to the next poison object

        if latch is None:
            continue

        # If latch created, proceed to stress test it
        @cereggii.ThreadSet.repeat(num_waiters)
        def waiter():
            """Waits on the potentially poisoned latch."""
            try:
                latch.wait()
            except Exception as e:
                # We expect potential TypeErrors etc. from internal AtomicInt64
                # print(f"Waiter caught expected exception: {e}", file=sys.stderr) # Optional debug
                pass

        @cereggii.ThreadSet.repeat(num_decrementers)
        def decrementer():
            """Decrements the potentially poisoned latch."""
            try:
                latch.decrement()
            except Exception as e:
                # We expect potential TypeErrors etc. from internal AtomicInt64
                # print(f"Decrementer caught expected exception: {e}", file=sys.stderr) # Optional debug
                pass

        try:
            (waiter | decrementer).start_and_join()
            # Survival is the primary goal
        except Exception as e:
            print(
                f"ERROR: Unhandled exception during concurrent latch test with {type(poison_object).__name__}: {e}",
                file=sys.stderr,
            )
            all_survived = False  # Mark failure but continue testing others

    return all_survived


# --- NEW: Part 2: Nested Concurrent Primitives Scenario ---
def scenario_latch_decremented_by_reduce(
    num_reduce_threads=4, num_wait_threads=4, num_items_per_reduce=100
):
    """
    Synergy Attack: Triggers CountDownLatch.decrement() as a side effect within
    a concurrent AtomicDict.reduce() aggregate function, while other threads
    wait on the latch. Tests for deadlocks/races between components.
    """
    # 1. Setup Shared Resources
    latch_count = num_reduce_threads * num_items_per_reduce
    if latch_count <= 0:  # Ensure latch count is positive
        print(
            "Warning: Calculated latch_count is zero or negative, skipping scenario.",
            file=sys.stderr,
        )
        return False

    latch = cereggii.CountDownLatch(latch_count)
    atomic_dict = cereggii.AtomicDict()
    REDUCE_KEY = "reduce_target"

    # 2. Define the Malicious Aggregate Function
    def malicious_aggregate(key, current, new):
        """Calls latch.decrement() as a side effect."""
        try:
            latch.decrement()  # --- THE SIDE EFFECT ---
        except Exception as e:
            # Log unexpected errors during decrement, but try to continue reduce
            print(
                f"ERROR: Unexpected exception during latch.decrement in aggregate: {e}",
                file=sys.stderr,
            )

        # Perform a standard sum aggregation to allow reduce to proceed
        if current is cereggii.NOT_FOUND:
            return new
        # Basic type check to avoid immediate failure if state gets corrupted
        if isinstance(current, int) and isinstance(new, int):
            return current + new
        return new  # Fallback if types are weird

    # 3. Define the "Reduce Worker" Function
    def reduce_worker():
        """Calls reduce with the malicious aggregate function."""
        try:
            data = itertools.repeat((REDUCE_KEY, 1), num_items_per_reduce)
            atomic_dict.reduce(data, malicious_aggregate)
        except Exception as e:
            # Catch unexpected errors during the reduce itself
            print(f"ERROR: Reduce worker failed unexpectedly: {e}", file=sys.stderr)
            # Ensure latch is fully decremented if a reduce thread fails,
            # otherwise wait threads might deadlock.
            try:
                current_latch_val = latch.get()
                for _ in range(current_latch_val):
                    latch.decrement()
            except Exception:
                pass  # Best effort

    # 4. Define the "Wait Worker" Function
    def wait_worker():
        """Waits for the latch count to reach zero."""
        try:
            latch.wait()
        except Exception as e:
            print(f"ERROR: Wait worker failed unexpectedly: {e}", file=sys.stderr)

    # 5. Orchestrate Concurrency
    reduce_threads = cereggii.ThreadSet.repeat(num_reduce_threads)(reduce_worker)
    wait_threads = cereggii.ThreadSet.repeat(num_wait_threads)(wait_worker)

    all_threads = reduce_threads | wait_threads
    all_threads.start_and_join()  # Will block until latch is zero or timeout/error

    # 6. Verification (Optional but Recommended)
    final_latch_count = latch.get()
    assert final_latch_count == 0, (
        f"Expected final latch count 0, got {final_latch_count}"
    )

    final_dict_value = atomic_dict.get(REDUCE_KEY, None)
    expected_dict_value = latch_count  # Total decrements should equal total sum
    assert final_dict_value == expected_dict_value, (
        f"Expected dict value {expected_dict_value}, got {final_dict_value}"
    )

    # 7. Return Value
    return True  # Survived without deadlock/crash and assertions passed


# --- Aggregate and Export Scenarios ---
python_utils_scenarios = {
    # "scenario_poison_countdownlatch": scenario_poison_countdownlatch,
    "scenario_latch_decremented_by_reduce": scenario_latch_decremented_by_reduce,  # Added new scenario
}

print("-" * 50)
# Update the count dynamically
print(f"Total Python Utils scenarios defined: {len(python_utils_scenarios)}")
print("-" * 50)
