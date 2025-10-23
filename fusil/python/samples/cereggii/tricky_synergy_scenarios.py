"""
This module defines high-level fuzzing scenarios that orchestrate interactions
between multiple tricky components from our other modules. The goal is to
find bugs that only emerge from the complex interplay of different parts
of the cereggii library under stress.
"""

import sys
import random
import cereggii
import itertools
import time  # Needed for the new scenario's worker

# --- Imports for Synergy Components ---
_synergy_dependencies_met = True
try:
    from fusil.python.samples.cereggii import tricky_reduce_nightmares

    print("Successfully imported tricky_reduce_nightmares for synergy.")
except ImportError:
    print("Warning: Could not import tricky_reduce_nightmares.", file=sys.stderr)
    tricky_reduce_nightmares = None
    _synergy_dependencies_met = False

try:
    from fusil.python.samples.cereggii import tricky_weird_cereggii

    print("Successfully imported tricky_weird_cereggii for synergy.")
except ImportError:
    print("Warning: Could not import tricky_weird_cereggii.", file=sys.stderr)
    tricky_weird_cereggii = None
    _synergy_dependencies_met = False

try:
    from fusil.python.samples.cereggii import (
        tricky_atomicdict,
    )  # Needed for the new scenario

    print("Successfully imported tricky_atomicdict for synergy.")
except ImportError:
    print("Warning: Could not import tricky_atomicdict.", file=sys.stderr)
    tricky_atomicdict = None
    _synergy_dependencies_met = False


# --- Synergy Scenario Definitions ---


def scenario_reduce_with_shared_handle_iterator(num_threads=4):
    """
    Synergy Attack 1: Uses a shared ThreadHandle wrapping a malicious iterator
    as input to a concurrent reduce operation. Tests ThreadHandle abuse combined
    with reduce's iteration logic.
    """
    if not _synergy_dependencies_met or not tricky_reduce_nightmares:
        print(
            "Warning: Missing dependencies for shared handle iterator scenario.",
            file=sys.stderr,
        )
        return False

    atomic_dict = cereggii.AtomicDict()
    # Use an iterator designed to raise an exception partway through
    raiser_iterable = tricky_reduce_nightmares.malicious_iterables[
        "iterable_raiser_ValueError"
    ]
    # Wrap it in a single, shared ThreadHandle
    shared_handle = cereggii.ThreadHandle(raiser_iterable)

    @cereggii.ThreadSet.repeat(num_threads)
    def worker():
        try:
            # All threads use the same handle to iterate over the same failing iterator
            atomic_dict.reduce(shared_handle, lambda k, c, n: n)
        except ValueError:
            pass  # Expected exception from the iterator
        except Exception as e:
            print(
                f"ERROR: Worker failed with unexpected exception: {e}", file=sys.stderr
            )

    worker.start_and_join()
    return True  # Survived without crashing


def scenario_atomicref_holding_weird_atomicdict(
    num_getter_threads=4, num_swapper_threads=4, num_ops=50
):
    """
    Synergy Attack 2: An AtomicRef holds a weird AtomicDict subclass.
    One group of threads tries to use the weird dict, while another group
    concurrently tries to swap the ref to a *different* weird dict.
    Tests lifecycle and error propagation between nested C-extension types.
    """
    if not _synergy_dependencies_met or not tricky_weird_cereggii:
        print(
            "Warning: Missing dependencies for ref holding weird dict scenario.",
            file=sys.stderr,
        )
        return False

    # Find weird AtomicDict subclasses that raise on common operations
    weird_dict_raiser = tricky_weird_cereggii.tricky_weird_cereggii_objects.get(
        "WeirdAtomicDict___getitem___raiser_ValueError"
    )
    weird_dict_looper = tricky_weird_cereggii.tricky_weird_cereggii_objects.get(
        "WeirdAtomicDict___len___looper"  # Using len as a different method to trigger
    )
    if not weird_dict_raiser or not weird_dict_looper:
        print(
            "Warning: Could not find required weird AtomicDict instances.",
            file=sys.stderr,
        )
        return False

    # Start with one weird dict in the ref
    shared_ref = cereggii.AtomicRef(weird_dict_raiser)

    @cereggii.ThreadSet.repeat(num_getter_threads)
    def getter_worker():
        """Tries to get the dict and use it, expecting failures."""
        for _ in range(num_ops):
            current_dict = shared_ref.get()
            try:
                # Attempt an operation that the weird dict overrides
                _ = current_dict["some_key"]
            except ValueError:
                pass  # Expected
            except Exception:
                # Catching other potential issues from weird dicts
                pass

    @cereggii.ThreadSet.repeat(num_swapper_threads)
    def swapper_worker():
        """Concurrently tries to swap the ref between the two weird dicts."""
        for _ in range(num_ops):
            expected = shared_ref.get()
            desired = (
                weird_dict_looper
                if expected is weird_dict_raiser
                else weird_dict_raiser
            )
            shared_ref.compare_and_set(expected, desired)

    (getter_worker | swapper_worker).start_and_join()

    return True  # Survived without crashing.


def scenario_concurrent_reduce_with_failures(
    num_success_threads=4, num_failure_threads=4, num_items_per_success_thread=1000
):
    """
    Synergy Attack 3: Tests state consistency of a concurrent reduce operation
    when a subset of participating threads fails with exceptions.
    """
    # 1. Dependency Check
    if not tricky_reduce_nightmares or not hasattr(
        tricky_reduce_nightmares, "malicious_iterables"
    ):
        print(
            "Warning: Missing dependencies for concurrent failure scenario.",
            file=sys.stderr,
        )
        return False

    # 2. Setup Shared Resources
    atomic_dict = cereggii.AtomicDict()
    SUCCESS_KEY = "success_counter"

    # 3. Define the "Success Worker"
    def success_worker():
        """This worker performs a clean, successful reduce_sum operation."""
        try:
            data = itertools.repeat((SUCCESS_KEY, 1), num_items_per_success_thread)
            atomic_dict.reduce_sum(data)
        except Exception as e:
            # This worker is not expected to fail. If it does, print an error.
            print(f"ERROR: Success worker failed unexpectedly: {e}", file=sys.stderr)
            # We don't re-raise, as the main thread needs to finish to check assertions.

    # 4. Define the "Failure Worker"
    def failure_worker():
        """This worker uses a malicious iterable designed to raise an exception."""
        try:
            # Ensure we get a fresh instance of the generator-based iterable each time
            raiser_iterable_gen = tricky_reduce_nightmares.malicious_iterables[
                "iterable_raiser_ValueError"
            ]
            if hasattr(
                raiser_iterable_gen, "__call__"
            ):  # Check if it's a factory function/lambda
                raiser_iterable = raiser_iterable_gen()
            else:  # Assume it's reusable if not callable
                raiser_iterable = raiser_iterable_gen
            # The aggregate function doesn't matter, as the iterator will fail first.
            atomic_dict.reduce(raiser_iterable, lambda k, c, n: n)
        except ValueError:
            # This exception is the expected outcome for this worker.
            pass
        except Exception as e:
            print(
                f"ERROR: Failure worker failed with unexpected exception: {e}",
                file=sys.stderr,
            )

    # 5. Orchestrate Concurrency
    success_threads = cereggii.ThreadSet.repeat(num_success_threads)(success_worker)
    failure_threads = cereggii.ThreadSet.repeat(num_failure_threads)(failure_worker)

    (success_threads | failure_threads).start_and_join()

    # 6. Verification
    expected_total = num_success_threads * num_items_per_success_thread
    actual_total = atomic_dict.get(SUCCESS_KEY, 0)  # Use get() in case key wasn't added

    # Check that the data from the successful threads is consistent and complete.
    assert actual_total == expected_total, (
        f"Expected {expected_total}, got {actual_total}"
    )

    # Check that no partial data from the failing threads was committed.
    # We expect only the SUCCESS_KEY to be in the dictionary, if any success threads ran.
    expected_len = (
        1 if num_success_threads > 0 and num_items_per_success_thread > 0 else 0
    )
    assert len(atomic_dict) == expected_len, (
        f"Expected {expected_len} key(s), found {len(atomic_dict)}"
    )

    return True  # Survived and maintained state consistency.


# --- Part 1: "Shared Handle Re-entrancy Attack" Scenario ---


# --- Step 1.2: Define the scenario function ---
def scenario_shared_handle_reentrancy_attack(num_threads=4):
    """
    Synergy Attack 4: Multiple threads use a SINGLE SHARED ThreadHandle wrapping
    an AtomicDict containing a MaliciousEqWithSideEffect object. All threads
    concurrently attempt the lookup that triggers the re-entrant side effect.
    Tests ThreadHandle contract violation + proxy logic + re-entrancy + state
    corruption under concurrency. The "Perfect Storm".
    """
    # --- Step 1.3: Implement the Scenario Logic ---

    # Dependency Check
    if (
        not tricky_atomicdict
        or not hasattr(tricky_atomicdict, "MaliciousEqWithSideEffect")
        or not hasattr(tricky_atomicdict, "AlwaysUnequalConstantHash")
    ):
        print(
            "Warning: Missing dependencies for shared handle re-entrancy scenario.",
            file=sys.stderr,
        )
        return False

    # Set the Trap
    d = cereggii.AtomicDict()
    attacker = tricky_atomicdict.MaliciousEqWithSideEffect(target_dict=d)
    trigger = tricky_atomicdict.AlwaysUnequalConstantHash()
    try:
        d[attacker] = "attacker_value"
    except Exception as e:
        print(
            f"Error setting up re-entrancy attack (inserting attacker): {e}",
            file=sys.stderr,
        )
        return False  # Cannot proceed if setup fails

    # Create the Weapon (The Forbidden Shared Handle)
    shared_handle = cereggii.ThreadHandle(d)

    # Define the Worker Function
    def worker():
        """Springs the trap using the shared handle."""
        try:
            # Perform the lookup using the SHARED handle.
            # This will call attacker.__eq__(trigger) via the handle's proxy.
            _ = shared_handle[trigger]
        except ValueError as e:
            # This is the exception expected from MaliciousEqWithSideEffect.__eq__
            # Catching it without a segfault is a success for this thread.
            # print(f"Thread caught expected ValueError: {e}", file=sys.stderr) # Optional: for debugging
            pass
        except Exception as e:
            # Any other exception indicates a potential problem.
            print(
                f"ERROR: Worker caught unexpected exception: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            # Re-raise here might hide segfaults, better to let main thread finish.

    # Orchestrate the Concurrent Attack
    attack_threads = cereggii.ThreadSet.repeat(num_threads)(worker)
    attack_threads.start_and_join()

    # If we survived start_and_join without a segfault or deadlock, it's a success.
    return True


# --- Step 1.4 & Previous Exports: Aggregate All Scenarios ---
synergy_scenarios = {
    "scenario_reduce_with_shared_handle_iterator": scenario_reduce_with_shared_handle_iterator,
    "scenario_atomicref_holding_weird_atomicdict": scenario_atomicref_holding_weird_atomicdict,
    "scenario_concurrent_reduce_with_failures": scenario_concurrent_reduce_with_failures,
    "scenario_shared_handle_reentrancy_attack": scenario_shared_handle_reentrancy_attack,  # Added the new scenario
}

print("-" * 50)
# Update the count dynamically
print(f"Total synergy scenarios defined: {len(synergy_scenarios)}")
print("-" * 50)
