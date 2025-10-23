"""
This module provides callable, high-contention scenarios for fuzzing
`cereggii.AtomicInt64`.

The scenarios are designed to go beyond simple correctness checks and create
"perfect storms" of concurrency, boundary values, and malicious inputs to
stress-test the C implementation's error handling and numeric protocols.
"""

import random
import operator
import sys
import cereggii

# --- Part 1: The "Numeric Hell" Scenario ---

# --- Step 1.1: Imports and Setup ---
# We make imports of our other tricky modules optional to allow for modularity.
try:
    from fusil.python.samples.cereggii import tricky_atomicint64
    from fusil.python.samples import weird_classes
except ImportError:
    print(
        "Warning: Could not import tricky_atomicint64 or weird_classes. "
        "Numeric Hell scenario will be less effective.",
        file=sys.stderr,
    )

    # Define fallbacks if modules are missing
    class TrickyAtomicInt64Mock:
        atomic_int_instances_for_binops = [cereggii.AtomicInt64(0)]
        overflow_operands = [0, 1, -1]

    class WeirdClassesMock:
        weird_instances = {}

    tricky_atomicint64 = TrickyAtomicInt64Mock()
    weird_classes = WeirdClassesMock()


# --- Step 1.2: Aggregate a "Menu" of Operations and Operands ---

# A list of all binary operators to be tested.
_BINARY_OPS = [
    operator.add,
    operator.sub,
    operator.mul,
    operator.truediv,
    operator.floordiv,
    operator.mod,
    operator.pow,
    operator.lshift,
    operator.rshift,
    operator.and_,
    operator.or_,
    operator.xor,
]

# A parallel list of all in-place operators.
_INPLACE_OPS = [
    operator.iadd,
    operator.isub,
    operator.imul,
    operator.itruediv,
    operator.ifloordiv,
    operator.imod,
    operator.ipow,
    operator.ilshift,
    operator.irshift,
    operator.iand,
    operator.ior,
    operator.ixor,
]

# Create a master list of all operands to be used in arithmetic operations.
_ALL_NUMERIC_OPERANDS = []
# 1. Add all pre-defined AtomicInt64 boundary instances.
_ALL_NUMERIC_OPERANDS.extend(tricky_atomicint64.atomic_int_instances_for_binops)
# 2. Add all plain integer boundary values.
_ALL_NUMERIC_OPERANDS.extend(tricky_atomicint64.overflow_operands)
# 3. Add all number-like "weird" instances.
_ALL_NUMERIC_OPERANDS.extend(
    inst for name, inst in weird_classes.weird_instances.items() if "weird_int" in name
)
# 4. Add fundamental tricky numerics.
_ALL_NUMERIC_OPERANDS.extend(
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        0.0,
        -1.0,
        3.14,
        complex(0, 1),
        complex(1, -1),
        complex(float("nan"), float("inf")),
    ]
)

print(
    f"Collected {len(_ALL_NUMERIC_OPERANDS)} diverse numeric operands for Numeric Hell."
)


# --- Step 1.3: Define the `scenario_numeric_hell` Function ---
def scenario_numeric_hell(num_threads=8, num_ops_per_thread=250):
    """
    Spawns multiple threads to concurrently hammer AtomicInt64 instances with
    a wide variety of arithmetic operations and tricky operands.
    """

    # This worker function will be the target for each thread.
    def worker():
        for _ in range(num_ops_per_thread):
            # 1. Pick a random AtomicInt64 instance to be the target.
            # We operate on a shared pool of instances, increasing contention.
            target_atomic_int = random.choice(
                tricky_atomicint64.atomic_int_instances_for_binops
            )

            # 2. Pick a random, potentially malicious, right-hand operand.
            right_hand_operand = random.choice(_ALL_NUMERIC_OPERANDS)

            # 3. Randomly choose the type of operation to perform.
            op_type = random.choice(["binary", "inplace", "reflected"])

            try:
                if op_type == "inplace":
                    op = random.choice(_INPLACE_OPS)
                    op(target_atomic_int, right_hand_operand)
                elif op_type == "binary":
                    op = random.choice(_BINARY_OPS)
                    op(target_atomic_int, right_hand_operand)
                elif op_type == "reflected":
                    # For reflected ops, the non-atomic operand comes first.
                    op = random.choice(_BINARY_OPS)
                    op(right_hand_operand, target_atomic_int)

            except (OverflowError, TypeError, ValueError, ZeroDivisionError) as e:
                # IMPORTANT: These exceptions are *expected*. Our goal is to
                # ensure that no matter how invalid the operation, the C
                # extension handles the error gracefully and doesn't segfault.
                # We can optionally log these for debugging, but we don't
                # treat them as a test failure.
                pass
            except Exception as e:
                # Catch any other unexpected exceptions.
                print(
                    f"ERROR (numeric_hell): Caught unexpected exception: {type(e).__name__}: {e}",
                    file=sys.stderr,
                )

    # Use ThreadSet to orchestrate the concurrent execution of the worker.
    thread_set = cereggii.ThreadSet.repeat(num_threads)(worker)
    thread_set.start_and_join()

    return True  # Survived without crashing


# --- Part 2: The "Callback Hell" Scenario ---


# --- Step 2.1 & 2.2: Define the `scenario_callback_hell` Function ---
def scenario_callback_hell(num_threads=8, num_ops_per_thread=200):
    """
    Spawns threads to hammer the update methods (`get_and_update`,
    `update_and_get`) with malicious callables that raise exceptions,
    return invalid types, or cause side effects.
    """
    # Ensure there's something to work with if the import failed.
    if not tricky_atomicint64.weird_callables:
        print(
            "Warning: No weird callables found. Callback Hell will be ineffective.",
            file=sys.stderr,
        )
        return False

    malicious_callables = list(tricky_atomicint64.weird_callables.values())

    def worker():
        for _ in range(num_ops_per_thread):
            # 1. Pick a random AtomicInt64 instance to be the target.
            target_atomic_int = random.choice(
                tricky_atomicint64.atomic_int_instances_for_binops
            )

            # 2. Pick a random malicious callable.
            malicious_callable = random.choice(malicious_callables)

            # 3. Randomly choose which update method to call.
            update_method = random.choice(
                [target_atomic_int.get_and_update, target_atomic_int.update_and_get]
            )

            try:
                update_method(malicious_callable)
            except Exception as e:
                # As before, we *expect* a wide variety of exceptions here.
                # The C code might raise TypeError/OverflowError when processing
                # a bad return value, or the callable itself might raise
                # ValueError, ZeroDivisionError, etc.
                # The goal is to survive without a segfault.
                pass

    # Use ThreadSet to orchestrate the concurrent execution.
    thread_set = cereggii.ThreadSet.repeat(num_threads)(worker)
    thread_set.start_and_join()

    return True  # Survived without crashing


# --- Part 3: Aggregate and Export ---
atomicint_scenarios = {
    "scenario_numeric_hell": scenario_numeric_hell,
    "scenario_callback_hell": scenario_callback_hell,
}

print("-" * 50)
print("Implemented Part 1: scenario_numeric_hell")
print("Implemented Part 2: scenario_callback_hell")
print(f"Total scenarios for AtomicInt64: {len(atomicint_scenarios)}")
print("-" * 50)
