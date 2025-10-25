"""
This module generates a rich set of tricky inputs for fuzzing cereggii.AtomicInt64.

It focuses on boundary values, operands designed to cause overflows, and
a mix of types to test the robustness of the C implementation.
"""

import cereggii
import sys

# We'll need our other tricky modules to make the callables truly weird.
# We wrap this in a try-except block to allow this module to be run standalone
# without breaking, which can be useful for debugging the generated inputs.
try:
    from fusil.python.samples import weird_classes as weird_classes_module

    _HAS_WEIRD_CLASSES = True
except ImportError:
    _HAS_WEIRD_CLASSES = False
    print(
        "Warning: 'weird_classes.py' not found. Some callables will be disabled.",
        file=sys.stderr,
    )


# --- 1. Constants for Boundary Values ---
# We define constants for both 64-bit and 32-bit signed integer limits,
# as C extensions can sometimes have legacy code or assumptions based on
# 32-bit integers, making these boundaries valuable for testing.

INT64_MAX = 2**63 - 1
INT64_MIN = -(2**63)
INT32_MAX = 2**31 - 1
INT32_MIN = -(2**31)


# --- 2. Tricky AtomicInt64 Instances ---
# A collection of AtomicInt64 instances initialized at, and around, the
# most significant boundary points for 64-bit and 32-bit signed integers.
# These are the primary targets for our fuzzing operations.

tricky_atomic_ints = {
    # --- 64-bit Boundaries ---
    "atomicint64_INT64_MAX": cereggii.AtomicInt64(INT64_MAX),
    "atomicint64_INT64_MAX_minus_1": cereggii.AtomicInt64(INT64_MAX - 1),
    "atomicint64_INT64_MIN": cereggii.AtomicInt64(INT64_MIN),
    "atomicint64_INT64_MIN_plus_1": cereggii.AtomicInt64(INT64_MIN + 1),
    # --- 32-bit Boundaries ---
    # These are critical for uncovering bugs where a 64-bit Python integer
    # might be incorrectly handled by a C variable of type 'int' or 'long'.
    "atomicint64_INT32_MAX": cereggii.AtomicInt64(INT32_MAX),
    "atomicint64_INT32_MAX_plus_1": cereggii.AtomicInt64(INT32_MAX + 1),
    "atomicint64_INT32_MIN": cereggii.AtomicInt64(INT32_MIN),
    "atomicint64_INT32_MIN_minus_1": cereggii.AtomicInt64(INT32_MIN - 1),
    # --- Zero and Small Integers ---
    # The most common edge cases.
    "atomicint64_zero": cereggii.AtomicInt64(0),
    "atomicint64_one": cereggii.AtomicInt64(1),
    "atomicint64_minus_one": cereggii.AtomicInt64(-1),
    "atomicint64_two": cereggii.AtomicInt64(2),
    "atomicint64_minus_two": cereggii.AtomicInt64(-2),
    "atomicint64_ten": cereggii.AtomicInt64(10),
    "atomicint64_minus_ten": cereggii.AtomicInt64(-10),
    # --- Mid-range Values ---
    # Values that are far from the boundaries but still large.
    "atomicint64_mid_positive": cereggii.AtomicInt64(INT64_MAX // 2),
    "atomicint64_mid_negative": cereggii.AtomicInt64(INT64_MIN // 2),
}


# --- 3. Operands for Triggering Overflows and Edge Cases ---
# This is a curated list of values to be used as the second operand in
# arithmetic operations. It includes values that are guaranteed to cause
# overflows when combined with the boundary instances above, as well as
# non-integer types to test C-level type checking and error handling.

overflow_operands = [
    # Boundary values themselves to maximize overflow potential
    INT64_MAX,
    INT64_MIN,
    INT32_MAX,
    INT32_MIN,
    # Values just beyond the 64-bit boundaries. These will raise OverflowError
    # during Python's own integer creation, which is a great test for the
    # C-level argument parsing logic (PyLong_AsLongAndOverflow).
    INT64_MAX + 1,
    INT64_MIN - 1,
    # Small integers that will tip boundary values over the edge
    0,
    1,
    -1,
    2,
    -2,
    # Values around the middle of the 64-bit range
    INT64_MAX // 2,
    (INT64_MAX // 2) + 1,
    INT64_MIN // 2,
    (INT64_MIN // 2) - 1,
    # Values for testing shift operations (<<, >>)
    30,
    31,
    32,
    33,  # Around 32-bit shift boundary
    62,
    63,
    64,
    65,  # Around 64-bit shift boundary
    # Non-integer types to test for TypeError handling in the C extension
    0.0,
    1.0,
    -1.0,
    sys.float_info.max,
    sys.float_info.min,
    float("inf"),
    float("-inf"),
    float("nan"),
    "a string",
    b"some bytes",
    None,
    True,  # Will be treated as 1
    False,  # Will be treated as 0
    (1, 2),
    [3, 4],
    {"a": 1},
    complex(1, 2),
]


# --- 4. Weird Callables for update_and_get / get_and_update ---
# A dictionary of functions designed to be passed to AtomicInt64's update methods.
# They test how the C code reacts when a callback returns unexpected types,
# raises exceptions, or attempts to cause an overflow.


def _raise_helper(exc_type, msg):
    """Helper to raise exceptions from within lambdas."""
    raise exc_type(msg)


weird_callables = {
    # --- Benign Callables (Sanity Check) ---
    "callable_simple_increment": lambda x: (x + 1) if x < INT64_MAX else x,
    "callable_simple_decrement": lambda x: (x - 1) if x > INT64_MIN else x,
    "callable_identity": lambda x: x,
    # --- Callables that Attempt Overflow ---
    # These return values outside the 64-bit signed int range.
    "callable_ret_max_plus_1": lambda x: INT64_MAX + 1,
    "callable_ret_min_minus_1": lambda x: INT64_MIN - 1,
    # --- Callables Returning Incorrect Types ---
    # The C code should gracefully handle these by raising a TypeError.
    "callable_ret_float": lambda x: float(x),
    "callable_ret_string": lambda x: f"value was {x}",
    "callable_ret_none": lambda x: None,
    "callable_ret_complex": lambda x: complex(x, 1),
    "callable_ret_list": lambda x: [x],
    # --- Callables that Raise Exceptions ---
    # Tests if an exception raised inside the callback is correctly propagated.
    "callable_raise_zero_div": lambda x: 1 // (x - x),
    "callable_raise_value_error": lambda x: _raise_helper(
        ValueError, "fuzzer-induced ValueError"
    ),
    "callable_raise_type_error": lambda x: _raise_helper(
        TypeError, "fuzzer-induced TypeError"
    ),
    "callable_raise_recursion_error": lambda x: _raise_helper(
        RecursionError, "fuzzer-induced RecursionError"
    ),
}

# --- Side-effect Callables ---
# These are more complex and require external state or modules.
side_effect_target = 0


def side_effect_callable(current_value):
    """
    This callable has a side effect: it modifies a global variable.
    This tests for unexpected interactions if the callable is invoked multiple
    times due to contention.
    """
    global side_effect_target
    side_effect_target += 1
    return (current_value + 1) if current_value < INT64_MAX else current_value


weird_callables["callable_with_side_effect"] = side_effect_callable

if _HAS_WEIRD_CLASSES:
    # Add callables that return instances from our other tricky modules.
    weird_callables["callable_ret_weird_list"] = (
        lambda x: weird_classes_module.weird_instances["weird_list_empty"]
    )

    # This callable returns a FrameModifier. When the C code DECREFs this returned
    # object, its __del__ method will be triggered, attempting to maliciously
    # modify variables in its caller's frame. This is a potent attack against
    # assumptions made by JIT compilers or C code about object lifetimes.
    weird_callables["callable_frame_modifier"] = lambda x: weird_classes_module.FrameModifier(
        "side_effect_target", 999
    )


# --- 5. Instances for Binary Operations ---
# A simple list of the AtomicInt64 instances created above.
# The fuzzer can pick two items from this list to test all binary operations
# (e.g., a + b where both a and b are AtomicInt64).
atomic_int_instances_for_binops = list(tricky_atomic_ints.values())


# --- Sanity Check ---
print(f"Prepared {len(tricky_atomic_ints)} tricky AtomicInt64 instances.")
print(f"Prepared {len(overflow_operands)} operands for overflow/type testing.")
print(f"Prepared {len(weird_callables)} weird callables for update methods.")
print(f"Prepared {len(atomic_int_instances_for_binops)} instances for binary ops.")
