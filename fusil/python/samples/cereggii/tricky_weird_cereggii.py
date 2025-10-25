"""
This module generates "weird" subclasses of cereggii types.

These subclasses override key methods with malicious or non-compliant
behaviors (e.g., raising exceptions, returning wrong types) to test the
robustness of cereggii's C-level implementation against API contract violations.
"""

import cereggii
import sys
import time

# --- 1. Imports ---
# Import FrameModifier for creating side-effects.
# This is wrapped in a try-except block to allow this module to run standalone.
try:
    # Assuming weird_classes is in the same directory for fuzzing.
    from fusil.python.samples.weird_classes import FrameModifier

    _HAS_DEPS = True
except ImportError:
    _HAS_DEPS = False
    print(
        "Warning: 'weird_classes.py' not found. Side-effect behaviors will be disabled.",
        file=sys.stderr,
    )
    # Create a dummy class if the import fails so the rest of the script doesn't crash.


class FrameModifier:
    def __init__(self, *args, **kwargs):
        pass


# --- 2. "Behavior Injection" Factory ---
def create_weird_subclass(base_class, method_name, behavior_func, behavior_name):
    """
    Dynamically creates a new class that inherits from a base_class but has one
    method overridden with a specific malicious behavior.

    Args:
        base_class: The cereggii class to subclass (e.g., cereggii.AtomicDict).
        method_name: The string name of the method to override (e.g., "__getitem__").
        behavior_func: The function that implements the malicious logic.
        behavior_name: A descriptive name for the behavior (e.g., "raise_ValueError").

    Returns:
        A new class object.
    """
    class_name = f"Weird_{base_class.__name__}_Override_{method_name}_{behavior_name}"

    # This is the new method that will be placed in the generated class.
    # It calls the behavior function, passing its own name for context.
    def overridden_method(self, *args, **kwargs):
        return behavior_func(method_name, self, *args, **kwargs)

    # Use type() to dynamically create the class
    new_class = type(
        class_name,
        (base_class,),
        {
            method_name: overridden_method,
            "__doc__": f"Weird subclass of {base_class.__name__} where {method_name} exhibits '{behavior_name}' behavior.",
        },
    )

    return new_class


# --- 3. Malicious Behavior Functions ---
# These are the actual implementations of the malicious behaviors that we will
# inject into our subclasses.


def make_raiser(exc, msg="Fuzzer-induced exception"):
    """Factory to create a function that raises a specific exception."""

    def raiser(method_name, self, *args, **kwargs):
        raise exc(
            f"Exception from weird subclass in '{self.__class__.__name__}.{method_name}': {msg}"
        )

    return raiser


def make_wrong_typer(return_value):
    """Factory to create a function that returns a specific, incorrect type."""

    def wrong_typer(method_name, self, *args, **kwargs):
        # Special case: if the marker "self" is used, return the instance itself.
        if isinstance(return_value, str) and return_value == "self":
            return self
        # Return a copy if mutable to avoid cross-test contamination
        if isinstance(return_value, (list, dict, set)):
            return return_value.copy()
        return return_value

    return wrong_typer


def looper(method_name, self, *args, **kwargs):
    """A behavior that enters an infinite loop to test for hangs/deadlocks."""
    print(
        f"Entering infinite loop in {self.__class__.__name__}.{method_name}...",
        file=sys.stderr,
    )
    while True:
        time.sleep(0.1)  # Sleep to avoid pegging the CPU entirely


def make_side_effect_mutator(var_name, new_value):
    """
    Factory for a behavior that uses FrameModifier to attack its caller's frame.
    The side effect is triggered when the FrameModifier instance is garbage collected.
    """

    def side_effect_mutator(method_name, self, *args, **kwargs):
        print(
            f"Creating FrameModifier in {self.__class__.__name__}.{method_name} to target '{var_name}'...",
            file=sys.stderr,
        )
        # Create the object; its __del__ will trigger when this function returns.
        _ = FrameModifier(var_name, new_value)
        # Return a benign value so the program can continue until the __del__ bomb goes off.
        return None

    return side_effect_mutator


def super_caller_abuse(method_name, self, *args, **kwargs):
    """A behavior that abuses super() calls to test error handling."""
    try:
        super_method = getattr(super(self.__class__, self), method_name, None)
        if callable(super_method):
            # Call it multiple times
            super_method(*args, **kwargs)
            super_method(*args, **kwargs)
            # Call it with completely wrong arguments
            super_method(9999, "extra_arg", bogus_kwarg=True)
    except Exception as e:
        # We expect exceptions here. Return the exception instance itself
        # as a form of "wrong type" to further stress the caller.
        return e
    return None


# A central dictionary mapping behavior names to the functions that implement them.
malicious_behaviors = {
    "raise_ValueError": make_raiser(ValueError),
    "raise_TypeError": make_raiser(TypeError),
    "raise_AttributeError": make_raiser(AttributeError),
    "raise_SystemError": make_raiser(SystemError, "C-API level error simulation"),
    "return_None": make_wrong_typer(None),
    "return_string": make_wrong_typer("this is not the expected return type"),
    "return_int": make_wrong_typer(12345),
    "return_self": make_wrong_typer("self"),  # Special case handled by the factory
    # "infinite_loop": looper,
    "abuse_super": super_caller_abuse,
}

# Only add the side-effect behavior if its dependency was successfully imported.
if _HAS_DEPS:
    malicious_behaviors["side_effect_mutate_local"] = make_side_effect_mutator(
        "local_var", "MODIFIED_BY_SIDE_EFFECT"
    )


# --- Sanity Check ---
print(
    f"Defined factory and {len(malicious_behaviors)} malicious behaviors for weird cereggii subclasses."
)


# --- 4. Target Methods for Overriding ---
# A mapping of each cereggii class to the list of its methods we want to
# target for malicious overriding.

TARGET_METHODS = {
    # cereggii.AtomicDict: [
    #     '__getitem__', '__setitem__', '__delitem__', '__len__',
    #     'compare_and_set', 'reduce', 'fast_iter', 'approx_len', 'get'
    # ],
    cereggii.AtomicInt64: [
        "get",
        "set",
        "compare_and_set",
        "__int__",
        "__add__",
        "__iadd__",
        "update_and_get",
        "get_and_update",
    ],
    # cereggii.AtomicRef: [
    #     'get', 'set', 'compare_and_set'
    # ],
    cereggii.CountDownLatch: ["wait", "decrement", "get"],
    cereggii.ThreadHandle: ["__getattr__", "__call__", "__getitem__", "__setitem__"],
}


# --- 5. Systematic Subclass and Instance Generation ---
# This is the main collection that will hold all our generated tricky instances.
tricky_weird_cereggii_objects = {}

# Main generation loop
for base_class, methods in TARGET_METHODS.items():
    for method_name in methods:
        for behavior_name, behavior_func in malicious_behaviors.items():
            # Create the unique, malicious subclass
            WeirdClass = create_weird_subclass(
                base_class, method_name, behavior_func, behavior_name
            )

            # Try to instantiate it. Some __init__ methods require arguments.
            instance = None
            try:
                if base_class is cereggii.CountDownLatch:
                    instance = WeirdClass(1)
                elif base_class is cereggii.ThreadHandle:
                    instance = WeirdClass(None)  # Handle needs an object to wrap
                else:
                    instance = WeirdClass()  # Most can be initialized without args
            except Exception as e:
                # Instantiation might fail (e.g., if __init__ itself is overridden to raise).
                # This is not an error for us; we just can't add the instance.
                print(
                    f"Could not instantiate {WeirdClass.__name__}: {e}", file=sys.stderr
                )
                continue

            # Add the successfully created instance to our collection.
            instance_name = f"instance_of_{WeirdClass.__name__}"
            tricky_weird_cereggii_objects[instance_name] = instance


# --- 6. Special Attack on cereggii.Constant ---
# The Constant type is not public, but we can get it from the type of a known constant.
# We will create subclasses and rogue instances to test for assumptions in the C code.
try:
    ConstantType = type(cereggii.NOT_FOUND)

    # Create a weird subclass of it, overriding __repr__ to test string handling
    WeirdConstantSubclass = create_weird_subclass(
        ConstantType,
        "__repr__",
        make_raiser(ValueError, "repr of a constant"),
        "raise_ValueError",
    )
    tricky_weird_cereggii_objects["weird_constant_subclass_instance"] = (
        WeirdConstantSubclass("weird_sub")
    )

    # Create a weird subclass overriding __eq__
    WeirdConstantEqSubclass = create_weird_subclass(
        ConstantType, "__eq__", make_wrong_typer(True), "return_True"
    )
    tricky_weird_cereggii_objects["weird_constant_eq_subclass_instance"] = (
        WeirdConstantEqSubclass("weird_eq_sub")
    )

    # Create "rogue" instances of the original ConstantType. This tests if the C code
    # relies on pointer identity for the three blessed singletons.
    tricky_weird_cereggii_objects["rogue_constant_1"] = ConstantType("rogue_one")
    tricky_weird_cereggii_objects["rogue_constant_2"] = ConstantType("rogue_two")

except Exception as e:
    print(
        f"Could not perform special attack on cereggii.Constant: {e}", file=sys.stderr
    )


# --- Final Sanity Check ---
print(
    f"Generated a total of {len(tricky_weird_cereggii_objects)} weird cereggii subclass instances."
)
