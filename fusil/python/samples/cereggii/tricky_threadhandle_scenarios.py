"""
Contains callable fuzzing scenarios specifically targeting cereggii.ThreadHandle,
focusing on its proxying logic and lifecycle management under stress.
"""

import random
import operator
import sys
import cereggii

# --- Imports for Synergy Components ---
try:
    from fusil.python.samples.cereggii import tricky_weird_cereggii

    print("Successfully imported tricky_weird_cereggii for ThreadHandle scenarios.")
except ImportError:
    print("Warning: Could not import tricky_weird_cereggii.", file=sys.stderr)
    tricky_weird_cereggii = None


# --- Helper Definitions for "Proxy Hell" ---

# A "menu" of operations covering various dunder methods and protocols.
# Maps method name to (operator function, sample arguments list).
_PROXY_ATTACK_MENU = {
    # Numeric
    "__add__": (operator.add, [1]),
    "__sub__": (operator.sub, [1]),
    "__mul__": (operator.mul, [2]),
    "__truediv__": (operator.truediv, [2]),
    "__floordiv__": (operator.floordiv, [2]),
    "__mod__": (operator.mod, [3]),
    "__pow__": (operator.pow, [2]),
    "__lshift__": (operator.lshift, [1]),
    "__rshift__": (operator.rshift, [1]),
    "__and__": (operator.and_, [1]),
    "__or__": (operator.or_, [1]),
    "__xor__": (operator.xor, [1]),
    "__iadd__": (operator.iadd, [1]),  # In-place ops
    # Sequence/Mapping
    "__len__": (len, []),
    "__getitem__": (operator.getitem, [0]),  # Assuming index/key 0 might exist
    "__setitem__": (operator.setitem, [0, "value"]),
    "__delitem__": (operator.delitem, [0]),
    "__contains__": (operator.contains, [0]),
    # Others
    "__call__": (
        lambda x, *a, **kw: x(*a, **kw),
        [1, 2],
        {"c": 3},
    ),  # Special handling for call
    "__getattr__": (getattr, ["non_existent_attribute"]),
    "__setattr__": (setattr, ["new_attribute", 123]),
    "__int__": (int, []),
    "__float__": (float, []),
    "__complex__": (complex, []),
    "__bool__": (bool, []),
    "__str__": (str, []),
    "__repr__": (repr, []),
}

# A collection of malicious objects (mostly weird subclasses) to wrap in the handle.
_TRICKY_OBJECTS_FOR_HANDLE = []
if tricky_weird_cereggii:
    # Select a diverse sample of weird subclasses that override methods
    # included in our _PROXY_ATTACK_MENU.
    _TRICKY_OBJECTS_FOR_HANDLE.extend(
        obj
        for name, obj in tricky_weird_cereggii.tricky_weird_cereggii_objects.items()
        if any(method_name in name for method_name in _PROXY_ATTACK_MENU)
    )
    # Add poisoned objects too, as they are prime targets
    _TRICKY_OBJECTS_FOR_HANDLE.extend(
        obj
        for name, obj in tricky_weird_cereggii.tricky_weird_cereggii_objects.items()
        if "poisoned" in name
    )
    # Ensure we have at least one object if sampling failed
    if not _TRICKY_OBJECTS_FOR_HANDLE:
        _TRICKY_OBJECTS_FOR_HANDLE.append(
            next(
                iter(tricky_weird_cereggii.tricky_weird_cereggii_objects.values()), None
            )
        )
else:
    # Fallback if imports failed
    class BasicMalice:
        def __add__(self, o):
            raise ValueError("BasicMalice Add")

        def __len__(self):
            raise TypeError("BasicMalice Len")

    _TRICKY_OBJECTS_FOR_HANDLE.append(BasicMalice())

print(
    f"Collected {len(_TRICKY_OBJECTS_FOR_HANDLE)} tricky objects for ThreadHandle proxy tests."
)


# --- Scenario Definition ---


def scenario_proxy_hell(num_threads=8, num_ops_per_thread=200):
    """
    Attacks the C-level method-dispatching (proxy) logic of ThreadHandle
    by wrapping objects with malicious dunder methods and then concurrently
    calling various operations on the handle.
    """
    if not _TRICKY_OBJECTS_FOR_HANDLE:
        print(
            "Warning: No tricky objects available for proxy hell scenario.",
            file=sys.stderr,
        )
        return False

    def worker():
        """The core logic executed by each thread."""
        for _ in range(num_ops_per_thread):
            # 1. Select a malicious object.
            malicious_object = random.choice(_TRICKY_OBJECTS_FOR_HANDLE)
            if malicious_object is None:
                continue  # Skip if fallback failed

            # 2. Wrap it in a handle.
            try:
                # Use try-except as even handle creation might fail with weird objects
                handle = cereggii.ThreadHandle(malicious_object)
            except Exception:
                continue  # Skip if handle creation fails

            # 3. Select a random operation to perform via the handle.
            method_name, (op_func, op_args, *op_kwargs_list) = random.choice(
                list(_PROXY_ATTACK_MENU.items())
            )
            op_kwargs = op_kwargs_list[0] if op_kwargs_list else {}

            # 4. Execute the proxied call, expecting exceptions.
            try:
                # Special handling for __call__ as it needs *args, **kwargs
                if method_name == "__call__":
                    _ = handle(*op_args, **op_kwargs)
                elif method_name == "__getattr__":
                    _ = op_func(handle, op_args[0])
                elif method_name == "__setattr__":
                    op_func(handle, op_args[0], op_args[1])
                elif method_name.startswith("__i"):  # In-place ops modify self
                    op_func(handle, *op_args)
                else:  # Standard binary/unary ops
                    _ = op_func(handle, *op_args)

            except Exception as e:
                # Catching *any* exception here is expected.
                # The goal is that the C extension survives without crashing.
                # print(f"Caught expected exception: {type(e).__name__} during {method_name}", file=sys.stderr) # Optional debug
                pass

    # --- Orchestrate Concurrency ---
    threads = cereggii.ThreadSet.repeat(num_threads)(worker)
    threads.start_and_join()

    # If start_and_join completed without a segfault, the test passes.
    return True


# --- Aggregate and Export Scenarios ---
threadhandle_scenarios = {
    "scenario_proxy_hell": scenario_proxy_hell,
}

print("-" * 50)
print(f"Total ThreadHandle scenarios defined: {len(threadhandle_scenarios)}")
print("-" * 50)
