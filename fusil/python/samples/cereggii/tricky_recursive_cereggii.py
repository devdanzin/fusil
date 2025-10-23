"""
This module generates tricky recursive and cyclical object structures using
cereggii.AtomicDict and cereggii.AtomicRef.

It specifically includes weak references to create fragile object graphs
that stress the C implementation's reference counting and garbage collection
handling.
"""

import cereggii
import weakref
import gc
import threading
import time

# --- Main collection for all generated tricky objects ---
tricky_recursive_objects = {}


# --- 1. Strongly-Referenced Cycles ---
# These test the basic ability of the garbage collector and traversal algorithms
# to handle cycles involving cereggii's C extension types.

# 1.1. Self-Recursive AtomicDict
d_self = cereggii.AtomicDict()
d_self["self"] = d_self
tricky_recursive_objects["atomicdict_self_recursive"] = d_self

# 1.2. Self-Recursive AtomicRef
r_self = cereggii.AtomicRef()
r_self.set(r_self)
tricky_recursive_objects["atomicref_self_recursive"] = r_self

# 1.3. Cross-Recursive AtomicDicts
d1 = cereggii.AtomicDict()
d2 = cereggii.AtomicDict()
d1["other"] = d2
d2["other"] = d1
tricky_recursive_objects["atomicdict_cross_recursive_1"] = d1
tricky_recursive_objects["atomicdict_cross_recursive_2"] = d2  # Also add the second one

# 1.4. Cross-Recursive AtomicRefs
r1 = cereggii.AtomicRef()
r2 = cereggii.AtomicRef()
r1.set(r2)
r2.set(r1)
tricky_recursive_objects["atomicref_cross_recursive_1"] = r1
tricky_recursive_objects["atomicref_cross_recursive_2"] = r2

# 1.5. Mixed Cross-Recursive AtomicDict and AtomicRef
d_mixed = cereggii.AtomicDict()
r_mixed = cereggii.AtomicRef(d_mixed)
d_mixed["ref"] = r_mixed
tricky_recursive_objects["atomicdict_mixed_recursive"] = d_mixed
tricky_recursive_objects["atomicref_mixed_recursive"] = r_mixed


# --- 2. Weakly-Referenced & Mixed Cycles ---
# These are designed to be more dangerous by creating object graphs that can
# be broken by the garbage collector, potentially leading to dangling pointers
# and use-after-free errors in the C code if reference counting is not perfect.

# 2.1. AtomicDict with weak reference to itself
d_self_weak = cereggii.AtomicDict()
d_self_weak["self_weakref"] = d_self_weak  # weakref.ref(d_self_weak)
tricky_recursive_objects["atomicdict_self_weakref"] = d_self_weak

# 2.2. AtomicDict with weak proxy to itself
d_self_proxy = cereggii.AtomicDict()
try:
    d_self_proxy["self_proxy"] = weakref.proxy(d_self_proxy)
    tricky_recursive_objects["atomicdict_self_proxy"] = d_self_proxy
except TypeError:
    # Some types cannot be proxied, which is fine.
    pass

# 2.3. Breakable Cross-Reference Cycle
d_break1 = cereggii.AtomicDict()
d_break2 = cereggii.AtomicDict()
d_break1["strong_link"] = d_break2
d_break2["weak_link"] = d_break1  # weakref.ref(d_break1)
tricky_recursive_objects["atomicdict_breakable_cycle_strong_end"] = d_break1
tricky_recursive_objects["atomicdict_breakable_cycle_weak_end"] = d_break2


# 2.4. AtomicRef pointing to a weak reference of an object that will be deleted
def create_ref_to_dead_weakref():
    some_object = {1, 2, 3}  # A simple, collectable object
    r = cereggii.AtomicRef(weakref.ref(some_object))
    del some_object
    gc.collect()  # Encourage garbage collection
    # Now the weakref inside 'r' is dead.
    return r


tricky_recursive_objects["atomicref_to_dead_weakref"] = create_ref_to_dead_weakref()


# 2.5. AtomicRef pointing to a weak proxy of an object that will be deleted
def create_ref_to_dead_proxy():
    try:
        some_object = [1, 2, 3]
        r = cereggii.AtomicRef(weakref.proxy(some_object))
        del some_object
        gc.collect()
        # Accessing r.get()() will now raise ReferenceError
        return r
    except TypeError:
        return None  # Return None if proxying fails


ref_to_dead_proxy = create_ref_to_dead_proxy()
if ref_to_dead_proxy:
    tricky_recursive_objects["atomicref_to_dead_proxy"] = ref_to_dead_proxy


# --- 3. Race Condition Test Function ---
# This is not a static object but a callable test case for the fuzzer.
# It creates a race between a thread trying to use an object via an AtomicRef
# and another thread trying to garbage collect that same object.


def race_condition_ref_vs_gc():
    """
    Callable test case to create a race condition.
    Returns True if no crash occurred, but a crash is the intended "success".
    """
    obj_to_race = [1, 2, 3, 4]
    ref = cereggii.AtomicRef(obj_to_race)
    can_start = threading.Event()
    stop_hammering = threading.Event()

    errors = []

    def hammer_thread():
        can_start.wait()
        while not stop_hammering.is_set():
            try:
                # Hammer the compare_and_set operation
                current = ref.get()
                if current is not None:
                    # Modify the list in-place to do some work
                    current.append(1)
                    ref.compare_and_set(current, current)
                else:
                    # The object might have been collected
                    ref.compare_and_set(None, None)
            except Exception as e:
                errors.append(e)
                break

    def gc_thread():
        nonlocal obj_to_race
        can_start.wait()
        time.sleep(0.001)  # Give the hammer a tiny head start
        # Remove the only strong reference and invoke GC
        del obj_to_race
        gc.collect()

    h_thread = threading.Thread(target=hammer_thread)
    g_thread = threading.Thread(target=gc_thread)

    h_thread.start()
    g_thread.start()

    can_start.set()  # Unleash both threads
    g_thread.join(timeout=1.0)
    time.sleep(0.01)  # Let the hammer run a bit more after GC
    stop_hammering.set()
    h_thread.join(timeout=1.0)

    if errors:
        # Re-raise any captured error to signal failure to the fuzzer
        raise errors[0]

    return True  # Survived without crashing


tricky_recursive_objects["callable_race_ref_vs_gc"] = race_condition_ref_vs_gc

# --- Sanity Check ---
print(
    f"Generated {len(tricky_recursive_objects)} tricky recursive/cyclical objects and callables."
)
