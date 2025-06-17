BUG_PATTERNS = {
    'decref_escapes': {
        'description': 'Attacks JIT assumptions about local variable stability using a __del__ side effect. Based on GH-124483.',
        'target_mechanism': 'DEOPT_IF on variable type change',
        'payload_variable_type': 'int',  # The variable being replaced is an integer from a range().
        'setup_code': """
    import operator

    class FrameModifier_{prefix}:
        def __del__(self):
            try:
                frame = sys._getframe(1)
                if frame.f_locals.get('{loop_var}') == {trigger_iteration}:
                    # Use the templated payload instead of a hardcoded value
                    frame.f_locals['{loop_var}'] = {corruption_payload}
            except Exception: pass
    """,
        'body_code': """
    for {loop_var} in range(1, {loop_iterations}): # Start from 1 to avoid division by zero
        FrameModifier_{prefix}()
        try:
            # This expression will be dynamically generated as either infix or functional
            _ = {expression}
        except (TypeError, ZeroDivisionError, ValueError): # Added ValueError for comparison ops
            pass
    """,
    },
    'isinstance_patch': {
        'description': 'Attacks isinstance elimination by monkey-patching __instancecheck__.',
        'target_mechanism': 'JIT `isinstance` elimination, side effects',
        'setup_code': """
from abc import ABCMeta
# Define the metaclass that we will later modify.
class EditableMeta_{prefix}(ABCMeta):
    instance_counter = 0

# Create a class with a deep inheritance tree to stress MRO traversal.
class Base_{prefix}(metaclass=EditableMeta_{prefix}): pass
last_class_{prefix} = Base_{prefix}
for _ in range({inheritance_depth}):
    class ClassStepDeeper(last_class_{prefix}): pass
    last_class_{prefix} = ClassStepDeeper

class EditableClass_{prefix}(last_class_{prefix}):
    pass

# Define the __instancecheck__ method that we will inject later.
def new__instancecheck_{prefix}(self, other):
    self.instance_counter += 1
    return self.instance_counter < 20 # Return True for a bit, then False.

# Define the Deletable class with the __del__ payload that performs the monkey-patch.
class Deletable_{prefix}:
    def __del__(self):
        try:
            print("  [+] __del__ triggered! Patching __instancecheck__ onto metaclass.", file=sys.stderr)
            EditableMeta_{prefix}.__instancecheck__ = new__instancecheck_{prefix}
        except Exception:
            pass

# Arm the trigger by creating an instance of our Deletable class.
trigger_obj_{prefix} = Deletable_{prefix}()

# Create a list of diverse objects to check against.
objects_to_check_{prefix} = [1, 'a_string', 3.14, Base_{prefix}()]
""",
        'body_code': """
# This hot loop baits, triggers, and traps the JIT.
for {loop_var} in range({loop_iterations}):
    # The Bait: This check should be optimized to a constant 'False' initially.
    target_obj = objects_to_check_{prefix}[{loop_var} % len(objects_to_check_{prefix})]
    is_instance_result = isinstance(target_obj, EditableClass_{prefix})

    # The Trigger: Halfway through, we delete the object, firing __del__.
    if {loop_var} == {trigger_iteration}:
        print("[{prefix}] Deleting trigger object...", file=sys.stderr)
        del trigger_obj_{prefix}
        collect()

    # Optional: Log the result to see the change after the trigger.
    if {loop_var} > {trigger_iteration} - 5 and {loop_var} < {trigger_iteration} + 5:
        print("[{prefix}][Iter %s] `isinstance(...)` is now: %s" % ({loop_var}, is_instance_result), file=sys.stderr)

"""
    },
    'type_version_polymorphism': {
        'description': 'Attacks JIT attribute caches by using polymorphic shapes for the same attribute name.',
        'target_mechanism': 'LOAD_ATTR specialization, type version caching',
        'setup_code': """
# Define classes where 'payload' has a different nature.
class ShapeA_{prefix}: payload = 123
class ShapeB_{prefix}:
    @property
    def payload(self): return 'property_payload'
class ShapeC_{prefix}:
    def payload(self): return id(self)
class ShapeD_{prefix}:
    __slots__ = ['payload']
    def __init__(self): self.payload = 'slot_payload'

# Create a list of polymorphic instances.
shapes_{prefix} = [ShapeA_{prefix}(), ShapeB_{prefix}(), ShapeC_{prefix}(), ShapeD_{prefix}()]
""",
        'body_code': """
for {loop_var} in range({loop_iterations}):
    obj = shapes_{prefix}[{loop_var} % len(shapes_{prefix})]
    try:
        # This repeated access forces the JIT to handle different kinds of LOAD_ATTR.
        payload_val = obj.payload
        # If the payload is a method, we call it to make the access meaningful.
        if callable(payload_val):
            payload_val()
    except Exception:
        pass
"""
    },
    'global_invalidation': {
        'description': "Attacks the JIT's cached knowledge of the globals() dictionary.",
        'target_mechanism': 'LOAD_GLOBAL specialization, dk_version invalidation',
        'setup_code': """
# Define a simple global function that will be our JIT target.
def my_global_func_{prefix}():
    return 1
""",
        'body_code': """
# This scenario is designed for correctness checking.
def JIT_path():
    # Phase 1 (Warm-up)
    accumulator = 0
    for _ in range({loop_iterations}):
        accumulator += my_global_func_{prefix}()

    # Phase 2 (Invalidate)
    globals()['new_global_for_invalidation_{prefix}'] = 123

    # Phase 3 (Re-execute)
    accumulator += my_global_func_{prefix}()
    return accumulator

def Control_path():
    # Identical logic for the control path
    accumulator = 0
    for _ in range({loop_iterations}):
        accumulator += my_global_func_{prefix}()
    globals()['new_global_for_invalidation_{prefix}'] = 123
    accumulator += my_global_func_{prefix}()
    return accumulator

jit_result = JIT_path()
control_result = no_jit_harness(Control_path)

assert compare_results(jit_result, control_result), "GLOBAL INVALIDATION BUG! JIT: %s, Control: %s" % (jit_result, control_result)
"""
    },
    'isinstance_elimination': {
        'description': "Tests the JIT's optimization that removes isinstance() calls with constant results.",
        'target_mechanism': '_CALL_ISINSTANCE uop elimination',
        'setup_code': """
# No special setup needed for this pattern.
""",
        'body_code': """
# This scenario checks if the JIT correctly optimizes away a constant isinstance() check.

def jit_target_isinstance_{prefix}():
    total = 0
    # The JIT should recognize that isinstance(10, int) is always True and optimize this branch.
    for i in range({loop_iterations}):
        if isinstance(10, int):
            total += 1
        else:
            total -= 100 # This path should never be taken.
    return total

def control_isinstance_{prefix}():
    total = 0
    # The control path hardcodes the known correct result of the check.
    for i in range({loop_iterations}):
        if True: # The hardcoded result of isinstance(10, int)
            total += 1
        else:
            total -= 100
    return total

# Warm-up, Execute, Compare
jit_harness(jit_target_isinstance_{prefix}, {warmup_calls})
jit_result = jit_target_isinstance_{prefix}()
control_result = no_jit_harness(control_isinstance_{prefix})

assert compare_results(jit_result, control_result), "ISINSTANCE ELIMINATION DEFECT! JIT: %s, Control: %s" % (jit_result, control_result)
"""
    },
    'pow_type_instability': {
        'description': "Tests the JIT's handling of value-dependent return types using pow().",
        'target_mechanism': "Type inference for BINARY_OP with NB_POWER",
        'setup_code': """
# Pairs of inputs for pow() that produce different result types.
# (value, value) -> result_type
interesting_pow_pairs = [
    ((2, 10), int),         # int ** int -> int
    ((2, -2), float),       # int ** neg_int -> float
    ((-2, 0.5), complex),   # neg_int ** float -> complex
    ((2.0, 2), float),      # float ** int -> float
    ((-2.0, 0.5), complex)  # neg_float ** float -> complex
]
""",
        'body_code': """
# This scenario checks if the JIT can handle changing return types for pow().

def jit_target_pow_{prefix}(a, b):
    # This loop will be specialized based on the types of a, b, and the return value.
    total = 0
    for _ in range({loop_iterations}):
        try:
            # We use a complex number accumulator to handle all possible return types.
            total += pow(a, b)
        except TypeError:
            total += 1
    return total

def control_pow_{prefix}(a, b):
    total = 0
    for _ in range({loop_iterations}):
        try:
            total += pow(a, b)
        except TypeError:
            total += 1
    return total

# Select a pair for warm-up and a different pair for the final test.
warmup_pair, test_pair = sample(interesting_pow_pairs, 2)
warmup_args, _ = warmup_pair
test_args, _ = test_pair

# Warm-up, Execute, Compare
jit_harness(jit_target_pow_{prefix}, {warmup_calls}, *warmup_args)
jit_result = jit_target_pow_{prefix}(*test_args)
control_result = no_jit_harness(control_pow_{prefix}, *test_args)

assert compare_results(jit_result, control_result), "POW() TYPE INSTABILITY DEFECT! JIT: %s, Control: %s" % (jit_result, control_result)
"""
    },
    'slice_type_propagation': {
        'description': 'Tests the JITs type propagation for slice operations.',
        'target_mechanism': 'Type propagation for BINARY_SLICE',
        'setup_code': "# No special setup needed for this pattern.",
        'body_code': """
# This scenario checks if the JIT correctly deduces the type of a slice result.

def jit_target_slice_{prefix}():
    the_list = [1, 2, 3, 4, 5]
    total = 0
    for i in range({loop_iterations}):
        # The JIT should know the result of this slice is a list.
        the_slice = the_list[1:4]
        # Therefore, this list-specific operation should not require a type guard.
        the_slice.append(i)
        total += the_slice[-1]
    return total

def control_slice_{prefix}():
    the_list = [1, 2, 3, 4, 5]
    total = 0
    for i in range({loop_iterations}):
        the_slice = the_list[1:4]
        the_slice.append(i)
        total += the_slice[-1]
    return total

# Warm-up, Execute, Compare
jit_harness(jit_target_slice_{prefix}, {warmup_calls})
jit_result = jit_target_slice_{prefix}()
control_result = no_jit_harness(control_slice_{prefix})

assert compare_results(jit_result, control_result), "SLICE TYPE PROPAGATION DEFECT! JIT: %s, Control: %s" % (jit_result, control_result)
"""
    },
    'jit_error_handling': {
        'description': "Tests JIT's error handling path by raising a TypeError in a hot loop.",
        'target_mechanism': 'Exception handling and stack unwinding in JIT-compiled code',
        'setup_code': """
# Create a list of many hashable items and one unhashable item at the end.
# The JIT will optimize the loop for the hashable items.
hashable_item_{prefix} = 1
unhashable_item_{prefix} = []
items_list_{prefix} = {loop_iterations} * [hashable_item_{prefix}] + [unhashable_item_{prefix}]
""",
        'body_code': """
# The hot loop will run many times successfully before hitting the unhashable type.
try:
    # A set comprehension is a concise way to trigger this.
    _ = set((item for item in items_list_{prefix}))
except TypeError:
    # We expect a TypeError. A crash indicates the bug is present.
    print(f"[{prefix}] Successfully caught expected TypeError.", file=sys.stderr)
    pass
"""
    },
    'generator_method_call': {
        'description': 'Tests JIT stability with method calls inside generator expressions in a hot loop.',
        'target_mechanism': 'JIT interaction with generator frames',
        'setup_code': """
class Target_{prefix}:
    def __init__(self):
        self.attr = 0
    def method(self, arg):
        self.attr += 1
""",
        'body_code': """
target_instance = Target_{prefix}()
for {loop_var} in range({loop_iterations}):
    # The JIT must correctly handle the 'target_instance.method' call,
    # which is inside a generator that is created and consumed in the hot loop.
    gen = (_ for _ in [target_instance.method(None)])
    try:
        # We must consume the generator for its code to execute.
        next(gen)
        next(gen)
    except StopIteration:
        pass
"""
    },
    'friendly_base': {
        'description': 'A general-purpose base pattern for friendly, AST-driven mutation. Contains a mix of common operations.',
        'target_mechanism': 'General JIT optimization paths',
        'setup_code': """
# Setup some basic variables for the pattern to use.
var_a_{prefix} = 100
var_b_{prefix} = 200
var_list_{prefix} = [1, 2, 3, 4]
var_str = "abcdefg"
var_tuple = (var_str, 2, 3)
""",
        'body_code': """
# This simple loop structure is the entry point for the AST mutator.
for {loop_var} in range(1, 2000):
    # The mutator can swap these operators, perturb constants, etc.
    temp_val = var_a_{prefix} + {loop_var}

    # The mutator can swap the comparison and duplicate statements.
    if temp_val > var_b_{prefix}:
        var_a_{prefix} = temp_val - 10

    # The mutator can change the method call or arguments.
    var_list_{prefix}.append({loop_var})

    if 20 in var_list_{prefix}:
        x_{prefix}, y_{prefix} = (temp_val, {loop_var})

    char = var_str[{loop_var} % len(var_str)]
"""
    },
    'many_vars_base': {
        'description': 'A base for creating functions with >256 variables and a mutated body.',
        'target_mechanism': 'EXTENDED_ARG, register allocation',
        'setup_code': """
# Define over 256 local variables.
{var_definitions}
""",
        'body_code': """
# Hot loop that uses the many variables in a complex expression.
total = 0
for {loop_var} in range(1, 1000):
    try:
        # This expression will be generated by the AST mutator
        # using the large pool of available variables.
        total += {expression}
    except Exception:
        pass
return total
"""
    },
    'jit_friendly_math': {
        'description': 'A "twin execution" test for a block of JIT-friendly math and logic patterns.',
        'target_mechanism': 'General JIT arithmetic and logic paths',
        'setup_code': """
# Setup some basic variables for the pattern to use.
var_a_{prefix} = 100
var_b_{prefix} = 200
""",
        'body_code': """
total = 0
# Use pre-generated constants to ensure both paths are identical.
var_int_a = var_a_{prefix}
var_int_b = var_b_{prefix}
for {loop_var} in range(1000):
    if {loop_var} > var_int_b:
        temp_val = (var_int_a + {loop_var}) % 1000
        total += temp_val
    else:
        total -= 1
return total
"""
    },
    'evil_boundary_math': {
        'description': 'A correctness test using complex operations and boundary values.',
        'target_mechanism': 'JIT handling of boundary values (NaN, inf, maxint) and exceptions.',
        'setup_code': """
import operator
# Pre-generate problematic constants once.
var_a = {val_a}
var_b = {val_b}
var_c = {val_c}
str_d = {str_d}
""",
        'body_code': """
total = 0.0 # Use a float accumulator for broader compatibility
for {loop_var} in range(1, 100): # Use a smaller loop for this complex test
    try:
        temp_val = (var_a + var_b) / {loop_var}
        temp_val_2 = var_c * {loop_var}
        if temp_val > temp_val_2:
            total += len(str_d) + len(str(temp_val))
        else:
            total -= temp_val_2
    except (ValueError, TypeError, ZeroDivisionError, OverflowError):
        total -= 1
return total
"""
    },
    'deleter_side_effect': {
        'description': 'A correctness test for the __del__ side effect attack.',
        'target_mechanism': 'DEOPT_IF on type confusion from __del__ side effects.',
        'setup_code': """
class FrameModifier_{prefix}:
    def __init__(self, var_name, new_value):
        self.var_name = var_name
        self.new_value = new_value
    def __del__(self):
        try:
            frame = sys._getframe(1)
            if self.var_name in frame.f_locals:
                frame.f_locals[self.var_name] = self.new_value
        except Exception: pass
""",
        'body_code': """
# A. Create a local variable and its FrameModifier
target_var = 100
fm_target_var = FrameModifier_{prefix}('target_var', 'local-string')

# Hot Loop
for i in range(500):
    try:
        x = target_var + i
    except TypeError:
        pass
    # Trigger on the penultimate iteration
    if i == 498:
        del fm_target_var
        collect()
return target_var
"""
    },
    'inplace_add_attack': {
        'description': 'A grey-box correctness test for the _BINARY_OP_INPLACE_ADD_UNICODE guard.',
        'target_mechanism': 'DEOPT_IF guard for inplace string addition.',
        'setup_code': """
class FrameModifier_{prefix}:
    def __init__(self, var_name, payload_var_name):
        self.var_name = var_name
        self.payload_var_name = payload_var_name
    def __del__(self):
        try:
            frame = sys._getframe(1)
            # Set the target variable to the value of the payload variable
            frame.f_locals[self.var_name] = frame.f_locals[self.payload_var_name]
        except Exception: pass
""",
        'body_code': """
s_target = 'start_'
# Create a new, different string object to be the payload
fm_payload = s_target + 'a'
fm = FrameModifier_{prefix}('s_target', 'fm_payload')

for i in range(250):
    if i == 248:
        del fm
        collect()
    try:
        s_target += str(i)
    except Exception:
        pass
return s_target
"""
    },
    'deep_calls_correctness': {
        'description': 'A correctness test for a deep recursive call chain.',
        'target_mechanism': 'JIT stack analysis, trace limits, function call overhead.',
        'setup_code': """
# Define a deep chain of functions. The AST mutator can alter the bodies.
def f_0_{prefix}(p):
    return p + 1

def f_1_{prefix}(p):
    return f_0_{prefix}(p) + 1

def f_2_{prefix}(p):
    return f_1_{prefix}(p) + 1

def f_3_{prefix}(p):
    return f_2_{prefix}(p) + 1

def f_4_{prefix}(p):
    return f_3_{prefix}(p) + 1

def f_5_{prefix}(p):
    return f_4_{prefix}(p) + 1

def f_6_{prefix}(p):
    return f_5_{prefix}(p) + 1

def f_7_{prefix}(p):
    return f_6_{prefix}(p) + 1

def f_8_{prefix}(p):
    return f_7_{prefix}(p) + 1

def f_9_{prefix}(p):
    return f_8_{prefix}(p) + 1

def f_10_{prefix}(p):
    return f_9_{prefix}(p) + 1

def f_11_{prefix}(p):
    return f_10_{prefix}(p) + 1

def f_12_{prefix}(p):
    return f_11_{prefix}(p) + 1

def f_13_{prefix}(p):
    return f_12_{prefix}(p) + 1

def f_14_{prefix}(p):
    return f_13_{prefix}(p) + 1
""",
        'body_code': """
# The top-level function in the chain.
top_level_func = f_14_{prefix}
total = 0
# The hot loop that calls the deep chain.
for i in range(20):
    total += top_level_func(i)
return total
"""
    },
    'managed_dict_attack': {
        'description': 'A correctness test for the managed dictionary guard on STORE_ATTR.',
        'target_mechanism': 'STORE_ATTR specialization, DEOPT_IF on non-dict object.',
        'setup_code': """
# Define the two classes needed for the polymorphic attribute access.
class ClassWithDict_{prefix}:
    pass

class ClassWithSlots_{prefix}:
    __slots__ = ['x'] # This class has no __dict__
""",
        'body_code': """
# Create a list of instances to use polymorphically.
objects_to_set = [ClassWithDict_{prefix}(), ClassWithSlots_{prefix}()]
for i in range(1000):
    # Polymorphically select an object and set an attribute.
    # This forces the JIT to guard on the object's dictionary type.
    obj = objects_to_set[i % 2]
    try:
        obj.x = i
    except AttributeError:
        # This is expected for the class with __slots__
        pass

# The final state of the objects is used for the correctness check.
# We return the attributes' values to be asserted.
dict_obj_x = getattr(objects_to_set[0], 'x', 'NOT_SET')
slots_obj_x = getattr(objects_to_set[1], 'x', 'NOT_SET')
return (dict_obj_x, slots_obj_x)
"""
    },
    'evil_deep_calls_correctness': {
        'description': 'A correctness test for a deep call chain that also uses boundary values, mixed operators, and calls a fuzzed function.',
        'target_mechanism': 'JIT stack analysis, handling of boundary values, calls to external functions.',
        'setup_code': """
# Setup for the evil deep call test
import operator

# Use the pre-generated constants and operators for this scenario
OPERATOR_SUITE = {operator_suite}
CONSTANTS = {constants}
EXCEPTION_LEVEL = {exception_level}

# Define the recursive function chain
def f_0_{prefix}(p_tuple):
    res = list(p_tuple)
    try:
        op = OPERATOR_SUITE[0]
        const = CONSTANTS[0]
        res[0] = op(res[0], const)
        # Also call the real fuzzed function from the target module
        {module_name}.{fuzzed_func_name}(res[0])
    except Exception:
        pass
    return tuple(res)

# Generate the rest of the chain...
{function_chain!s}
""",
        'body_code': """
# The top-level function is the final one in the chain
top_level_func = f_{depth_minus_1}_{prefix}
try:
    # Initial values for the test are the first two constants
    result = top_level_func((CONSTANTS[0], CONSTANTS[1]))
except ValueError as e:
    # Check if this is our intentionally raised probe
    if e.args == ('evil_deep_call_probe',):
        result = "PROBE_CAUGHT"
    else:
        raise
return result
"""
    },
}
