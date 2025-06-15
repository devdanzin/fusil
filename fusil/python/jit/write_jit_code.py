from __future__ import annotations

import ast
from textwrap import dedent
from typing import Any
from random import choice, randint, random
from typing import TYPE_CHECKING

import fusil.python.values
from fusil.python.jit.ast_mutator import ASTMutator
from fusil.python.jit.bug_patterns import BUG_PATTERNS

if TYPE_CHECKING:
    from fusil.python.write_python_code import WritePythonCode


class WriteJITCode:
    """
    Generates Python code with scenarios specifically designed to stress
    the CPython Tier 2 JIT optimizer.
    """

    def __init__(self, parent: "WritePythonCode"):
        # We hold a reference to the main writer to access its options,
        # argument generator, and file writing methods.
        self.parent = parent
        self.options = parent.options
        self.arg_generator = parent.arg_generator
        self.module_name = parent.module_name

        self.ast_mutator = ASTMutator()

        # Bind the writing methods directly for convenience
        self.write = parent.write
        self.addLevel = parent.addLevel
        self.restoreLevel = parent.restoreLevel
        self.emptyLine = parent.emptyLine
        self.write_print_to_stderr = parent.write_print_to_stderr

        self.jit_warmed_targets = []

    def generate_scenario(self, prefix: str) -> None:
        """
        Main entry point for generating a JIT-specific scenario.
        This method decides which type of scenario (correctness, hostile, friendly)
        to generate based on the fuzzer's configuration.
        """
        if not self.parent.module_functions:
            return

        fuzzed_func_name = choice(self.parent.module_functions)
        try:
            fuzzed_func_obj = getattr(self.parent.module, fuzzed_func_name)
        except AttributeError:
            return

        if self.options.rediscover_decref_crash:
            self._generate_decref_escapes_scenario(prefix)
            return

        if self.options.jit_fuzz_patterns:
            self._generate_variational_scenario(prefix, self.options.jit_fuzz_patterns)
            return

        # Correctness testing takes precedence if enabled.
        if self.options.jit_correctness_testing and random() < self.options.jit_hostile_prob / 5:
            self._generate_correctness_scenario(prefix, fuzzed_func_name, fuzzed_func_obj)
            return

        # Fallback to crash/hang testing scenarios.
        level = self.options.jit_fuzz_level

        if level >= 3 and random() < self.options.jit_hostile_prob:
            self._generate_hostile_scenario(prefix, fuzzed_func_name, fuzzed_func_obj, is_mixed=True)
        elif level >= 2 and random() < self.options.jit_hostile_prob:
            self._generate_hostile_scenario(prefix, fuzzed_func_name, fuzzed_func_obj, is_mixed=False)
        else:  # Level 1 or failed probability rolls
            self._generate_friendly_scenario(prefix, fuzzed_func_name, fuzzed_func_obj)

    def _generate_correctness_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """Chooses and generates one of the self-checking correctness scenarios."""
        generators = [
            self._generate_jit_pattern_block_with_check,
            self._generate_evil_jit_pattern_block_with_check,
            self._generate_deleter_scenario_with_check,
            self._generate_deep_calls_scenario_with_check,
            self._generate_evil_deep_calls_scenario_with_check,
            self._generate_inplace_add_attack_scenario_with_check,
            self._generate_global_invalidation_scenario_with_check,
            self._generate_managed_dict_attack_scenario_with_check,
        ]
        chosen = choice(generators)
        chosen(prefix, fuzzed_func_name, fuzzed_func_obj)

    def _generate_hostile_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any,
                                   is_mixed: bool) -> None:
        """Chooses and generates one of the hostile (crash-finding) scenarios."""
        # Level 2 scenarios (isolated hostile)
        hostile_generators = [
            self._generate_invalidation_scenario,
            self._generate_deleter_scenario,
            self._generate_many_vars_scenario,
            self._generate_deep_calls_scenario,
            self._generate_type_version_scenario,
            self._generate_concurrency_scenario
        ]

        # Level 3 scenarios (mixed hostile)
        if is_mixed:
            hostile_generators.extend([
                self._generate_mixed_many_vars_scenario,
                self._generate_del_invalidation_scenario,
                self._generate_mixed_deep_calls_scenario,
                self._generate_deep_call_invalidation_scenario,
                self._generate_fuzzed_func_invalidation_scenario,
                self._generate_polymorphic_call_block_scenario
            ])

        # Add flag-based scenarios
        if self.options.jit_hostile_side_exits:
            hostile_generators.append(self._generate_side_exit_scenario)
        if self.options.jit_hostile_isinstance:
            hostile_generators.append(self._generate_isinstance_attack_scenario)

        chosen = choice(hostile_generators)
        chosen(prefix, fuzzed_func_name, fuzzed_func_obj)

    def _generate_friendly_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """Chooses and generates one of the JIT-friendly (warm-up) scenarios."""
        if random() < 0.5:
            self._generate_jit_pattern_block(prefix, fuzzed_func_name, fuzzed_func_obj)
        else:
            self._generate_polymorphic_call_block(prefix, fuzzed_func_name, fuzzed_func_obj)

    def generate_stateful_object_scenario(self, prefix: str, instance_var_name: str, class_name_str: str,
                                          class_type: type) -> None:
        """Generates a stateful hot loop for a class instance."""
        # This method is called from _fuzz_one_class in the main writer
        self.write_print_to_stderr(0, f'"[{prefix}] JIT MODE: Stateful fuzzing for class: {class_name_str}"')
        self.write(0, f"if {instance_var_name} is not None and {instance_var_name} is not SENTINEL_VALUE:")
        self.addLevel(1)
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        self.write(0, '"INDENTED BLOCK"')

        # ... logic to call random methods on the instance ...
        methods_dict = self.parent._get_object_methods(class_type, class_name_str)
        if methods_dict:
            chosen_method_name = choice(list(methods_dict.keys()))
            chosen_method_obj = methods_dict[chosen_method_name]
            self.parent._generate_and_write_call(
                prefix=f"{prefix}_{chosen_method_name}",
                callable_name=chosen_method_name,
                callable_obj=chosen_method_obj,
                min_arg_count=0,
                target_obj_expr=instance_var_name,
                is_method_call=True,
                generation_depth=0,
                in_jit_loop=True,
            )
        self.restoreLevel(self.parent.base_level - 2)  # exit for and if

    def _generate_jit_pattern_block(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """Generates a block of code with patterns designed to stress the JIT."""
        self.write_print_to_stderr(
            0, f'"[{prefix}] Generating JIT-optimized pattern block."'
        )

        # 1. Initialize some variables for the block to use
        self.write(0, f"var_int_a = {self.arg_generator.genInt()[0]}")
        self.write(0, f"var_int_b = {self.arg_generator.genSmallUint()[0]}")
        self.write(0, f'var_str_c = "fusil_jit_fuzzing_string"')
        self.write(0, f"var_list_d = [10, 20, 30, 40, 50]")
        self.write(0, f"var_tuple_e = (100, 200, 300)")
        self.write(0, f"temp_val = 0")
        self.emptyLine()

        # 2. Create the hot loop
        loop_iterations = self.options.jit_loop_iterations
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
        # 3. Weave in the JIT-friendly patterns inside the loop
        # Math, Truth Tests, Subscripts, and Calls
        self.write(0, f"if i_{prefix} > var_int_b:")
        self.write(1, f"temp_val = var_int_a + i_{prefix}")
        self.write(1, f"char = var_str_c[i_{prefix} % len(var_str_c)]")

        # Containment check and Unpacking
        self.write(0, "if 20 in var_list_d:")
        self.write(1, f"x_{prefix}, y_{prefix} = (i_{prefix}, temp_val)")

        # Attribute loading on a common object
        self.write(0, f"var_list_d.append(i_{prefix})")

        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

    def _generate_polymorphic_call_block(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """Generates a hot loop with calls to one function using args of different types."""
        if not self.parent.module_functions:
            return

        func_name = choice(self.parent.module_functions)
        target_func_name = fuzzed_func_name

        self.write(0, "fuzzed_func_is_viable = True")
        self.write(0, "try:")
        self.addLevel(1)
        # Warm up with one simple call.
        self.write(0, f"callFunc('{prefix}_warmup', '{target_func_name}', 1)")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(0,
                                   f'"[{prefix}] Fuzzed function failed on warmup, skipping polymorphic block: {{e}}"')
        self.write(0, "fuzzed_func_is_viable = False")
        self.restoreLevel(self.parent.base_level - 1)
        self.write_print_to_stderr(
            0, f'"[{prefix}] Generating polymorphic call block for: {func_name}"'
        )

        # Select a few argument generators to cycle through
        poly_gens = [
            self.arg_generator.genInt,
            self.arg_generator.genString,
            self.arg_generator.genList,
            self.arg_generator.genBytes,
            self.arg_generator.genBool,
            self.arg_generator.genFloat,
        ]

        # Get N diverse generators
        num_types = self.options.jit_polymorphic_degree
        gens_to_use = [choice(poly_gens) for _ in range(num_types)]

        # Write the hot loop
        loop_iterations = self.options.jit_loop_iterations // num_types
        self.write(0, "if fuzzed_func_is_viable:")
        self.addLevel(1)
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for _ in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if _ % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
        self.write(0, f"'INDENTED BLOCK'")


        # Inside the loop, call the same function with different typed args
        for gen_func in gens_to_use:
            arg_str = " ".join(gen_func())
            self.write(0, f"callFunc('{prefix}', '{func_name}', {arg_str}, verbose=False)")

        self.restoreLevel(self.parent.base_level - 1)  # for
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()
        self.restoreLevel(self.parent.base_level - 1)  # if
        self.emptyLine()

    def _generate_phase1_warmup(self, prefix: str) -> dict | None:
        if not self.parent.module_classes:
            return None

        class_name = choice(self.parent.module_classes)
        class_obj = getattr(self.parent.module, class_name)
        methods = self.parent._get_object_methods(class_obj, class_name)
        if not methods:
            return None

        method_name = choice(list(methods.keys()))
        method_obj = methods[method_name]
        instance_var = f"instance_{prefix}"

        self.write_print_to_stderr(0, f'"[{prefix}] PHASE 1: Warming up {class_name}.{method_name}"')

        # Generate instantiation code
        # (This reuses logic from your existing _fuzz_one_class)
        self.write(0, f"{instance_var} = callFunc('{prefix}_init', '{class_name}')")

        # Generate the hot loop
        self.write(0, f"if {instance_var} is not None and {instance_var} is not SENTINEL_VALUE:")
        self.addLevel(1)
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if _ % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        # Generate the repeated call inside the loop
        self.parent._generate_and_write_call(
            prefix=f"{prefix}_warmup",
            callable_name=method_name,
            callable_obj=method_obj,
            min_arg_count=0,
            target_obj_expr=instance_var,
            is_method_call=True,
            generation_depth=0,
            in_jit_loop=True,
            verbose=False,
        )

        self.restoreLevel(self.parent.base_level - 1)  # Exit for
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()
        self.restoreLevel(self.parent.base_level - 1)  # Exit if

        # Store context for the next phases
        target_info = {
            'type': 'method_call',
            'class_name': class_name,
            'instance_var': instance_var,
            'method_name': method_name,
        }
        self.jit_warmed_targets.append(target_info)
        return target_info

    def _generate_phase2_invalidate(self, prefix: str, target_info: dict) -> None:
        self.write_print_to_stderr(0, f'"[{prefix}] PHASE 2: Invalidating dependency for {target_info["class_name"]}"')

        class_name = target_info['class_name']
        method_name = target_info['method_name']

        # Invalidate by replacing the method on the class with a lambda
        # This is inspired by test_guard_type_version_executor_invalidated from test_opt.py
        self.write(0, "# Maliciously replacing the method on the class to invalidate JIT cache")
        self.write(0, "try:")
        self.write(1,
                   f"setattr({self.module_name}.{class_name}, '{method_name}', lambda *a, **kw: 'invalidation payload')")
        self.write(1, "collect() # Encourage cleanup")
        self.write(0, "except Exception as e:")
        self.write_print_to_stderr(1, f'f"[{prefix}] PHASE 2: Exception invalidating {target_info["class_name"]}: {{ e }}"')


        self.emptyLine()

    def _generate_phase3_reexecute(self, prefix: str, target_info: dict) -> None:
        self.write_print_to_stderr(0,
                                   f'"[{prefix}] PHASE 3: Re-executing {target_info["method_name"]} to check for crash"')

        instance_var = target_info['instance_var']
        method_name = target_info['method_name']

        self.write(0, f"if {instance_var} is not None and {instance_var} is not SENTINEL_VALUE:")
        self.addLevel(1)
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if _ % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "try:")
        self.addLevel(1)

        # Re-execute the original call. We don't need the full _generate_and_write_call,
        # just a simple call to the now-potentially-broken method.
        self.write(0, f"getattr({instance_var}, '{method_name}')()")

        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        # Log expected exceptions, a crash is the real prize.
        self.write_print_to_stderr(0, f'f"[{prefix}] Caught expected exception: {{e.__class__.__name__}}"')
        self.write(0, "break")

        self.restoreLevel(self.parent.base_level - 3) # Exit try, loop, if
        if self.options.jit_raise_exceptions:
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

    def _generate_invalidation_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        Orchestrates the generation of a three-phase JIT invalidation scenario.

        This method calls helper methods to generate code for each phase:
        1. Warm-up: JIT-compile a target method.
        2. Invalidate: Change a dependency of the compiled code.
        3. Re-execute: Call the target method again to check for crashes.
        """
        self.write(0, f"# --- JIT Invalidation Scenario: {prefix} ---")
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Invalidation Scenario <<<"'
        )
        self.emptyLine()

        # --- Phase 1: Warm-up and JIT Compilation ---
        # This call generates the code to get a method JIT-compiled and returns
        # information about that target for the subsequent phases.
        target_info = self._generate_phase1_warmup(prefix)

        # --- Check if a suitable target was found ---
        if target_info:
            # If warmup was successful, proceed to the next phases.
            self.emptyLine()

            # --- Phase 2: Invalidate Dependency ---
            # This call uses the info from phase 1 to generate code that
            # maliciously alters a dependency of the JIT-compiled code.
            self._generate_phase2_invalidate(prefix, target_info)
            self.emptyLine()

            # --- Phase 3: Re-execute and Check for Crash ---
            # This call generates code to run the original target again. If the
            # JIT cache was not correctly invalidated, this is where a crash
            # or incorrect behavior would occur.
            self._generate_phase3_reexecute(prefix, target_info)

        else:
            # If no suitable target was found in Phase 1, log it and abort this scenario.
            self.write_print_to_stderr(
                0, f'"[{prefix}] Could not find a suitable target for an invalidation scenario. Skipping."'
            )

        self.emptyLine()
        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished JIT Invalidation Scenario >>>"'
        )
        self.write(0, f"# --- End Scenario: {prefix} ---")
        self.emptyLine()

    def _generate_deleter_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        Generates a sophisticated scenario that uses a __del__ side effect
        to induce type confusion for local, instance, and class variables.
        The side effect is triggered only once, near the end of the hot loop.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] >>> Starting Advanced __del__ Side Effect Scenario <<<"')

        # --- 1. SETUP OUTSIDE THE LOOP ---
        # Define unique names for all our variables using the prefix.
        target_var = f"target_{prefix}"
        fm_target_var = f"fm_{target_var}"
        dummy_class_name = f"Dummy_{prefix}"
        dummy_instance_name = f"dummy_instance_{prefix}"
        fm_dummy_class_attr = f"fm_{dummy_instance_name}_a"
        fm_dummy_instance_attr = f"fm_{dummy_instance_name}_b"
        loop_iterations = self.options.jit_loop_iterations

        # Create the local variable and its FrameModifier.
        self.write(0, f"# A. Create a local variable and its FrameModifier")
        self.write(0, f"{target_var} = 100")
        self.write(0, f"{fm_target_var} = FrameModifier('{target_var}', 'local-string')")
        self.write(0, f"fm_target_i_{prefix} = FrameModifier('i_{prefix}', 'local-string')")
        self.emptyLine()

        # Create the class, instance, and their FrameModifiers.
        self.write(0, f"# B. Create a class with instance/class attributes and their FrameModifiers")
        self.write(0, f"class {dummy_class_name}:")
        self.write(1, "a = 200  # Class attribute")
        self.write(1, "def __init__(self):")
        self.write(2, "self.b = 300  # Instance attribute")
        self.write(0, f"{dummy_instance_name} = {dummy_class_name}()")
        # Note: The target strings now include the instance name, e.g., 'dummy_instance_f1.a'
        self.write(0, f"{fm_dummy_class_attr} = FrameModifier('{dummy_instance_name}.a', 'class-attr-string')")
        self.write(0, f"{fm_dummy_instance_attr} = FrameModifier('{dummy_instance_name}.b', 'instance-attr-string')")
        self.emptyLine()

        # --- 2. HOT LOOP ---
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        # --- 2A. WARM-UP PHASE (inside loop) ---
        self.write(0, f"# Use all variables to warm up the JIT with their initial types")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"{target_var} + {target_var}")
        self.write(0, f"i_{prefix} + i_{prefix}")
        # self.write(0, f"x = {target_var} + i_{prefix}")
        self.write(0, f"y = {dummy_instance_name}.a + i_{prefix}")
        self.write(0, f"z = {dummy_instance_name}.b + i_{prefix}")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except TypeError: pass")
        self.emptyLine()

        # --- 2B. TRIGGER PHASE (inside loop) ---
        # Trigger the deletion on the penultimate iteration to ensure the loop
        # runs one more time with the corrupted state.
        self.write(0, f"# On the penultimate loop, delete the FrameModifiers to trigger __del__")
        self.write(0, f"if i_{prefix} == {loop_iterations - 2}:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] DELETING FRAME MODIFIERS..."')
        self.write(0, f"del {fm_target_var}")
        self.write(0, f"del {fm_dummy_class_attr}")
        self.write(0, f"del {fm_dummy_instance_attr}")
        self.write(0, f"del fm_target_i_{prefix}")
        self.write(0, "collect()")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # --- 2C. RE-EXECUTE PHASE (inside loop) ---
        self.write(0, f"# Use the variables again, which may hit a corrupted JIT state after deletion")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"i_{prefix} + i_{prefix}")
        self.write(0, f"{target_var} + {target_var}")
        self.write(0, f"res_local = {target_var} + i_{prefix}")
        self.write(0, f"res_cls_attr = {dummy_instance_name}.a + i_{prefix}")
        self.write(0, f"res_inst_attr = {dummy_instance_name}.b + i_{prefix}")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except TypeError as e:")
        self.write(1, "pass # This TypeError is expected if the side effect worked")
        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        self.write_print_to_stderr(0, f'"[{prefix}] <<< Finished Advanced __del__ Side Effect Scenario >>>"')
        self.emptyLine()

    def _generate_many_vars_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        Generates a function with >256 local variables to stress the JIT's
        bytecode parser, specifically its handling of the EXTENDED_ARG opcode.
        """
        func_name = f"many_vars_func_{prefix}"
        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Many Vars" Resource Limit Scenario <<<"""')
        self.write(0, f"# Define a function with an unusually large number of local variables.")
        self.write(0, f"def {func_name}():")
        self.addLevel(1)

        # 1. Generate over 256 local variable assignments.
        num_vars = 260  # A value safely over the 256 threshold
        for i in range(num_vars):
            self.write(0, f"var_{i} = {i}")

        # 2. Add a hot loop that uses some of these variables to make the function
        #    a candidate for JIT compilation.
        self.write(0, f"# Hot loop to trigger JIT compilation of this large function.")
        self.write(0, "total = 0")
        if self.options.jit_raise_exceptions and 0:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions and 0:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
        # Use the first, middle, and last variables to ensure they aren't optimized away.
        self.write(0, f"total += var_0 + var_{num_vars // 2} + var_{num_vars - 1}")
        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        self.write(0, "return total")
        self.restoreLevel(self.parent.base_level - 1)  # Exit def
        self.emptyLine()

        # 3. Call the newly defined function.
        self.write(0, f"# Execute the function with many variables.")
        self.write(0, f"{func_name}()")
        self.write_print_to_stderr(0, f'"""[{prefix}] <<< Finished "Many Vars" Scenario >>>"""')
        self.emptyLine()
        if self.options.jit_raise_exceptions and 0:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

    def _generate_deep_calls_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        Generates a deep chain of function calls to stress the JIT's
        stack analysis and trace stack limits.
        """
        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Deep Calls" Resource Limit Scenario <<<"""')

        # 1. Define the base case for the call chain.
        depth = 20  # A reasonably deep call chain
        self.write(0, f"# Define a deep chain of {depth} nested function calls.")
        self.write(0, f"def f_0_{prefix}(): return 1")

        # 2. Generate the chain of functions, each calling the previous one.
        for i in range(1, depth):
            self.write(0, f"def f_{i}_{prefix}(): return 1 + f_{i - 1}_{prefix}()")

        top_level_func = f"f_{depth - 1}_{prefix}"
        self.emptyLine()

        # 3. Call the top-level function inside a hot loop to trigger the JIT.
        #    Wrap it in a try...except RecursionError since this is a possible outcome.
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"# Execute the top-level function of the chain in a hot loop.")
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if _ % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"{top_level_func}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except RecursionError:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Caught expected RecursionError."')
        self.write(0, "break # Exit loop if recursion limit is hit")
        self.restoreLevel(self.parent.base_level - 2)  # Exit except and for loop

        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()
        self.write_print_to_stderr(0, f'"""[{prefix}] <<< Finished "Deep Calls" Scenario >>>"""')
        self.emptyLine()

    def _define_frame_modifier_instances(self, prefix: str, targets_and_payloads: dict) -> list[str]:
        """
        Generates the 'fm_... = FrameModifier(...)' lines for a set of targets.

        Args:
            prefix: The unique prefix for this scenario.
            targets_and_payloads: A dictionary mapping target variable paths
                                  (e.g., 'var_250') to their malicious payload.

        Returns:
            A list of the variable names created for the FrameModifier instances.
        """
        fm_vars = []
        self.write(0, "# Define FrameModifier instances to arm the __del__ side effects.")
        for i, (target_path, payload) in enumerate(targets_and_payloads.items()):
            fm_var_name = f"fm_{prefix}_{i}"
            self.write(0, f"{fm_var_name} = FrameModifier('{target_path}', {payload})")
            fm_vars.append(fm_var_name)
        self.emptyLine()
        return fm_vars

    def _generate_del_trigger(self, loop_var: str, loop_iterations: int, fm_vars_to_del: list[str]) -> None:
        """
        Generates the 'if ...: del ...' block to trigger the __del__ methods
        on the penultimate iteration of a loop.
        """
        self.write(0, f"# Trigger the __del__ side effect on the penultimate iteration.")
        self.write(0, f"if {loop_var} == {loop_iterations - 2}:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[+] Deleting FrameModifiers to trigger side effects..."')
        for fm_var in fm_vars_to_del:
            self.write(0, f"del {fm_var}")
        self.write(0, "collect()")
        self.restoreLevel(self.parent.base_level - 1)

    def _generate_mixed_many_vars_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        MIXED SCENARIO 1: Combines "Many Vars", `__del__` side effects, and
        JIT-friendly math/logic patterns into one hostile function.
        """
        func_name = f"mixed_many_vars_func_{prefix}"
        loop_var = f"i_{prefix}"
        num_vars = 260
        loop_iterations = self.options.jit_loop_iterations

        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Mixed Many Vars" Hostile Scenario <<<"""')
        self.write(0, f"def {func_name}():")
        self.addLevel(1)

        # 1. Define 260+ local variables to stress EXTENDED_ARG.
        self.write(0, f"# Define {num_vars} local variables.")
        for i in range(num_vars):
            self.write(0, f"var_{i} = {i}")
        self.emptyLine()

        # 2. Arm the __del__ side effect using our new helper.
        #    We will target a high-index variable that is used in the hot loop.
        target_variable_path = f'var_{num_vars - 1}'
        fm_vars = self._define_frame_modifier_instances(
            prefix, {target_variable_path: "'corrupted-by-del'"}
        )

        # 3. Add a hot loop.
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for {loop_var} in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if {loop_var} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        # 4. Inside the loop, generate JIT-friendly patterns that use the variables.
        self.write(0, "# Use variables in JIT-friendly patterns.")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"res = var_0 + {loop_var}")
        self.write(0, f"res += var_{num_vars - 1} # This is the variable we will corrupt.")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except TypeError: pass")
        self.emptyLine()

        # 5. Inside the loop, plant the time bomb using our new helper.
        self._generate_del_trigger(loop_var, loop_iterations, fm_vars)

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        self.emptyLine()

        # 6. Call the master function we just created.
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()
        self.restoreLevel(self.parent.base_level - 1)  # Exit def

        self.write(0, f"# Execute the composed hostile function.")
        self.write(0, f"{func_name}()")

        self.write_print_to_stderr(0, f'"""[{prefix}] <<< Finished "Mixed Many Vars" Scenario >>>"""')
        self.emptyLine()

    def _generate_del_invalidation_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        MIXED SCENARIO 2: An invalidation scenario where the invalidation
        is performed indirectly via a __del__ side effect.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting __del__ Invalidation Scenario <<<"'
        )
        self.emptyLine()

        # --- Phase 1: Warm-up ---
        target_info = self._generate_phase1_warmup(prefix)

        if not target_info:
            self.write_print_to_stderr(
                0, f'"[{prefix}] Could not find a suitable target. Aborting scenario."'
            )
            self.emptyLine()
            return

        self.emptyLine()

        # --- Phase 2: Invalidate via __del__ ---
        self.write_print_to_stderr(
            0, f'"[{prefix}] PHASE 2: Arming FrameModifier to invalidate via __del__."'
        )

        # The target path is the method on the class, e.g., 'MyTargetClass.target_method'
        target_path = f'{self.module_name}.{target_info["class_name"]}.{target_info["method_name"]}'

        fm_vars = self._define_frame_modifier_instances(
            prefix, {target_path: "lambda *a, **kw: 'invalidated by __del__'"}
        )

        # Immediately delete the instance to trigger the __del__ method.
        self.write(0, "# Immediately delete the FrameModifier to trigger the side effect.")
        for fm_var in fm_vars:
            self.write(0, f"del {fm_var}")
        self.write(0, "collect()")
        self.emptyLine()

        # --- Phase 3: Re-execute ---
        self._generate_phase3_reexecute(prefix, target_info)

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished __del__ Invalidation Scenario >>>"'
        )
        self.emptyLine()

    def _generate_mixed_deep_calls_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        MIXED SCENARIO 3: Combines "Deep Calls" with JIT-friendly patterns.
        Each function in the deep call chain performs complex work, stressing
        the JIT's ability to optimize across many active stack frames.
        """
        self.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Mixed Deep Calls" Hostile Scenario <<<"""'
        )

        depth = 15  # A moderately deep chain is sufficient when each frame does work.
        loop_iterations = self.options.jit_loop_iterations // 100  # A smaller loop is fine for this test

        self.write(0, f"# Define a deep chain of {depth} functions, each with internal JIT-friendly patterns.")

        # 1. Define the base case (the final function in the chain).
        #    It performs some work instead of just returning a value.
        self.write(0, f"def f_0_{prefix}(p):")
        self.addLevel(1)
        self.write(0, "x = len('base_case') + p")
        self.write(0, "y = x % 5")
        self.write_print_to_stderr(0, f'''f"[{prefix}] Calling fuzzed function '{fuzzed_func_name}' from deep inside the call chain"''')
        self.write(0, f"callFunc('{prefix}_fuzzed', '{fuzzed_func_name}', x)")
        self.write(0, "return x - y")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Generate the intermediate functions in the chain.
        for i in range(1, depth):
            self.write(0, f"def f_{i}_{prefix}(p):")
            self.addLevel(1)
            # Each function performs its own JIT-friendly work.
            self.write(0, f"local_val = p * {i}")
            self.write(0, "s = 'abcdef'")
            self.write(0, f"if local_val > 10 and (s[{i} % len(s)]):")
            self.write(1, f"local_val += f_{i - 1}_{prefix}(p)")
            self.write(0, "return local_val")
            self.restoreLevel(self.parent.base_level - 1)
            self.emptyLine()

        top_level_func = f"f_{depth - 1}_{prefix}"

        # 3. Call the top-level function inside a hot loop to trigger the JIT.
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, "# Execute the top-level function of the complex chain in a hot loop.")
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"{top_level_func}(i_{prefix})")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except RecursionError:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Caught expected RecursionError."')
        self.write(0, "break")
        self.restoreLevel(self.parent.base_level - 2)  # Exit except and for loop
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        self.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Mixed Deep Calls" Scenario >>>"""'
        )
        self.emptyLine()

    def _generate_deep_call_invalidation_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        MIXED SCENARIO 4: Combines "Deep Calls" with an invalidation attack.
        A deep function call chain is JIT-compiled, then a function in the
        middle of the chain is redefined, testing the JIT's ability to
        invalidate the entire dependent trace.
        """
        self.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Deep Call Invalidation" Hostile Scenario <<<"""'
        )

        depth = 20  # A deep chain to create a long dependency graph.
        loop_iterations = self.options.jit_loop_iterations // 100

        # --- Phase 1: Define and Warm-up the Call Chain ---
        self.write(0, f"# Phase 1: Define a deep chain of {depth} functions.")

        # Define the base case.
        self.write(0, f"def f_0_{prefix}(p): return p + 1")

        # Define the recursive chain.
        for i in range(1, depth):
            self.write(0, f"def f_{i}_{prefix}(p): return f_{i - 1}_{prefix}(p) + 1")

        top_level_func = f"f_{depth - 1}_{prefix}"
        self.emptyLine()

        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Warming up the deep call chain..."')
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
        self.write(0, f"{top_level_func}(i_{prefix})")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        # --- Phase 2: Invalidate a Middle Link ---
        # We will redefine a function right in the middle of the chain.
        invalidation_index = depth // 2
        invalidation_func_name = f"f_{invalidation_index}_{prefix}"

        self.write_print_to_stderr(
            0, f'"[{prefix}] Phase 2: Invalidating the middle of the call chain ({invalidation_func_name})..."'
        )
        self.write(0, "# Redefine the middle function to return a completely different type.")
        self.write(0, f"def {invalidation_func_name}(p):")
        self.addLevel(1)
        self.write(0, "return '<< JIT-INVALIDATED >>'")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "collect()")
        self.emptyLine()

        # --- Phase 3: Re-execute the Chain ---
        self.write_print_to_stderr(
            0, f'"[{prefix}] Phase 3: Re-executing the chain to check for crashes..."'
        )
        self.write(0, "# The function now called by f_{invalidation_index+1} has changed.")
        self.write(0, "# This should raise a TypeError if the JIT de-optimizes correctly.")
        self.write(0, "# A segfault indicates a successful fuzzing attack.")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"{top_level_func}(1)")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except TypeError:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Caught expected TypeError after invalidation."')
        self.restoreLevel(self.parent.base_level - 1)

        self.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Deep Call Invalidation" Scenario >>>"""'
        )
        self.emptyLine()

    def _generate_indirect_call_scenario(self, prefix, fuzzed_func_name: str, fuzzed_func_obj: Any):
        harness_func_name = f"harness_{prefix}"
        self.write_print_to_stderr(0, f'"[{prefix}] >>> Starting Indirect Call Scenario ({fuzzed_func_name}) <<<"')

        # 1. Define a harness function that takes a callable.
        self.write(0, f"def {harness_func_name}(callable_arg):")
        self.addLevel(1)
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "try: callable_arg(i)")  # Call the argument
        self.restoreLevel(self.parent.base_level - 2)  # Exit loop and def
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        # 2. Call the harness, passing the fuzzed function to it.
        self.write(0, f"# Pass the real fuzzed function to the JIT-hot harness.")
        fuzzed_func_path = f"{self.module_name}.{fuzzed_func_name}"
        self.write(0, f"{harness_func_name}({fuzzed_func_path})")

    def _generate_fuzzed_func_invalidation_scenario(self, prefix: str, fuzzed_func_name: str,
                                                    fuzzed_func_obj: Any) -> None:
        """
        MIXED SCENARIO: A three-phase invalidation attack where the fuzzed
        function itself is the dependency that gets invalidated.
        """
        wrapper_func_name = f"jit_wrapper_{prefix}"
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Fuzzed Function Invalidation Scenario ({fuzzed_func_name}) <<<"'
        )
        self.emptyLine()

        # --- Phase 1: Define a Wrapper and Warm It Up ---
        self.write(0, f"# Phase 1: Define a wrapper and JIT-compile it.")
        self.write(0, f"def {wrapper_func_name}():")
        self.addLevel(1)
        # The wrapper simply calls our target fuzzed function.
        self.write(0, f"try:")
        self.addLevel(1)
        self.write(0, f"{self.module_name}.{fuzzed_func_name}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except: pass")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # Warm up the wrapper so the JIT compiles it and likely inlines the fuzzed function call.
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if _ % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        self.write(0, f"{wrapper_func_name}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        # --- Phase 2: Invalidate the Fuzzed Function ---
        self.write_print_to_stderr(
            0, f'"[{prefix}] Phase 2: Redefining {fuzzed_func_name} on the module..."'
        )
        self.write(0, f"# Maliciously redefine the fuzzed function on its own module.")
        # This change must be detected by the JIT, invalidating the optimized wrapper.
        self.write(0, f"setattr({self.module_name}, '{fuzzed_func_name}', lambda *a, **kw: 'payload')")
        self.write(0, "collect()")
        self.emptyLine()

        # --- Phase 3: Re-execute the Wrapper ---
        self.write_print_to_stderr(
            0, f'"[{prefix}] Phase 3: Re-executing the wrapper to check for crashes..."'
        )
        self.write(0, f"try: {wrapper_func_name}()")
        self.write(0, "except Exception as e:")
        self.write(1, 'pass # Any exception is fine, a crash is the goal.')
        self.emptyLine()

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Fuzzed Function Invalidation Scenario >>>"'
        )

    def _generate_polymorphic_call_block_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        Generates a hot loop that makes calls to different KINDS of callables
        (fuzzed function, lambda, instance method) to stress call-site caching.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Polymorphic Callable Set Scenario ({fuzzed_func_name}) <<<"'
        )

        # 1. Define the set of diverse callables.
        lambda_name = f"lambda_{prefix}"
        self.write(0, f"{lambda_name} = lambda x: x + 1")

        class_name = f"CallableClass_{prefix}"
        instance_name = f"instance_{prefix}"
        self.write(0, f"class {class_name}:")
        self.write(1, "def method(self, x): return x * 2")
        self.write(0, f"{instance_name} = {class_name}()")
        self.emptyLine()

        # List of callables to be used in the loop.
        # This prepares the paths for calling each one.
        callables_to_test = [
            f"{self.module_name}.{fuzzed_func_name}",
            lambda_name,
            f"{instance_name}.method",
        ]

        # 2. Create the hot loop.
        # Divide iterations among the callables.
        loop_iterations = self.options.jit_loop_iterations // len(callables_to_test)
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        # 3. Inside the loop, call each of the different callables.
        self.write(0, "# Call different types of callables to stress the JIT's call-site caches.")
        for i, callable_path in enumerate(callables_to_test):
            self.write(0, "try:")
            self.addLevel(1)
            # Pass a simple argument that should work for most.
            self.write(0, f"{callable_path}(i_{prefix})")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "except: pass")

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Polymorphic Callable Set Scenario >>>"'
        )
        self.emptyLine()

    def _generate_type_version_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        ADVANCED SCENARIO: Attacks the JIT's attribute caching by accessing an
        attribute with the same name across classes where its nature differs.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Type Version Fuzzing Scenario <<<"'
        )

        # 1. Define several classes with the same attribute name ('payload')
        #    but different kinds of attributes.
        self.write(0, "# Define classes with conflicting 'payload' attributes.")
        self.write(0, f"class ShapeA_{prefix}: payload = 123  # Data attribute (int)")
        self.write(0, f"class ShapeB_{prefix}: payload = 'abc' # Data attribute (str)")
        self.write(0, f"class ShapeC_{prefix}:")
        self.write(1, "@property")
        self.write(1, "def payload(self): return 3.14  # Property")
        self.write(0, f"class ShapeD_{prefix}:")
        self.write(1, "def payload(self): return len # Method that returns a builtin")
        self.emptyLine()

        # 2. Create a list of instances of these classes.
        self.write(0, "# Create a list of instances to iterate over.")
        self.write(0, f"shapes = [ShapeA_{prefix}(), ShapeB_{prefix}(), ShapeC_{prefix}(), ShapeD_{prefix}()]")
        self.emptyLine()

        # 3. In a hot loop, polymorphically access the 'payload' attribute.
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i_{prefix} in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        self.write(0, f"obj = shapes[i_{prefix} % len(shapes)]")
        self.write(0, "try:")
        self.addLevel(1)
        # This access forces the JIT to constantly check the object's type
        # and the version of its attribute cache.
        self.write(0, "payload_val = obj.payload")
        # If the payload is a method, call it.
        self.write(0, "if callable(payload_val): payload_val()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception: pass")
        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Type Version Fuzzing Scenario >>>"'
        )
        self.emptyLine()

    def _generate_concurrency_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        ADVANCED SCENARIO: Creates a race condition between a "hammer" thread
        running JIT'd code and an "invalidator" thread modifying its dependencies.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Concurrency (Race Condition) Scenario <<<"'
        )

        # 1. Setup shared state: a target class and a stop flag.
        self.write(0, "# Shared state for the threads.")
        self.write(0, f"class JITTarget_{prefix}: attr = 100")
        self.write(0, f"stop_flag_{prefix} = False")
        self.emptyLine()

        # 2. Define Thread 1: The "JIT Hammer"
        self.write(0, f"def hammer_thread_{prefix}():")
        self.addLevel(1)
        self.write(0, f"target = JITTarget_{prefix}()")
        self.write_print_to_stderr(0, f'"[{prefix}] Hammer thread starting..."')
        self.write(0, f"while not stop_flag_{prefix}:")
        self.addLevel(1)
        self.write(0, "try: _ = target.attr + 1 # This line will be JIT-compiled")
        self.write(0, "except: pass")
        self.restoreLevel(self.parent.base_level - 1)
        self.write_print_to_stderr(0, f'"[{prefix}] Hammer thread stopping."')
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Define Thread 2: The "Invalidator"
        self.write(0, f"def invalidator_thread_{prefix}():")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Invalidator thread starting..."')
        self.write(0, f"while not stop_flag_{prefix}:")
        self.addLevel(1)
        # Repeatedly change the attribute that the hammer thread depends on.
        self.write(0, f"JITTarget_{prefix}.attr = randint(1, 1000)")
        self.write(0, "time.sleep(0.00001) # Sleep briefly to allow hammer to run")
        self.restoreLevel(self.parent.base_level - 1)
        self.write_print_to_stderr(0, f'"[{prefix}] Invalidator thread stopping."')
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 4. Main execution logic to run and manage the threads.
        self.write(0, "# Create and start the competing threads.")
        self.write(0, f"hammer = Thread(target=hammer_thread_{prefix})")
        self.write(0, f"invalidator = Thread(target=invalidator_thread_{prefix})")
        self.write(0, "hammer.start()")
        self.write(0, "invalidator.start()")
        self.write(0, "time.sleep(0.1) # Let the race condition run for a moment")
        self.write(0, f"stop_flag_{prefix} = True # Signal threads to stop")
        self.write(0, "hammer.join()")
        self.write(0, "invalidator.join()")

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished JIT Concurrency Scenario >>>"'
        )
        self.emptyLine()

    def _generate_side_exit_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        ADVANCED SCENARIO: Stresses the JIT's deoptimization mechanism by
        creating a hot loop with a guard that fails unpredictably, forcing
        frequent "side exits" from the optimized trace.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Frequent Side Exit Scenario <<<"'
        )

        target_var = f"side_exit_var_{prefix}"

        # 1. Initialize a variable with a known, stable type.
        self.write(0, f"{target_var} = 0  # Start with a known type (int)")
        self.emptyLine()

        # 2. Start a hot loop.
        if self.options.jit_raise_exceptions:
            self.write(0, "try:")
            self.addLevel(1)
        self.write(0, f"for i_{prefix} in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        if self.options.jit_aggressive_gc:
            self.write(0, f"if i_{prefix} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(0, "collect()")
            self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, f"# Check if we should raise an exception on this iteration.")
            self.write(0, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(0, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)

        # 3. Create an unpredictable guard condition. The JIT will optimize
        #    the 'else' path but must correctly handle when this guard fails.
        self.write(0, "# This guard is designed to fail unpredictably (10% chance).")
        self.write(0, "if random() < 0.1:")
        self.addLevel(1)
        # Inside the failing guard, change the variable's type.
        self.write_print_to_stderr(0, f'"[{prefix}] Side exit triggered! Changing variable type."')
        self.write(0, f"{target_var} = 'corrupted-by-side-exit'")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 4. Perform an operation on the variable. This will be JIT-optimized
        #    assuming the variable is an integer.
        self.write(0, "# This operation is optimized assuming the variable is an int.")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"_ = {target_var} + 1")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except TypeError:")
        self.addLevel(1)
        # 5. CRITICAL: After a side exit causes a TypeError, we must reset
        #    the variable's type so the loop can become hot again.
        self.write(0, f"# Reset the variable's type to allow re-optimization.")
        self.write(0, f"{target_var} = i_{prefix}")
        self.restoreLevel(self.parent.base_level - 1)
        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        if self.options.jit_raise_exceptions:
            self.restoreLevel(self.parent.base_level - 1)  # try
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)  # if
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)  # except
            self.emptyLine()

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Frequent Side Exit Scenario >>>"'
        )
        self.emptyLine()

    def _generate_isinstance_attack_scenario(self, prefix: str, fuzzed_func_name: str, fuzzed_func_obj: Any) -> None:
        """
        ADVANCED SCENARIO (UPGRADED): Attacks the JIT's `isinstance` elimination
        by using a class with a deep, randomized inheritance hierarchy and a
        polymorphic target object.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Upgraded `isinstance` JIT Attack Scenario <<<"'
        )
        loop_iterations = self.options.jit_loop_iterations
        trigger_iteration = loop_iterations // 2
        inheritance_depth = randint(100, 500)  # Randomize the depth

        # 1. SETUP - Define all the components for the attack.
        self.write(0, "# 1. Define the components for the attack.")
        self.write(0, "from abc import ABCMeta")
        self.emptyLine()

        # Define the metaclass that we will later modify.
        meta_name = f"EditableMeta_{prefix}"
        self.write(0, f"class {meta_name}(ABCMeta):")
        self.write(1, "instance_counter = 0")
        self.emptyLine()

        # --- UPGRADE: Deep Inheritance Tree ---
        self.write(0, f"# Create a deep inheritance tree of depth {inheritance_depth}.")
        self.write(0, f"class Base_{prefix}(metaclass={meta_name}): pass")
        self.write(0, f"last_class_{prefix} = Base_{prefix}")
        self.write(0, f"for _ in range({inheritance_depth}):")
        self.addLevel(1)
        # We create a uniquely named class each time to avoid name clashes.
        self.write(0, f"class ClassStepDeeper(last_class_{prefix}): pass")
        self.write(0, f"last_class_{prefix} = ClassStepDeeper")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # The final class inherits from the end of our long chain.
        class_name = f"EditableClass_{prefix}"
        self.write(0, f"class {class_name}(last_class_{prefix}): pass")
        self.emptyLine()

        # --- UPGRADE: Injected Fuzzed Function Call ---
        # Define the __instancecheck__ method that we will inject later.
        # It now calls a real fuzzed function.
        check_func_name = f"new__instancecheck_{prefix}"
        self.write(0, f"def {check_func_name}(self, other):")
        self.addLevel(1)
        self.write_print_to_stderr(0, '"  [+] Patched __instancecheck__ called!"')
        self.write(0, "try:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f"'    -> Calling fuzzed function: {fuzzed_func_name}'")
        # Call the real fuzzed function!
        self.write(0, f"{self.module_name}.{fuzzed_func_name}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except: pass")
        self.write(0, f"return True # Always return True after being patched")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # Define the Deletable class with the __del__ payload.
        deletable_name = f"Deletable_{prefix}"
        # ... (The Deletable class definition remains the same as before) ...
        self.write(0, f"class {deletable_name}:")
        self.addLevel(1)
        self.write(0, "def __del__(self):")
        self.addLevel(1)
        self.write_print_to_stderr(0, '"  [+] __del__ triggered! Patching __instancecheck__ onto metaclass."')
        self.write(0, f"{meta_name}.__instancecheck__ = {check_func_name}")
        self.restoreLevel(self.parent.base_level - 2)
        self.emptyLine()

        # Arm the trigger.
        self.write(0, f"trigger_obj = {deletable_name}()")
        self.emptyLine()

        # --- UPGRADE: Polymorphic Target Object ---
        self.write(0, "# Create a list of diverse objects to check against.")
        self.write(0, f"fuzzed_obj_instance = {self.module_name}.{fuzzed_func_name}")
        self.write(0, f"objects_to_check = [1, 'a_string', 3.14, fuzzed_obj_instance]")
        self.emptyLine()

        # 2. HOT LOOP - The Bait, Trigger, and Trap
        self.write(0, "# 2. Run the hot loop to bait, trigger, and trap the JIT.")
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)

        # Pick a different object to check on each iteration.
        self.write(0, f"target_obj = objects_to_check[i_{prefix} % len(objects_to_check)]")

        # The Bait: This check now has a polymorphic target.
        self.write(0, f"is_instance_result = isinstance(target_obj, {class_name})")

        # The Trigger
        self.write(0, f"if i_{prefix} == {trigger_iteration}:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Deleting trigger object..."')
        self.write(0, f"del trigger_obj")
        self.write(0, "collect()")
        self.restoreLevel(self.parent.base_level - 1)

        # The Trap (logging)
        self.write(0, f"if i_{prefix} % 100 == 0:")
        self.addLevel(1)
        self.write_print_to_stderr(0,
                                   f'f"[{prefix}][Iter {{ i_{prefix} }} ] `isinstance({{target_obj!r}}, {class_name})` is now: {{is_instance_result}}"')
        self.restoreLevel(self.parent.base_level - 1)

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Upgraded `isinstance` JIT Attack Scenario >>>"'
        )
        self.emptyLine()

    def _generate_math_logic_body(self, prefix: str, const_a_str: str, const_b_str: str) -> None:
        """
        Generates the body of a function containing a hot loop filled with
        JIT-friendly math and logic patterns. It uses pre-generated constant values.
        """
        # 1. Initialize variables for the block to use, using the passed-in constants.
        self.write(1, f"var_int_a = {const_a_str}")
        self.write(1, f"var_int_b = {const_b_str}")
        self.write(1, "total = 0")
        self.emptyLine()

        # 2. Create the hot loop.
        loop_iterations = self.options.jit_loop_iterations // 10
        loop_var = f"i_{prefix}"
        self.write(1, f"for {loop_var} in range({loop_iterations}):")
        self.addLevel(1)

        # 3. Weave in the JIT-friendly patterns inside the loop.
        self.write(1, f"if {loop_var} > var_int_b:")
        self.addLevel(1)
        self.write(1, f"temp_val = (var_int_a + {loop_var}) % 1000")
        self.write(1, f"total += temp_val")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "else:")
        self.addLevel(1)
        self.write(1, "total -= 1")
        self.restoreLevel(self.parent.base_level - 1)

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        self.write(1, "return total")

    def _generate_jit_pattern_block_with_check(self, prefix: str, fuzzed_func_name: str,
                                                      fuzzed_func_obj: Any) -> None:
        """
        CORRECTNESS SCENARIO 1: Generates a 'Twin Execution' test for a
        block of JIT-friendly patterns to check for silent correctness bugs.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Correctness Scenario (Math Patterns) <<<"'
        )

        const_a_str = self.arg_generator.genInt()[0]
        const_b_str = self.arg_generator.genSmallUint()[0]

        jit_func_name = f"jit_target_math_{prefix}"
        control_func_name = f"control_math_{prefix}"

        # 1. Define the JIT Target function.
        self.write(0, "# This function will be run on a 'hot' path to engage the JIT.")
        self.write(0, f"def {jit_func_name}():")
        self.addLevel(1)
        # Pass the pre-generated constants to the body generator.
        self._generate_math_logic_body(prefix, const_a_str, const_b_str)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Define the Control function with identical logic.
        self.write(0, "# This function has identical logic but will be run only once.")
        self.write(0, f"def {control_func_name}():")
        self.addLevel(1)
        # Pass the SAME pre-generated constants to this body generator as well.
        self._generate_math_logic_body(prefix, const_a_str, const_b_str)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        self.write(0, f"# 1. Warm up the JIT target function so it gets compiled.")
        self.write(0, f"jit_harness({jit_func_name}, {self.options.jit_loop_iterations})")
        self.emptyLine()

        self.write(0, f"# 2. Get the final result from the JIT-compiled version and the control version.")
        self.write(0, f"jit_result = {jit_func_name}()")
        self.write(0, f"control_result = no_jit_harness({control_func_name})")
        self.emptyLine()
        self.write(0,
                   f'assert jit_result == control_result, f"JIT CORRECTNESS BUG! JIT Result: {{jit_result}}, Control Result: {{control_result}}"')

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario (Math Patterns) Passed >>>"'
        )
        self.emptyLine()

    def _generate_evil_math_logic_body(self, prefix: str, constants: dict) -> None:
        """
        Generates the body of a function with complex, "evil" JIT-friendly
        patterns, using boundary values from the INTERESTING list.
        """
        # 1. Initialize variables using the pre-generated constants.
        self.write(1, f"# Initialize variables with potentially problematic boundary values.")
        self.write(1, f"var_a = {constants['val_a']}")
        self.write(1, f"var_b = {constants['val_b']}")
        self.write(1, f"var_c = {constants['val_c']}")
        self.write(1, f"str_d = {constants['str_d']}")
        self.write(1, "total = 0.0 # Use a float accumulator for broader compatibility")
        self.emptyLine()

        # 2. Create the hot loop.
        loop_iterations = self.options.jit_loop_iterations // 20
        loop_var = f"i_{prefix}"
        self.write(1, f"for {loop_var} in range(1, {loop_iterations}): # Start from 1 to avoid division by zero")
        self.addLevel(1)

        # 3. Weave in more complex and "evil" patterns inside the loop.
        self.write(1, "try:")
        self.addLevel(1)
        # Mix float, int, and boundary values. Use operators the JIT optimizes.
        self.write(1, f"temp_val = (var_a + var_b) / {loop_var}")
        self.write(1, f"temp_val_2 = var_c * {loop_var}")
        # Perform a comparison that will change throughout the loop.
        self.write(1, f"if temp_val > temp_val_2:")
        self.addLevel(1)
        # Use string operations as well.
        self.write(1, f"total += len(str_d) + len(str(temp_val))")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "else:")
        self.addLevel(1)
        self.write(1, f"total -= temp_val_2")
        self.restoreLevel(self.parent.base_level - 1)
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except (ValueError, TypeError, ZeroDivisionError, OverflowError):")
        self.addLevel(1)
        # It's expected that operations on boundary values might raise exceptions.
        # We just need to handle them so the loop can continue.
        self.write(1, "total -= 1")
        self.restoreLevel(self.parent.base_level - 1)

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop
        self.write(1, "return total")

    def _generate_evil_jit_pattern_block_with_check(self, prefix: str, fuzzed_func_name: str,
                                                      fuzzed_func_obj: Any) -> None:
        """
        CORRECTNESS SCENARIO (EVIL): Generates a 'Twin Execution' test using
        complex operations and boundary values to stress the JIT's correctness.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting EVIL JIT Correctness Scenario (Boundary Values) <<<"'
        )

        # 1. Generate the problematic constants ONCE.
        #    We pull directly from the `INTERESTING` list for maximum effect.
        constants = {
            'val_a': self.arg_generator.genInterestingValues()[0],
            'val_b': self.arg_generator.genInterestingValues()[0],
            'val_c': self.arg_generator.genInterestingValues()[0],
            'str_d': self.arg_generator.genString()[0],
        }

        jit_func_name = f"jit_target_evil_{prefix}"
        control_func_name = f"control_evil_{prefix}"

        # 2. Define the JIT Target function.
        self.write(0, f"def {jit_func_name}():")
        self.addLevel(1)
        self._generate_evil_math_logic_body(prefix, constants)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Define the Control function with identical logic.
        self.write(0, f"def {control_func_name}():")
        self.addLevel(1)
        self._generate_evil_math_logic_body(prefix, constants)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 4. Generate the execution and assertion code.
        self.write(0, "# Run both versions and assert their results are identical.")
        self.write(0, f"jit_result, control_result = None, None")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"jit_harness({jit_func_name}, {self.options.jit_loop_iterations})")
        self.write(0, f"jit_result = {jit_func_name}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] JIT version raised unexpected exception: {{e}}"')
        self.restoreLevel(self.parent.base_level - 1)

        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"control_result = no_jit_harness({control_func_name})")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Control version raised unexpected exception: {{e}}"')
        self.restoreLevel(self.parent.base_level - 1)

        # We can only assert if both completed without error.
        # A discrepancy in which one raises an error is itself a bug.
        self.write(0,
                   f'are_nan = math.isnan(jit_result) and math.isnan(control_result)')
        self.write(0,
                   f'assert jit_result == control_result or are_nan, f"EVIL JIT CORRECTNESS DEFECT! JIT Result: {{jit_result}}, Control Result: {{control_result}}"')

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< EVIL JIT Correctness Scenario Passed >>>"'
        )
        self.emptyLine()

    def _generate_deleter_logic_body(self, prefix: str) -> None:
        """
        Generates the body of a function that performs the __del__ side effect
        attack. It returns the final state of the targeted variables for correctness checking.
        """
        # Define unique names for all our variables using the prefix.
        target_var = f"target_{prefix}"
        fm_target_var = f"fm_{target_var}"
        dummy_class_name = f"Dummy_{prefix}"
        dummy_instance_name = f"dummy_instance_{prefix}"
        fm_dummy_class_attr = f"fm_{dummy_instance_name}_a"
        fm_dummy_instance_attr = f"fm_{dummy_instance_name}_b"
        loop_iterations = self.options.jit_loop_iterations
        trigger_iteration = loop_iterations - 2  # Trigger on the penultimate iteration

        # 1. SETUP - This logic is now inside the function body.
        self.write(1, f"# A. Create a local variable and its FrameModifier")
        self.write(1, f"{target_var} = 100")
        self.write(1, f"{fm_target_var} = FrameModifier('{target_var}', 'local-string')")
        self.emptyLine()

        self.write(1, f"# B. Create a class with instance/class attributes and their FrameModifiers")
        self.write(1, f"class {dummy_class_name}:")
        self.addLevel(1)
        self.write(1, "a = 200  # Class attribute")
        self.write(1, "def __init__(self): self.b = 300  # Instance attribute")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, f"{dummy_instance_name} = {dummy_class_name}()")
        self.write(1, f"{fm_dummy_class_attr} = FrameModifier('{dummy_instance_name}.a', 'class-attr-string')")
        self.write(1, f"{fm_dummy_instance_attr} = FrameModifier('{dummy_instance_name}.b', 'instance-attr-string')")
        self.emptyLine()

        # 2. HOT LOOP
        self.write(1, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)
        self.write(1, "try:")
        self.addLevel(1)
        # Warm-up phase
        self.write(1, f"x = {target_var} + i_{prefix}")
        self.write(1, f"y = {dummy_instance_name}.a + i_{prefix}")
        self.write(1, f"z = {dummy_instance_name}.b + i_{prefix}")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except TypeError: pass")

        # Trigger phase
        self.write(1, f"if i_{prefix} == {trigger_iteration}:")
        self.addLevel(1)
        self.write(1, f"del {fm_target_var}")
        self.write(1, f"del {fm_dummy_class_attr}")
        self.write(1, f"del {fm_dummy_instance_attr}")
        self.write(1, "collect()")
        self.restoreLevel(self.parent.base_level - 1)
        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop

        # 3. RETURN FINAL STATE for comparison.
        self.write(1, f"# Return the final state of all targeted variables.")
        self.write(1, f"return ({target_var}, {dummy_instance_name}.a, {dummy_instance_name}.b)")

    def _generate_deleter_scenario_with_check(self, prefix: str, fuzzed_func_name: str,
                                                      fuzzed_func_obj: Any) -> None:
        """
        CORRECTNESS SCENARIO 2: Generates a 'Twin Execution' test for the
        __del__ side effect attack to check for silent state corruption.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Correctness Scenario (__del__ Attack) <<<"'
        )

        jit_func_name = f"jit_target_deleter_{prefix}"
        control_func_name = f"control_deleter_{prefix}"

        # 1. Define the JIT Target function.
        self.write(0, f"def {jit_func_name}():")
        self.addLevel(1)
        self._generate_deleter_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Define the Control function with identical logic.
        self.write(0, f"def {control_func_name}():")
        self.addLevel(1)
        self._generate_deleter_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Generate the execution and assertion code.
        self.write(0, "# Run both versions and assert their final states are identical.")
        self.write(0, f"jit_final_state = {jit_func_name}()")
        self.write(0, f"control_final_state = no_jit_harness({control_func_name})")

        # Use our NaN-aware comparison for the assertion.
        self.write(0,
                   f'assert compare_results(jit_final_state, control_final_state), f"JIT STATE MISMATCH after __del__ attack! JIT: {{jit_final_state}}, Control: {{control_final_state}}"')

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario (__del__ Attack) Passed >>>"'
        )
        self.emptyLine()

    def _generate_deep_calls_logic_body(self, prefix: str, func_name_prefix: str) -> str:
        """
        Generates the definitions for a deep chain of functions, where each
        function in the chain performs complex work.

        Returns:
            The name of the top-level function to be called.
        """
        depth = 15
        self.write(1, f"# Define a deep chain of {depth} functions.")

        # 1. Define the base case (the final function in the chain).
        self.write(1, f"def {func_name_prefix}_0(p):")
        self.addLevel(1)
        self.write(1, "x = len('base_case') + p")
        self.write(1, "y = x % 5")
        self.write(1, "return x - y")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Generate the intermediate functions in the chain.
        for i in range(1, depth):
            self.write(1, f"def {func_name_prefix}_{i}(p):")
            self.addLevel(1)
            self.write(1, f"local_val = p * {i}")
            self.write(1, "s = 'abcdef'")
            self.write(1, f"if local_val > 10 and (s[{i} % len(s)]):")
            self.addLevel(1)
            # Recursively call the next function in the chain.
            self.write(1, f"local_val += {func_name_prefix}_{i - 1}(p)")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(1, "return local_val")
            self.restoreLevel(self.parent.base_level - 1)
            self.emptyLine()

        return f"{func_name_prefix}_{depth - 1}"

    def _generate_deep_calls_scenario_with_check(self, prefix: str, fuzzed_func_name: str,
                                                      fuzzed_func_obj: Any) -> None:
        """
        CORRECTNESS SCENARIO 3: Generates a 'Twin Execution' test for the
        'Mixed Deep Calls' scenario to verify its correctness.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Correctness Scenario (Deep Calls) <<<"'
        )

        jit_func_prefix = f"jit_f_{prefix}"
        control_func_prefix = f"control_f_{prefix}"

        # 1. Define the JIT Target function chain.
        self.write(0, "# This function chain will be run on a 'hot' path.")
        self.write(0, f"def jit_target_harness_{prefix}():")
        self.addLevel(1)
        jit_top_level_func = self._generate_deep_calls_logic_body(prefix, jit_func_prefix)
        # Call the top-level function inside a loop.
        self.write(1, f"total = 0")
        self.write(1, f"for i in range(10): total += {jit_top_level_func}(i)")
        self.write(1, f"return total")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Define the Control function chain with identical logic.
        self.write(0, "# This function chain has identical logic but will be run only once.")
        self.write(0, f"def control_harness_{prefix}():")
        self.addLevel(1)
        control_top_level_func = self._generate_deep_calls_logic_body(prefix, control_func_prefix)
        self.write(1, f"total = 0")
        self.write(1, f"for i in range(10): total += {control_top_level_func}(i)")
        self.write(1, f"return total")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Generate the execution and assertion code.
        self.write(0, f"# 1. Warm up the JIT target function so it gets compiled.")
        self.write(0, f"jit_harness(jit_target_harness_{prefix}, {self.options.jit_loop_iterations})")
        self.emptyLine()

        self.write(0, f"# 2. Get the final result from the JIT-compiled version and the control version.")
        self.write(0, f"jit_result = jit_target_harness_{prefix}()")
        self.write(0, f"control_result = no_jit_harness(control_harness_{prefix})")

        self.write(0,
                   f'assert compare_results(jit_result, control_result), f"JIT CORRECTNESS BUG (Deep Calls)! JIT: {{jit_result}}, Control: {{control_result}}"')

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario (Deep Calls) Passed >>>"'
        )
        self.emptyLine()

    def _generate_evil_deep_calls_logic_body(self, prefix: str, func_name_prefix: str,
                                             constants: list[str], operators: list[str],
                                             exception_level: int, fuzzed_func_name: str) -> str:
        """
        Generates the body for the 'evil' deep calls scenario, using boundary
        values, a suite of operators, and a potential exception trigger.
        """
        depth = 15
        self.write(1, "# This function chain uses boundary values and mixed operators.")

        # 1. Define the base case. It performs a final operation and
        #    also calls a real fuzzed function.
        self.write(1, f"def {func_name_prefix}_0(p_tuple):")
        self.addLevel(1)
        self.write(1, "res = list(p_tuple)")
        self.write(1, "try:")
        self.addLevel(1)
        self.write(1, f"op = {operators[0]}")
        self.write(1, f"const = {constants[0]}")
        self.write(1, "res[0] = op(res[0], const)")
        self.write(1, f"{self.module_name}.{fuzzed_func_name}(res[0])")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except (TypeError, ValueError, ZeroDivisionError, OverflowError): pass")
        self.write(1, "return tuple(res)")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Generate the intermediate functions.
        for i in range(1, depth):
            self.write(1, f"def {func_name_prefix}_{i}(p_tuple):")
            self.addLevel(1)
            # Potentially raise our probe exception.
            if i == exception_level:
                self.write(1, "if random() < 0.001:")
                self.addLevel(1)
                self.write_print_to_stderr(1, f'"[{prefix}] EVIL DEEP CALL: Raising ValueError probe!"')
                self.write(1, "raise ValueError(('evil_deep_call_probe',))")
                self.restoreLevel(self.parent.base_level - 1)

            self.write(1, "res = list(p_tuple)")
            self.write(1, "try:")
            self.addLevel(1)
            # Use a different operator and constant at each level of the chain.
            self.write(1, f"op = {operators[i % len(operators)]}")
            self.write(1, f"const = {constants[i % len(constants)]}")
            self.write(1, "res[1] = op(res[1], const)")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(1, "except (TypeError, ValueError, ZeroDivisionError, OverflowError): pass")
            # Call the next function in the chain.
            self.write(1, f"return {func_name_prefix}_{i - 1}(tuple(res))")
            self.restoreLevel(self.parent.base_level - 1)
            self.emptyLine()

        return f"{func_name_prefix}_{depth - 1}"

    def _generate_evil_deep_calls_scenario_with_check(self, prefix: str, fuzzed_func_name: str,
                                                      fuzzed_func_obj: Any) -> None:
        """
        CORRECTNESS SCENARIO (EVIL DEEP CALLS): Generates a 'Twin Execution'
        test for a deep call chain using boundary values and mixed operators.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting EVIL JIT Correctness Scenario (Deep Calls) <<<"'
        )
        self.write(0, "import operator")

        # 1. Setup for the scenario: Choose operators and boundary values ONCE.
        operator_suite = ['operator.add', 'operator.sub', 'operator.mul', 'operator.truediv']
        constants = [self.arg_generator.genInterestingValues()[0] for _ in range(4)]
        exception_level = randint(5, 12)  # Choose a random level to hide the exception.

        jit_func_prefix = f"jit_evil_f_{prefix}"
        control_func_prefix = f"control_evil_f_{prefix}"

        # 2. Define the JIT Target function chain.
        self.write(0, f"def jit_target_harness_{prefix}():")
        self.addLevel(1)
        jit_top_level_func = self._generate_evil_deep_calls_logic_body(
            prefix, jit_func_prefix, constants, operator_suite, exception_level, fuzzed_func_name
        )
        self.write(1, f"return {jit_top_level_func}(({constants[0]}, {constants[1]}))")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Define the Control function chain.
        self.write(0, f"def control_harness_{prefix}():")
        self.addLevel(1)
        control_top_level_func = self._generate_evil_deep_calls_logic_body(
            prefix, control_func_prefix, constants, operator_suite, exception_level, fuzzed_func_name
        )
        self.write(1, f"return {control_top_level_func}(({constants[0]}, {constants[1]}))")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 4. Generate the execution and assertion code.
        self.write(0, "# Run both versions and assert their final states are identical.")
        self.write(0, f"jit_result, control_result = None, None")
        self.write(0, f"jit_exc, control_exc = None, None")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"# 1. Warm up the JIT target function so it gets compiled.")
        self.write(0, f"jit_harness(jit_target_harness_{prefix}, {self.options.jit_loop_iterations})")
        self.write(0, f"jit_result = jit_target_harness_{prefix}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e: jit_exc = e")

        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"control_result = no_jit_harness(control_harness_{prefix})")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e: control_exc = e")

        # Assertions
        self.write(0,
                   "if not isinstance(jit_exc, ValueError) and not isinstance(control_exc, ValueError):")
        self.write(1,
                   "assert type(jit_exc) == type(control_exc) or None in (jit_exc, control_exc), f'Exception type mismatch! JIT: {type(jit_exc)}, Control: {type(control_exc)}'")
        self.write(0,
                   "if isinstance(jit_exc, ValueError) and isinstance(control_exc, ValueError): assert jit_exc.args == control_exc.args, 'Probe exception payload mismatch!'")
        self.write(0, "if not compare_results(jit_result, control_result):")
        self.addLevel(1)
        # Try to represent the results for the error message, but handle the ValueError.
        self.write(0, "try: jit_repr = repr(jit_result)")
        self.write(0, "except ValueError: jit_repr = '<int too large to display>'")
        self.write(0, "try: control_repr = repr(control_result)")
        self.write(0, "except ValueError: control_repr = '<int too large to display>'")

        # Raise the AssertionError with the safe representations.
        self.write(0,
                   'raise AssertionError(f"EVIL DEEP CALLS BUG! JIT: {jit_repr}, Control: {control_repr}")'
                   )
        self.restoreLevel(self.parent.base_level - 1)

        # Add an else case for clarity in the generated code
        self.write(0, "else:")
        self.addLevel(1)
        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< EVIL JIT Correctness Scenario (Deep Calls) Passed >>>"'
        )
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

    def _generate_inplace_add_attack_scenario_with_check(self, prefix: str, fuzzed_func_name: str,
                                                         fuzzed_func_obj: Any) -> None:
        """
        GREY-BOX CORRECTNESS SCENARIO 1: Attacks the guard on the
        _BINARY_OP_INPLACE_ADD_UNICODE specialization.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Correctness Scenario (In-Place Add Attack) <<<"'
        )

        jit_func_name = f"jit_target_inplace_{prefix}"
        control_func_name = f"control_inplace_{prefix}"

        # 1. Define the JIT Target function.
        self.write(0, f"def {jit_func_name}():")
        self.addLevel(1)
        self._generate_inplace_add_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Define the Control function.
        self.write(0, f"def {control_func_name}():")
        self.addLevel(1)
        self._generate_inplace_add_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Generate the execution and assertion code.
        self.write(0, f"# 1. Warm up the JIT target function so it gets compiled.")
        self.write(0, f"jit_harness({jit_func_name}, {self.options.jit_loop_iterations})")
        self.emptyLine()

        self.write(0, f"# 2. Get the final result from the JIT-compiled version and the control version.")
        self.write(0, f"jit_result = {jit_func_name}()")
        self.write(0, f"control_result = no_jit_harness({control_func_name})")
        self.emptyLine()

        self.write(0,
                   f'assert compare_results(jit_result, control_result), f"JIT CORRECTNESS BUG (In-Place Add)! JIT: {{jit_result}}, Control: {{control_result}}"')

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario (In-Place Add Attack) Passed >>>"'
        )
        self.emptyLine()

    def _generate_inplace_add_logic_body(self, prefix: str) -> None:
        """
        Generates the body of a function that performs the in-place add attack.
        """
        target_var = f"s_{prefix}"
        loop_iterations = self.options.jit_loop_iterations // 2
        trigger_iteration = loop_iterations - 2

        # 1. Initialize the target string variable and the FrameModifier payload.
        self.addLevel(1)
        self.write(0, f"{target_var} = 'start_'")
        self.write(0, f"fm_payload = {target_var} + 'a' # Create a new, different string object")
        fm_vars = self._define_frame_modifier_instances(
            prefix, {target_var: "fm_payload"}  # Pass the variable name containing the payload
        )
        self.emptyLine()

        # 2. Hot loop to warm up the s += operation.
        self.write(0, f"for i in range({loop_iterations}):")
        self.addLevel(1)

        # 3. On the penultimate iteration, trigger the __del__ to corrupt 's'.
        self._generate_del_trigger('i', loop_iterations, fm_vars)

        # 4. Perform the in-place add.
        # Before the trigger, this is normal. After, the DEOPT_IF guard should fail.
        self.write(0, f"try: {target_var} += str(i)")
        self.write(0, "except Exception: pass")

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop

        # 5. Return the final state of the string for comparison.
        self.write(0, f"return {target_var}")
        self.restoreLevel(self.parent.base_level - 1)

    def _generate_global_invalidation_logic_body(self, prefix: str) -> None:
        """
        Generates the body of a function that performs the global dictionary
        invalidation attack. Returns the accumulated result for checking.
        """
        global_func_name = f"my_global_func_{prefix}"
        loop_iterations = self.options.jit_loop_iterations // 10

        # 1. Define a simple global function that will be our JIT target.
        self.write(1, f"# Define a global function to be targeted.")
        self.write(1, f"def {global_func_name}(): return 1")
        self.emptyLine()

        # 2. Phase 1 (Warm-up): Run a hot loop calling the global function.
        #    This will cause the JIT to specialize the LOAD_GLOBAL and cache the dk_version.
        self.write(1, f"accumulator = 0")
        self.write(1, f"for _ in range({loop_iterations}):")
        self.addLevel(1)
        self.write(1, f"accumulator += {global_func_name}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Phase 2 (Invalidate): Modify the globals() dictionary.
        #    This action changes the dk_version, which should trigger the guard.
        self.write(1, "# Invalidate the dictionary key version by adding a new global.")
        self.write(1, f"globals()['new_global_{prefix}'] = 123")
        self.emptyLine()

        # 4. Phase 3 (Re-execute): Call the function one more time.
        #    This call will hit the DEOPT_IF guard.
        self.write(1, f"accumulator += {global_func_name}()")
        self.emptyLine()

        # 5. Return the final accumulated value for correctness checking.
        self.write(1, "return accumulator")

    def _generate_global_invalidation_scenario_with_check(self, prefix: str, fuzzed_func_name: str,
                                                          fuzzed_func_obj: Any) -> None:
        """
        GREY-BOX CORRECTNESS SCENARIO 2: Attacks the dk_version guard
        for LOAD_GLOBAL by invalidating the globals() dictionary.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Correctness Scenario (Global Invalidation) <<<"'
        )

        jit_func_name = f"jit_target_global_{prefix}"
        control_func_name = f"control_global_{prefix}"

        # 1. Define the JIT Target function.
        self.write(0, f"def {jit_func_name}():")
        self.addLevel(1)
        self._generate_global_invalidation_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Define the Control function.
        self.write(0, f"def {control_func_name}():")
        self.addLevel(1)
        self._generate_global_invalidation_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Generate the execution and assertion code.
        self.write(0, f"# 1. Warm up the JIT target function so it gets compiled.")
        self.write(0, f"jit_harness({jit_func_name}, {self.options.jit_loop_iterations})")
        self.emptyLine()

        self.write(0, f"# 2. Get the final result from the JIT-compiled version and the control version.")
        self.write(0, f"jit_result = {jit_func_name}()")
        self.write(0, f"control_result = no_jit_harness({control_func_name})")
        self.emptyLine()

        self.write(0,
                   f'assert compare_results(jit_result, control_result), f"JIT CORRECTNESS BUG (Global Invalidation)! JIT: {{jit_result}}, Control: {{control_result}}"')

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario (Global Invalidation) Passed >>>"'
        )
        self.emptyLine()

    def _generate_managed_dict_logic_body(self, prefix: str) -> None:
        """
        Generates the body of a function that attacks the managed dictionary guard.
        Returns the final list of objects for state comparison.
        """
        loop_iterations = self.options.jit_loop_iterations

        # 1. Define two classes: one with a __dict__, one with __slots__.
        self.write(1, f"# Define a standard class and a class with __slots__.")
        self.write(1, f"class ClassWithDict_{prefix}: pass")
        self.write(1, f"class ClassWithSlots_{prefix}:")
        self.addLevel(1)
        self.write(1, "__slots__ = ['x']")  # This class has no __dict__
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Create a list of instances to use polymorphically.
        self.write(1, f"objects_to_set = [ClassWithDict_{prefix}(), ClassWithSlots_{prefix}()]")
        self.emptyLine()

        # 3. Hot loop to warm up the STORE_ATTR operation.
        self.write(1, f"for i in range({loop_iterations}):")
        self.addLevel(1)

        # 4. Polymorphically select an object and set an attribute.
        #    This will alternate between the fast path (dict) and the
        #    slow path (slots), forcing the DEOPT_IF guard to be hit frequently.
        self.write(1, "obj = objects_to_set[i % 2]")
        self.write(1, "try:")
        self.addLevel(1)
        self.write(1, "obj.x = i")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except AttributeError:")
        self.addLevel(1)
        # We expect this for the slotted class if 'x' isn't in __slots__,
        # which is part of the test.
        self.write(1, "pass")
        self.restoreLevel(self.parent.base_level - 1)

        self.restoreLevel(self.parent.base_level - 1)  # Exit for loop

        # 5. Return the final list of objects to check their state.
        self.write(1, "return objects_to_set")

    def _generate_managed_dict_attack_scenario_with_check(self, prefix: str, fuzzed_func_name: str,
                                                          fuzzed_func_obj: object) -> None:
        """
        GREY-BOX CORRECTNESS SCENARIO 3: Attacks the managed dictionary
        guard for STORE_ATTR.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Correctness Scenario (Managed Dict Attack) <<<"'
        )

        jit_func_name = f"jit_target_managed_dict_{prefix}"
        control_func_name = f"control_managed_dict_{prefix}"

        # 1. Define the JIT Target function.
        self.write(0, f"def {jit_func_name}():")
        self.addLevel(1)
        self._generate_managed_dict_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 2. Define the Control function.
        self.write(0, f"def {control_func_name}():")
        self.addLevel(1)
        self._generate_managed_dict_logic_body(prefix)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Generate the execution and comparison code.
        self.write(0, f"# 1. Warm up the JIT target function so it gets compiled.")
        self.write(0, f"jit_harness({jit_func_name}, {self.options.jit_loop_iterations})")
        self.emptyLine()

        self.write(0, f"# 2. Get the final result from the JIT-compiled version and the control version.")
        self.write(0, f"jit_result = {jit_func_name}()")
        self.write(0, f"control_result = no_jit_harness({control_func_name})")
        self.emptyLine()

        # Compare the final 'x' attribute of the objects from both runs.
        self.write(0, "jit_dict_obj_x = getattr(jit_result[0], 'x', 'NOT_SET')")
        self.write(0, "control_dict_obj_x = getattr(control_result[0], 'x', 'NOT_SET')")
        self.write(0, "jit_slots_obj_x = getattr(jit_result[1], 'x', 'NOT_SET')")
        self.write(0, "control_slots_obj_x = getattr(control_result[1], 'x', 'NOT_SET')")
        self.emptyLine()

        self.write(0,
                   f'assert jit_dict_obj_x == control_dict_obj_x, f"JIT MISMATCH (Dict Object)! JIT: {{jit_dict_obj_x}}, Control: {{control_dict_obj_x}}"'
                   )
        self.write(0,
                   f'assert jit_slots_obj_x == control_slots_obj_x, f"JIT MISMATCH (Slots Object)! JIT: {{jit_slots_obj_x}}, Control: {{control_slots_obj_x}}"'
                   )

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario (Managed Dict Attack) Passed >>>"'
        )
        self.emptyLine()

    def _generate_decref_escapes_scenario(self, prefix: str) -> None:
        """
        RE-DISCOVERY SCENARIO: A highly targeted attack designed specifically
        to reproduce the crash from GH-124483 (test_decref_escapes).
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting `test_decref_escapes` Re-discovery Scenario <<<"'
        )

        loop_var = f"i_{prefix}"
        loop_iterations = 500  # Use a smaller, specific number of iterations
        trigger_iteration = loop_iterations - 2  # The value to check for in __del__

        # 1. Define a minimal FrameModifier with NO __init__
        fm_class_name = f"FrameModifier_{prefix}"
        self.write(0, f"class {fm_class_name}:")
        self.addLevel(1)
        self.write(0, "def __del__(self):")
        self.addLevel(1)
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, "frame = sys._getframe(1)")
        # 2. Hardcode the check inside __del__ as you discovered
        self.write(0, f"if frame.f_locals.get('{loop_var}') == {trigger_iteration}:")
        self.addLevel(1)
        self.write_print_to_stderr(1, f'"  [Side Effect] Triggered! Modifying `{loop_var}` to None"')
        self.write(1, f"frame.f_locals['{loop_var}'] = None")
        self.restoreLevel(self.parent.base_level - 1)
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception: pass")
        self.restoreLevel(self.parent.base_level - 2)
        self.emptyLine()

        # 3. Define the main function harness. All logic is INSIDE this function.
        harness_func_name = f"harness_{prefix}"
        self.write(0, f"def {harness_func_name}():")
        self.addLevel(1)

        # 4. The hot loop
        self.write(1, f"try:")
        self.addLevel(1)
        self.write(1, f"for {loop_var} in range({loop_iterations}):")
        self.addLevel(1)

        # 5. Instantiate and destroy the FrameModifier on EACH iteration.
        self.write(1, f"{fm_class_name}()")

        # 6. Perform the operation that gets optimized.
        self.write(1, f"{loop_var} + {loop_var}")

        self.restoreLevel(self.parent.base_level - 1)
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except Exception: pass # Catch potential TypeErrors")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 7. Call the harness function.
        self.write(0, f"# Execute the test harness.")
        self.write(0, f"{harness_func_name}()")
        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished `test_decref_escapes` Re-discovery Scenario >>>"'
        )
        self.emptyLine()

    def _generate_variational_scenario(self, prefix: str, pattern_names: str) -> None:
        """
        Takes a bug pattern template and generates test cases.
        Can operate in three modes:
        1. Systematic Values: Iterates through all known "interesting" values.
        2. Type-Aware: Iterates through a set of contrasting types.
        3. Random (default): Applies a single set of random mutations.
        """
        if pattern_names == "ALL":
            pattern_names = ",".join(BUG_PATTERNS.keys())
        pattern_name = choice(pattern_names.split(","))
        pattern = BUG_PATTERNS.get(pattern_name)
        if not pattern:
            self.write_print_to_stderr(0, f'"[!] Unknown bug pattern name: {pattern_name}"')
            return

        has_payload_placeholder = (
                '{corruption_payload}' in pattern['setup_code'] or
                '{corruption_payload}' in pattern['body_code']
        )

        if self.options.jit_fuzz_ast_mutation:
            # AST MUTATION MODE
            self.write_print_to_stderr(0,
                                       f'"[{prefix}] >>> AST MUTATION Fuzzing Pattern: {pattern_name} <<<"')

            body_code_template = dedent(pattern['body_code'])

            # Check if this is a correctness pattern
            is_correctness_pattern = (
                    "def jit_target" in body_code_template and
                    "def control_" in body_code_template
            )

            if is_correctness_pattern:
                # --- PAIRED MUTATION FOR CORRECTNESS ---
                jit_body = self._get_function_body(body_code_template, "jit_target")
                control_body = self._get_function_body(body_code_template, "control_")

                # Find the assertion line to append after mutation
                assertion_line = [
                    line for line in body_code_template.splitlines()
                    if line.strip().startswith("assert")
                ]

                if jit_body and control_body and assertion_line:
                    mutation_seed = randint(0, 2 ** 32 - 1)

                    mutated_jit_body = self.ast_mutator.mutate(jit_body, seed=mutation_seed)
                    mutated_control_body = self.ast_mutator.mutate(control_body, seed=mutation_seed)

                    # Reassemble the final code
                    final_body_code = (
                        f"{mutated_jit_body}\n\n"
                        f"{mutated_control_body}\n\n"
                        f"# Harness and assertion logic from original pattern...\n"
                        f"{assertion_line[0]}"  # Simplified re-assembly for clarity
                    )
                    # Note: A full implementation would need to robustly find and
                    # preserve the harness calls between the function defs and the assert.
                    # For now, we demonstrate the core seeded mutation logic.

                    # Write the pattern setup and the reassembled, mutated body
                    # (Setup is not mutated for correctness patterns to preserve harnesses)
                    setup_code = dedent(pattern['setup_code']).format(prefix=prefix)
                    self.write_pattern(setup_code, final_body_code)
                else:
                    self.write_print_to_stderr(0,
                                               f'"[!] Could not parse correctness pattern {pattern_name}. Skipping."')

            else:
                # Use a simple mutation dict for placeholders like {prefix}
                mutations = self._get_mutated_values_for_pattern(prefix, [])

                # Format the template with basic values first
                initial_setup_code = dedent(pattern['setup_code']).format(**mutations)
                initial_body_code = dedent(pattern['body_code']).format(**mutations)

                # Pass the formatted code to the AST mutator
                mutated_body_code = self.ast_mutator.mutate(initial_body_code)

                self.write_pattern(initial_setup_code, mutated_body_code)
                self.emptyLine()

        elif self.options.jit_fuzz_systematic_values and has_payload_placeholder:
            # Logic from previous step remains here...
            self.write_print_to_stderr(0,
                                       f'"[{prefix}] >>> SYSTEMATIC Fuzzing Pattern: {pattern_name} <<<"')
            interesting_values = fusil.python.values.INTERESTING
            for i, payload_str in enumerate(interesting_values):
                iter_prefix = f"{prefix}_{i}"

                self.write_print_to_stderr(0, f'"""--- Iteration {i}: Payload = {payload_str} ---"""')

                mutations = self._get_mutated_values_for_pattern(iter_prefix, [])
                mutations['corruption_payload'] = payload_str

                setup_code = pattern['setup_code'].format(**mutations)
                body_code = pattern['body_code'].format(**mutations)

                self.write_pattern(setup_code, body_code)
                self.emptyLine()

        elif self.options.jit_fuzz_type_aware and has_payload_placeholder:
            # TYPE-AWARE MODE
            self.write_print_to_stderr(
                0,
                f'"[{prefix}] >>> TYPE-AWARE Fuzzing Pattern: {pattern_name} <<<"'
            )

            original_type = pattern.get('payload_variable_type')
            if not original_type:
                self.write_print_to_stderr(
                    0,
                    f'"[!] Pattern {pattern_name} is missing "payload_variable_type" metadata. Skipping type-aware fuzzing."'
                )
            else:
                # Define a suite of generators for our contrasting types
                type_generators = {
                    'str': self.arg_generator.genString,
                    'bytes': self.arg_generator.genBytes,
                    'float': self.arg_generator.genFloat,
                    'list': self.arg_generator.genList,
                    'NoneType': lambda: ['None'],
                    'tricky': self.arg_generator.genTrickyObjects,
                }

                # Remove the original type to ensure we only use contrasting types
                if original_type in type_generators:
                    del type_generators[original_type]

                for type_name, generator_func in type_generators.items():
                    iter_prefix = f"{prefix}_{type_name}"
                    # Generate a value string for the chosen type
                    payload_str = " ".join(generator_func())

                    self.write_print_to_stderr(0,
                                           f'"""--- Corrupting with type {type_name}: Payload = {payload_str} ---"""')

                    mutations = self._get_mutated_values_for_pattern(iter_prefix, [])
                    mutations['corruption_payload'] = payload_str

                    setup_code = pattern['setup_code'].format(**mutations)
                    body_code = pattern['body_code'].format(**mutations)

                    self.write_pattern(setup_code, body_code)
                    self.emptyLine()
        else:
            if self.options.jit_fuzz_systematic_values and not has_payload_placeholder:
                self.write_print_to_stderr(0,
                                           f'"[{prefix}] Pattern {pattern_name} does not use a payload. Generating one random variant instead."')

            self.write_print_to_stderr(0,
                                       f'"[{prefix}] >>> RANDOM Fuzzing Pattern: {pattern_name} - {pattern["description"]} <<<"')
            mutations = self._get_mutated_values_for_pattern(prefix, [])

            if '{corruption_payload}' not in mutations:
                mutations['corruption_payload'] = "None"

            setup_code = pattern['setup_code'].format(**mutations)
            body_code = pattern['body_code'].format(**mutations)
            self._write_mutated_code_in_environment(prefix, setup_code, body_code)

        self.write_print_to_stderr(0, f'"[{prefix}] <<< Finished Fuzzing Pattern: {pattern_name} >>>"')
        self.emptyLine()

    def _get_mutated_values_for_pattern(self, prefix: str, param_names: list[str]) -> dict:
        """
        Creates a dictionary of randomized values. Chooses one of three strategies
        for the 'expression' value:
        1. Simple Infix Operator (40% chance)
        2. AST-Generated Complex Expression (40% chance)
        3. Operator Module Function Call (20% chance)
        """
        # --- Value & Type Mutation (Setup) ---
        corruption_payload = self.arg_generator.genInterestingValues()[0]
        loop_var = f"i_{prefix}"
        expression_str = ""

        # --- Super-Hybrid Expression Mutation ---
        strategy_roll = random()

        if strategy_roll < 0.4:
            # --- Strategy 1: Simple Infix Operator (40% probability) ---
            self.write_print_to_stderr(0, f'"[{prefix}] Expression Strategy: Infix Operator"')
            operator_list = [
                '+', '-', '*', '/', '//', '%', '>>', '&', '|', '^',
                '<', '<=', '==', '!=', '>', '>='
            ]  # Remove  '**' and '<<' as they often result in OverflowErrors
            chosen_op = choice(operator_list)
            expression_str = f"{loop_var} {chosen_op} {loop_var}"

        elif strategy_roll < 0.8:
            # --- Strategy 2: AST-Generated Complex Expression (40% probability) ---
            self.write_print_to_stderr(0, f'"[{prefix}] Expression Strategy: AST-Generated"')
            available_vars = [f"i_{prefix}"] + param_names
            expression_ast = self._generate_expression_ast(available_vars=available_vars)
            try:
                expression_str = ast.unparse(expression_ast)
            except AttributeError:
                expression_str = f"{loop_var} # AST unparsing failed"

        else:
            # --- Strategy 3: Operator Module Function Call (20% probability) ---
            self.write_print_to_stderr(0, f'"[{prefix}] Expression Strategy: Functional Call"')
            func_list = [
                'operator.add', 'operator.sub', 'operator.mul', 'operator.truediv',
                'operator.floordiv', 'operator.mod', 'operator.pow', 'operator.lshift',
                'operator.rshift', 'operator.and_', 'operator.or_', 'operator.xor',
                'operator.lt', 'operator.le', 'operator.eq', 'operator.ne',
                'operator.gt', 'operator.ge'
            ]
            chosen_func = choice(func_list)
            expression_str = f"{chosen_func}({loop_var}, {loop_var})"

        return {
            'prefix': prefix,
            'loop_var': loop_var,
            'loop_iterations': randint(500, self.options.jit_loop_iterations),
            'trigger_iteration': randint(400, 498),
            'corruption_payload': corruption_payload,
            'expression': expression_str,
            'inheritance_depth': randint(50, 500),
            'warmup_calls': self.options.jit_loop_iterations // 10,
        }

    def _write_mutated_code_in_environment(self, prefix: str, setup_code: str, body_code: str) -> None:
        """
        Takes the mutated code and writes it into the script, wrapped in
        a randomly chosen execution environment from an expanded suite.
        """
        # 1. Generate the mutated parameter and argument set FIRST.
        params = self._generate_mutated_parameters(prefix)
        param_def = params['def_str']
        param_call = params['call_str']
        param_setup = params['setup_code']
        param_names = params['param_names']

        # Inject parameter setup code before the rest of the logic
        if param_setup:
            self.write(0, param_setup)

        # 2. Generate the rest of the mutations, PASSING IN the param_names
        # This is a key change: the expression now knows about the parameters
        # (The logic of _get_mutated_values_for_pattern is now conceptually here)
        mutations = self._get_mutated_values_for_pattern(prefix, param_names)

        # 3. Format the core setup and body with these mutations
        final_setup = setup_code.format(**mutations)
        final_body = body_code.format(**mutations)

        # --- Environment Mutation ---
        env_choice = randint(0, 5)

        # --- Environment 1: Simple top-level function (existing) ---
        if env_choice == 0:
            self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: Top-Level Function"')
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(final_setup, final_body)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"harness_{prefix}({param_call})")


        # --- Environment 2: Nested function (existing) ---
        elif env_choice == 1:
            self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: Nested Function"')
            self.write(0, f"def outer_{prefix}({param_def}):")
            self.addLevel(1)
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(final_setup, final_body)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"harness_{prefix}({param_call})")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"outer_{prefix}({param_call})")

        # --- Environment 3: Class method (existing) ---
        elif env_choice == 2:
            self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: Class Method"')
            self.write(0, f"class Runner_{prefix}:")
            self.addLevel(1)
            self.write(0, f"def harness(self, {param_def}):")
            self.addLevel(1)
            self.write_pattern(final_setup, final_body)
            self.restoreLevel(self.parent.base_level - 2)
            self.write(0, f"Runner_{prefix}().harness({param_call})")

        # --- Environment 4: Asynchronous Function (NEW) ---
        elif env_choice == 3:
            self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: Async Function"')
            self.write(0, "import asyncio")
            self.write(0, f"async def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(final_setup, final_body)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"asyncio.run(harness_{prefix}({param_call}))")

        # --- Environment 5: Generator Function (NEW) ---
        elif env_choice == 4:
            self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: Generator Function"')
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(final_setup, final_body)
            self.write(0, "yield # Make this a generator")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "# We must consume the generator for its code to execute.")
            self.write(0, f"for _ in harness_{prefix}({param_call}): pass")

        # --- Environment 6: Lambda-called Function (NEW) ---
        else:  # env_choice == 5
            self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: Lambda-called Function"')
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(final_setup, final_body)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"caller = lambda: harness_{prefix}({param_call})")
            self.write(0, "caller()")

    def write_pattern(self, setup_code: str, body_code: str, level=0):
        """
        Writes the setup and body code for a pattern, wrapped in a
        try...except block to handle benign exceptions from mutated code.
        """
        self.write(level, "try:")
        self.addLevel(1)

        # Write the actual pattern code inside the try block
        for line in dedent(setup_code).splitlines():
            self.write(level, line)
        self.emptyLine()
        for line in dedent(body_code).splitlines():
            self.write(level, line)

        self.restoreLevel(self.parent.base_level - 1)
        # Raise AssertionErrors so we know the control and JITted code results don't match.
        self.write(level, "except AssertionError:")
        self.addLevel(1)
        self.write(level, "raise")
        self.restoreLevel(self.parent.base_level - 1)
        # Catch any exception to prevent the fuzzer from stopping on
        # benign errors, allowing it to continue hunting for crashes.
        self.write(level, "except Exception:")
        self.addLevel(1)
        self.write(level, "pass")
        self.restoreLevel(self.parent.base_level - 1)

    def _generate_expression_ast(self, available_vars: list[str], depth: int = 0) -> ast.expr:
        """
        Recursively builds an Abstract Syntax Tree for a complex, random expression.

        Args:
            available_vars: A list of variable names (as strings) to use as operands.
            depth: The current recursion depth, to prevent infinite recursion.

        Returns:
            An ast.expr node representing the generated expression.
        """
        # Max recursion depth to ensure termination
        if depth > randint(2, 3):
            # Base Case: Return a variable or a constant.
            if random() < 0.7:
                return ast.Name(id=choice(available_vars), ctx=ast.Load())
            else:
                # Use a small, simple constant for this proof-of-concept
                return ast.Constant(value=randint(1, 100))

        # Recursive Step: Choose an operator and generate sub-expressions.
        # Define our suite of AST operator nodes
        ast_ops = [
            ast.Add(), ast.Sub(), ast.Mult(), ast.Div(), ast.FloorDiv(), ast.Mod(),
            ast.RShift(), ast.BitAnd(), ast.BitOr(), ast.BitXor()
        ]  # Remove ast.Pow() and ast.LShift() as they frequently lead to OverflowErrors
        chosen_op = choice(ast_ops)

        # Generate the left and right operands by calling ourselves recursively.
        left_operand = self._generate_expression_ast(available_vars, depth + 1)
        right_operand = self._generate_expression_ast(available_vars, depth + 1)

        return ast.BinOp(left=left_operand, op=chosen_op, right=right_operand)

    def _generate_mutated_parameters(self, prefix: str) -> dict:
        """
        Generates a dictionary containing parameter definitions and corresponding
        arguments for a function call, using various mutation strategies.

        Returns: {
            'def_str': The string for the function definition (e.g., "p0, p1=[]").
            'call_str': The string for the function call (e.g., "val0, a_list").
            'setup_code': Any code needed before the function definition.
            'param_names': A list of parameter names for the AST generator.
        }
        """
        strategy_roll = random()
        setup_code = []
        param_names = []

        if strategy_roll < 0.25:
            # --- Strategy 1: Pathological Parameter Count ---
            self.write_print_to_stderr(0, f'"[{prefix}] Parameter Strategy: Pathological Count"')
            count = 260
            param_names = [f"p_{i}_{prefix}" for i in range(count)]
            def_str = ", ".join(param_names)
            call_args = [self.arg_generator.genInt()[0] for _ in range(count)]
            call_str = ", ".join(call_args)

        elif strategy_roll < 0.5:
            # --- Strategy 2: Mutable Default Argument ---
            self.write_print_to_stderr(0, f'"[{prefix}] Parameter Strategy: Mutable Default"')
            param_names = [f"p0_{prefix}", f"p1_{prefix}"]
            # The default object is created once and shared across calls
            def_str = f"{param_names[0]}, {param_names[1]}=[]"
            # Call the function in a way that uses the default argument
            call_str = self.arg_generator.genString()[0]

        elif strategy_roll < 0.75:
            # --- Strategy 3: Argument Aliasing ---
            self.write_print_to_stderr(0, f'"[{prefix}] Parameter Strategy: Argument Aliasing"')
            param_names = [f"p_a_{prefix}", f"p_b_{prefix}"]
            def_str = ", ".join(param_names)
            # Define the mutable object that will be aliased
            aliased_obj_name = f"aliased_list_{prefix}"
            setup_code.append(f"{aliased_obj_name} = [1, 2, 3, 4, 5]")
            # Pass the same object to multiple parameters
            call_str = f"{aliased_obj_name}, {aliased_obj_name}"

        else:
            # --- Strategy 4: Standard, simple parameters ---
            self.write_print_to_stderr(0, f'"[{prefix}] Parameter Strategy: Standard"')
            param_names = [f"p_{i}_{prefix}" for i in range(randint(1, 4))]
            def_str = ", ".join(param_names)
            call_args = [self.arg_generator.genInt()[0] for _ in range(len(param_names))]
            call_str = ", ".join(call_args)

        return {
            "def_str": def_str,
            "call_str": call_str,
            "setup_code": "\n".join(setup_code),
            "param_names": param_names,
        }

    def _get_function_body(self, code: str, func_name_prefix: str) -> str | None:
        """
        Parses a string of code and extracts the source of the first function
        whose name starts with the given prefix.
        """
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name.startswith(func_name_prefix):
                    return ast.unparse(node)
        except (SyntaxError, AttributeError):
            return None
        return None

