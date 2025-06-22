"""
Main orchestrator for the CPython Tier 2 JIT Fuzzing subsystem.

This module provides the `WriteJITCode` class, which acts as the primary
entry point and dispatcher for all JIT-related test case generation. It is
instantiated by the main `WritePythonCode` class and handles the high-level
logic for deciding which fuzzing strategy to employ based on the user's
command-line options.

The key responsibilities of this module are:
- Parsing JIT-specific command-line options.
- Dispatching test case generation to one of three main modes:
  1. `synthesize`: Calls the ASTPatternGenerator to create novel patterns
     from scratch.
  2. `variational`: Calls the variational engine to mutate existing patterns
     from the bug_patterns.py library.
  3. `legacy`: Calls the original, hard-coded scenario generators for
     regression testing.
- Wrapping the final generated code in a variety of execution environments
  (e.g., functions, class methods, async functions) to increase coverage.
"""

from __future__ import annotations

import ast
import inspect
from textwrap import dedent
from typing import Any
from random import choice, randint, random
from typing import TYPE_CHECKING

import fusil.python.values
from fusil.python.jit.ast_mutator import ASTMutator
from fusil.python.jit.ast_pattern_generator import ASTPatternGenerator
from fusil.python.jit.bug_patterns import BUG_PATTERNS
from fusil.write_code import CodeTemplate as CT

if TYPE_CHECKING:
    from fusil.python.write_python_code import WritePythonCode


class WriteJITCode:
    """
    Acts as the main orchestrator for the CPython JIT Fuzzing subsystem.

    This class is instantiated by the primary `WritePythonCode` object and serves
    as the main entry point for all JIT-related test case generation. It contains
    the top-level dispatch logic that selects a fuzzing strategy based on the
    user's command-line options.

    The primary code generation flow is as follows:
    1.  `generate_scenario()` is called.
    2.  It reads the `--jit-mode` flag to determine the primary strategy
        ('synthesize', 'variational', 'legacy', or 'all').
    3.  It dispatches to a specialized helper method for that strategy:
        - `_generate_variational_scenario()` for mutating existing patterns.
        - The `ast_pattern_generator` for synthesizing new patterns.
        - `_generate_legacy_scenario()` for running older, hard-coded tests.
    4.  The chosen generator produces a block of code representing the core logic.
    5.  This code is then passed to `_write_mutated_code_in_environment()` to be
        wrapped in a randomly chosen execution context (e.g., a function, a
        class method, an async function) to increase test diversity.
    """
    def __init__(self, parent: "WritePythonCode"):
        # We hold a reference to the main writer to access its options,
        # argument generator, and file writing methods.
        self.parent = parent
        self.options = parent.options
        self.arg_generator = parent.arg_generator
        self.module_name = parent.module_name

        self.ast_mutator = ASTMutator()
        self.ast_pattern_generator = ASTPatternGenerator(parent)

        # Bind the writing methods directly for convenience
        self.write_block = parent.write_block
        self.write_print_to_stderr = parent.write_print_to_stderr

        self.jit_warmed_targets = []
        self.fuzzable_classes = None

    def generate_scenario(self, prefix: str) -> str:
        """
        Main entry point for all JIT scenario generation.

        This method acts as the master orchestrator. It first selects a target
        (a module-level function or a class method) using the
        _select_fuzzing_target() helper. It then dispatches to the
        appropriate generation engine based on the user's --jit-mode and
        other command-line flags. It then writes the result to the output buffer.
        """
        # 1. Select a target to be fuzzed. This can be a function or a method.
        target = self._select_fuzzing_target(prefix)
        if not target:
            output = self.write_print_to_stderr(
                0, '"[-] No suitable functions or methods found to fuzz."', return_str=True
            )
            return output

        # 2. Dispatch to the main generation logic based on the chosen mode.
        mode = self.options.jit_mode
        output = ""

        # This helper is now only used for `--jit-mode=all`
        if mode == 'all':
            output = self._execute_randomized_strategy(prefix, target)

        elif mode == 'synthesize':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: AST Pattern Synthesis"')
            body_code = self.ast_pattern_generator.generate_pattern()
            params = self._generate_mutated_parameters(prefix, target)
            output = self._write_mutated_code_in_environment(prefix, "", body_code, params)

        elif mode == 'variational':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Variational Pattern Fuzzing"')
            output = self._generate_variational_scenario(prefix, self.options.jit_pattern_name, target)

        elif mode == 'legacy':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Legacy Scenario Generation"')
            output = self._generate_legacy_scenario(prefix, target)

        self.write_block(0, output)
        return output  # To make testing easier

    def _execute_randomized_strategy(self, prefix: str, target: dict) -> str:
        """
        Implements the logic for `--jit-mode=all`.

        For a single test case, this method randomly selects a core generation
        strategy ('synthesize', 'variational', or 'legacy') and a set of
        compatible modifier flags. It then calls the appropriate generator
        to create a test case, ensuring maximum diversity over the course
        of a long fuzzing session.
        """
        chosen_mode = choice(['synthesize', 'variational', 'legacy'])
        header_print = self.write_print_to_stderr(
            0, f'"[{prefix}] JIT-MODE=ALL: Randomly selected mode: {chosen_mode}"', return_str=True
        )

        # Store original values and set temporary random ones
        flags_to_modify = [
            "jit_fuzz_ast_mutation", "jit_wrap_statements"
        ]
        original_flag_values = {flag: getattr(self.options, flag) for flag in flags_to_modify}
        for flag in flags_to_modify:
            setattr(self.options, flag, choice([True, False]))

        output = ""
        # Dispatch to the chosen mode's logic
        if chosen_mode == 'synthesize':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: AST Pattern Synthesis"')
            body_code = self.ast_pattern_generator.generate_pattern()
            params = self._generate_mutated_parameters(prefix, target)
            output = self._write_mutated_code_in_environment(prefix, "", body_code, params)
        elif chosen_mode == 'variational':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Variational Pattern Fuzzing"')
            output = self._generate_variational_scenario(prefix, 'ALL', target)
        elif chosen_mode == 'legacy':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Legacy Scenario Generation"')
            output = self._generate_legacy_scenario(prefix, target)

        # Restore original flag values
        for flag, value in original_flag_values.items():
            setattr(self.options, flag, value)
        return f"{header_print}\n{output}"

    def _generate_legacy_scenario(self, prefix: str, target: dict) -> str:
        """
        Executes the original "legacy" fuzzing logic. It chooses between
        correctness, hostile, or friendly scenarios based on the original
        set of command-line flags. This is preserved for regression testing.
        """
        # Handle specific re-discovery flag ---
        if self.options.rediscover_decref_crash:
            header_print = self.write_print_to_stderr(
                0, f'"[{prefix}] LEGACY MODE: Generating Re-discovery Scenario"', return_str=True
            )
            output = self._generate_decref_escapes_scenario(prefix, target)
            return f"{header_print}\n{output}"

        # 1. First, check if we should run a correctness test.
        if self.options.jit_correctness_testing and random() < self.options.jit_correctness_prob:
            header_print = self.write_print_to_stderr(
                0, f'"[{prefix}] LEGACY MODE: Generating Correctness Scenario"', return_str=True
            )
            # We can pick a random correctness pattern to run here.
            corr_pattern = choice(list(BUG_PATTERNS.keys()))
            output = self._generate_paired_ast_mutation_scenario(prefix, corr_pattern, BUG_PATTERNS[corr_pattern], {})
            return f"{header_print}\n{output}"

        # Decide whether to generate a hostile scenario.
        hostile_prob = self.options.jit_hostile_prob
        if random() < hostile_prob:
            header_print = self.write_print_to_stderr(
                0, f'"[{prefix}] LEGACY MODE: Generating Hostile Scenario"', return_str=True
            )
            output = self._generate_hostile_scenario(prefix, target)
            return f"{header_print}\n{output}"
        else:
            header_print = self.write_print_to_stderr(
                0, f'"[{prefix}] LEGACY MODE: Generating Friendly Scenario"', return_str=True
            )
            output = self._generate_friendly_scenario(prefix, target)
            return f"{header_print}\n{output}"

    def _generate_correctness_scenario(self, prefix: str, target: dict) -> str:
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
        return chosen(prefix, target)

    def _generate_hostile_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Chooses and generates one of the hostile (crash-finding)
        scenarios from the original, hard-coded suite.

        This method maintains a weighted choice between simpler, isolated hostile
        scenarios and more complex "mixed" scenarios that combine multiple
        attack techniques.
        """
        # The list of our original, non-pattern-based hostile generators.
        basic_hostile_generators = [
            self._generate_invalidation_scenario,
            self._generate_deleter_scenario,
            self._generate_many_vars_scenario,
            self._generate_deep_calls_scenario,
            self._generate_type_version_scenario,
            self._generate_concurrency_scenario,
            self._generate_side_exit_scenario,
            self._generate_isinstance_attack_scenario
        ]

        # Level 3 scenarios (mixed hostile)
        mixed_hostile_generators = [
            self._generate_mixed_many_vars_scenario,
            self._generate_del_invalidation_scenario,
            self._generate_mixed_deep_calls_scenario,
            self._generate_deep_call_invalidation_scenario,
            self._generate_fuzzed_func_invalidation_scenario,
            self._generate_polymorphic_call_block_scenario
        ]

        if random() < 0.8:
            hostile_generators = basic_hostile_generators
        else:
            hostile_generators = mixed_hostile_generators
        chosen_generator = choice(hostile_generators)
        return chosen_generator(prefix, target)

    def _generate_friendly_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Chooses and generates a JIT-friendly (warm-up) scenario.

        This method randomly chooses between two strategies: generating a simple
        polymorphic call block, or delegating to the more powerful variational
        engine with the 'friendly_base' pattern.
        """
        if random() < 0.0:
            # Use the simple polymorphic call block.
            return self._generate_polymorphic_call_block(prefix, target)
        else:
            # Use the JIT pattern block, which is now powered by the variational engine.
            return self._generate_jit_pattern_block(prefix, target)

    def generate_stateful_object_scenario(self, prefix: str, instance_var_name: str, class_name_str: str,
                                          class_type: type) -> str:
        """
        Generates a stateful hot loop for a class instance.

        This method is the primary bridge between the original `fusil` class
        fuzzing logic and the JIT subsystem. It is called by `_fuzz_one_class`
        when JIT mode is enabled. It selects a random method from the provided
        class instance and generates code to call it repeatedly in a hot loop.
        """
        # 1. Discover a suitable method on the class to target.
        methods_dict = self.parent._get_object_methods(class_type, class_name_str)
        if not methods_dict:
            # If no methods, we can't generate a meaningful scenario.
            return

        chosen_method_name = choice(list(methods_dict.keys()))
        chosen_method_obj = methods_dict[chosen_method_name]

        # 2. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] JIT MODE: Stateful fuzzing for class: {class_name_str}"',
            return_str=True
        )

        # Get "smart" arguments for the chosen method.
        args_str = self._generate_args_for_method(chosen_method_obj)

        # Generate the hot loop and the guarded method call.
        hot_loop_str = self._begin_hot_loop(prefix)
        call_str = self._generate_guarded_call(f"{instance_var_name}.{chosen_method_name}({args_str})")

        # 3. Assemble the final code block.
        final_code = CT("""
{header_print}
# Check that the instance was created successfully before starting the hot loop.
if {instance_var_name} is not None and {instance_var_name} is not SENTINEL_VALUE:
    {hot_loop_str}
        # In the hot loop, repeatedly call a single method to warm it up for the JIT.
        {call_str}

""")
        # 4. Return the assembled block.
        return final_code.render(**locals())

    def _generate_jit_pattern_block(self, prefix: str, target: dict) -> str:
        """
        Generates a friendly block of code by feeding a general-purpose
        pattern into our advanced variational/AST mutation engine.
        """
        header_print = self.write_print_to_stderr(
            0, f'"[{prefix}] Generating friendly JIT patterns via variational engine."', return_str=True
        )
        scenario_str = self._generate_variational_scenario(prefix, 'friendly_base', target)
        return f"{header_print}\n{scenario_str}"

    def _generate_polymorphic_call_block(self, prefix: str, target: dict) -> str:
        """
        Generates a hot loop that calls one function/method with arguments
        of different types to stress the JIT's call-site caching.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Polymorphic Call Scenario for: {target["name"]} <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Polymorphic Call Scenario >>>"',
            return_str=True
        )

        # Get the safe setup code for the target (e.g., guarded instantiation).
        setup_str, instance_var = self._write_target_setup(prefix, target)

        # Get the boilerplate for the hot loop.
        hot_loop_str = self._begin_hot_loop(prefix)

        # Generate the list of polymorphic calls that will go inside the loop.
        poly_gens = [
            self.arg_generator.genInt,
            self.arg_generator.genString,
            self.arg_generator.genList,
            self.arg_generator.genBytes,
        ]

        calls_in_loop = []
        for gen_func in poly_gens:
            arg_str = " ".join(gen_func())
            # Generate a full, guarded call for each argument type.
            call = self._generate_guarded_call(f"{target['call_str']}({arg_str})")
            calls_in_loop.append(call)

        # Join the calls into a single, indented block for the f-string.
        calls_in_loop_str = "\n".join(calls_in_loop).replace("\n", "\n    ")

        # 2. Assemble the final code block.
        final_code = f"""
{header_print}

{setup_str}

# Only proceed if the target was successfully set up (e.g., instantiated).
if {instance_var if instance_var else 'True'}:
    # Generate the JIT-warming hot loop.
    {hot_loop_str}:
        # Inside the loop, call the target with arguments of varying types.
        {calls_in_loop_str}

{footer_print}

"""
        # 3. Return the entire assembled block.
        return final_code

    def _generate_invalidation_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a three-phase invalidation attack on a class method.

        This scenario is designed to test the JIT's ability to correctly
        invalidate its caches for optimized code. It proceeds in three phases:
        1. WARM-UP: A method on a class instance is called in a hot loop to
           get it JIT-compiled.
        2. INVALIDATE: The method is maliciously replaced on the class itself.
        3. RE-EXECUTE: The method is called again on the original instance. A
           crash at this stage indicates a JIT bug.
        """
        # This scenario is specific to invalidating a method on a class.
        if target['type'] != 'method':
            return self.write_print_to_stderr(
                0, f'"[{prefix}] Skipping Invalidation Scenario for non-method target."', return_str=True
            )

        # 1. Get necessary info from the target dictionary.
        instance_var = target['instance_var']
        class_name = target['name'].split('.')[0]
        method_name = target['name'].split('.')[-1]

        # 2. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Invalidation Scenario targeting {target["name"]} <<<"'
        )
        setup_str, _ = self._write_target_setup(prefix, target)

        # Warmup Phase
        warmup_loop_str = self._begin_hot_loop(f"{prefix}_warmup")
        warmup_call_str = self._generate_guarded_call(f"{target['call_str']}()")

        # Invalidation Phase
        payloads = ["lambda *a, **kw: 'payload'", "123", "'a string'", "None"]
        invalidation_str = self._generate_guarded_call(
            f"setattr({self.module_name}.{class_name}, '{method_name}', {choice(payloads)})"
        )

        # Re-execute Phase
        reexecute_call_str = self._generate_guarded_call(f"{target['call_str']}()")

        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished JIT Invalidation Scenario >>>"'
        )

        # 3. Assemble the final code block using a multi-line f-string.
        phase_1_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] PHASE 1: Warming up {class_name}.{method_name}"', return_str=True)
        phase_2_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] PHASE 2: Invalidating method on class."', return_str=True)
        phase_3_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] PHASE 3: Re-executing to check for crash."', return_str=True)
        final_code = CT("""
{header_print}

# Safely instantiate the target object for the invalidation test.
{setup_str}

# Only proceed if the object was successfully created.
if {instance_var}:
    # Phase 1: Warm-up the method to get it JIT-compiled.
    {phase_1_print}
    {warmup_loop_str}
        {warmup_call_str}

    # Phase 2: Invalidate the dependency by replacing the method on the class.
    {phase_2_print}
    {invalidation_str}
    collect()

    # Phase 3: Re-execute the method to check for a crash.
    {phase_3_print}
    {reexecute_call_str}

{footer_print}

""")
        # 4. Return entire assembled block.
        return final_code.render(**locals())

    def _generate_deleter_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a scenario that uses a __del__ side effect to induce type
        confusion for local, instance, and class variables.

        This legacy scenario creates a `FrameModifier` class and then, within
        a hot loop, instantiates it and arranges for its `__del__` method to
        fire and corrupt variables that are being used in the same loop.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Advanced __del__ Side Effect Scenario <<<"', return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Advanced __del__ Side Effect Scenario >>>"', return_str=True
        )

        loop_iterations = self.options.jit_loop_iterations
        trigger_iteration = loop_iterations - 2

        # --- Generate setup strings ---
        setup_str = dedent(f"""
            # A. Create a local variable and its FrameModifier
            target_{prefix} = 100
            fm_target_{prefix} = FrameModifier('target_{prefix}', 'local-string')
            fm_target_i_{prefix} = FrameModifier('i_{prefix}', 'local-string')

            # B. Create a class with instance/class attributes and their FrameModifiers
            class Dummy_{prefix}:
                a = 200  # Class attribute
                def __init__(self):
                    self.b = 300  # Instance attribute
            
            dummy_instance_{prefix} = Dummy_{prefix}()
            fm_dummy_class_attr = FrameModifier('dummy_instance_{prefix}.a', 'class-attr-string')
            fm_dummy_instance_attr = FrameModifier('dummy_instance_{prefix}.b', 'instance-attr-string')
        """)

        hot_loop_header_str = self._begin_hot_loop(prefix)
        # --- Generate hot loop body strings ---
        warmup_str = self._generate_guarded_call(dedent(f"""
            _ = target_{prefix} + i_{prefix}
            _ = dummy_instance_{prefix}.a + i_{prefix}
            _ = dummy_instance_{prefix}.b + i_{prefix}
        """))

        del_trigger_str = dedent(f"""
            if i_{prefix} == {trigger_iteration}:
                print("[{prefix}] DELETING FRAME MODIFIERS...", file=stderr)
                del fm_target_{prefix}
                del fm_dummy_class_attr
                del fm_dummy_instance_attr
                del fm_target_i_{prefix}
                collect()
        """)

        reexecute_str = self._generate_guarded_call(dedent(f"""
            _ = i_{prefix} + i_{prefix}
            _ = target_{prefix} + target_{prefix}
            _ = dummy_instance_{prefix}.a + i_{prefix}
            _ = dummy_instance_{prefix}.b + i_{prefix}
        """))

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

{setup_str}

{hot_loop_header_str}
    # Use all variables to warm up the JIT with their initial types
    {warmup_str}

    # On the penultimate loop, delete the FrameModifiers to trigger __del__
    {del_trigger_str}

    # Use the variables again, which may hit a corrupted JIT state
    {reexecute_str}

{footer_print}

""")
        # 3. Return the assembled block.
        return final_code.render(**locals())

    def _generate_many_vars_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a function with >256 local variables by delegating to the
        variational engine with the 'many_vars_base' pattern.

        This approach leverages the AST mutator to create complex expressions
        that use the large set of local variables, providing a more dynamic
        and stressful test than the original hard-coded version.
        """
        header_print = self.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Many Vars" Generative Scenario via Pattern <<<"""', return_str=True
        )

        scenario_str = self._generate_variational_scenario(prefix, 'many_vars_base', target)
        return f"{header_print}\n{scenario_str}"

    def _generate_deep_calls_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a scenario to stress the JIT's handling of deep call stacks.

        This method defines a chain of deeply nested recursive function calls
        and then executes the top-level function in a hot loop to test the
        JIT's ability to handle deep C stack usage and long traces.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Deep Calls" Resource Limit Scenario <<<"""',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Deep Calls" Scenario >>>"""',
            return_str=True
        )

        depth = 20

        # --- Generate the recursive function chain as a single string block ---
        func_chain_lines = [f"# Define a deep chain of {depth} nested function calls."]
        func_chain_lines.append(f"def f_0_{prefix}(): return 1")
        for i in range(1, depth):
            func_chain_lines.append(f"def f_{i}_{prefix}(): return 1 + f_{i-1}_{prefix}()")

        func_chain_str = "\n".join(func_chain_lines)
        top_level_func = f"f_{depth - 1}_{prefix}"

        # --- Generate the hot loop using our helper ---
        hot_loop_str = self._begin_hot_loop(prefix)
        # The body of the loop will be a guarded call to the top of the chain.
        # We specifically catch RecursionError here, as it's an expected outcome.
        hot_loop_call_str = dedent(f"""
            try:
                {top_level_func}()
            except RecursionError:
                print(f"[{prefix}] Caught expected RecursionError.", file=stderr)
                break
        """)

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

{func_chain_str}

# Execute the top-level function of the chain in a hot loop.
{hot_loop_str}
    {hot_loop_call_str}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _define_frame_modifier_instances(self, prefix: str, targets_and_payloads: dict) -> tuple[str, list[str]]:
        """
        Generates the 'fm_... = FrameModifier(...)' lines for a set of targets.

        This helper takes a dictionary mapping target variable paths (e.g.,
        'my_var' or 'my_instance.attr') to the payload they should be
        corrupted with. It returns the generated code as a string, along with
        a list of the variable names created for the FrameModifier instances,
        which can then be used in a `del` trigger.
        """
        fm_vars = []
        code_lines = ["# Define FrameModifier instances to arm the __del__ side effects."]

        for i, (target_path, payload) in enumerate(targets_and_payloads.items()):
            fm_var_name = f"fm_{prefix}_{i}"
            code_lines.append(f"{fm_var_name} = FrameModifier('{target_path}', {payload})")
            fm_vars.append(fm_var_name)

        # Join the generated lines into a single string block.
        code_block = "\n".join(code_lines)

        return code_block, fm_vars

    def _generate_mixed_many_vars_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario combining multiple stress factors.

        This hostile scenario creates a single function that:
        1. Defines over 256 local variables to stress EXTENDED_ARG handling.
        2. Arms a `__del__` side-effect attack to corrupt one of the high-index
           variables during a hot loop.
        3. Executes JIT-friendly math patterns within that loop.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Mixed Many Vars" Hostile Scenario <<<"""',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Mixed Many Vars" Scenario >>>"""',
            return_str=True
        )

        func_name = f"mixed_many_vars_func_{prefix}"
        loop_var = f"i_{prefix}"
        num_vars = 260
        loop_iterations = self.options.jit_loop_iterations

        # --- Generate setup code strings ---
        var_defs = "\n".join([f"var_{i} = {i}" for i in range(num_vars)])

        # The __del__ attack now targets a high-index variable.
        target_variable_path = f'var_{num_vars - 1}'
        fm_var_name = f"fm_{prefix}"
        fm_setup_str = self._generate_guarded_call(
            f"{fm_var_name} = FrameModifier('{target_variable_path}', 'corrupted-by-del')"
        )

        hot_loop_header_str = self._begin_hot_loop(prefix)
        # --- Generate hot loop body strings ---
        hot_loop_body_warmup = self._generate_guarded_call(
            f"res = var_0 + {loop_var}\nres += var_{num_vars - 1}"
        )

        del_trigger_str = dedent(f"""
            if {loop_var} == {loop_iterations - 2}:
                print("[{prefix}] DELETING FRAME MODIFIER...", file=stderr)
                del {fm_var_name}
                collect()
        """)

        composed_hostile_call = self._generate_guarded_call(f'{func_name}()')

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

def {func_name}():
    # Define {num_vars} local variables.
    {var_defs}

    # Arm the __del__ side effect.
    {fm_setup_str}
    
    # Run the hot loop.
    {hot_loop_header_str}
        # Use variables in JIT-friendly patterns.
        {hot_loop_body_warmup}
        
        # Plant the time bomb to trigger the __del__ side effect.
        {del_trigger_str}

# Execute the composed hostile function.
{composed_hostile_call}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _generate_del_invalidation_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario that uses a __del__ side effect
        to trigger a JIT cache invalidation.

        This mixed hostile scenario first warms up a target method to get it
        JIT-compiled. It then defines and immediately deletes a `FrameModifier`
        instance whose `__del__` method monkey-patches the target method on
        its class. Finally, it re-executes the method to check for a crash.
        """
        if target['type'] != 'method':
            return self.write_print_to_stderr(
                0, f'"[{prefix}] Skipping __del__ Invalidation for non-method target."', return_str=True
            )

        # 1. Generate the component code blocks as strings.
        instance_var = target['instance_var']
        class_name = target['name'].split('.')[0]
        method_name = target['name'].split('.')[-1]

        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting __del__ Invalidation Scenario <<<"', return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished __del__ Invalidation Scenario >>>"', return_str=True
        )

        # --- Phase 1: Warm-up ---
        setup_str, _ = self._write_target_setup(prefix, target)
        phase1_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] PHASE 1: Warming up {target["name"]}"', return_str=True)
        warmup_loop_str = self._begin_hot_loop(f"{prefix}_warmup")
        warmup_call_str = self._generate_guarded_call(f"{target['call_str']}()")

        # --- Phase 2: Invalidation via __del__ ---
        phase2_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] PHASE 2: Arming FrameModifier to invalidate via __del__."', return_str=True)
        target_path = f'{self.module_name}.{class_name}.{method_name}'
        fm_var_name = f"fm_{prefix}"
        # Create the FrameModifier instance and immediately delete it to trigger __del__.
        fm_guarded_call_str = self._generate_guarded_call(f"{fm_var_name} = FrameModifier('{target_path}', lambda *a, **kw: 'invalidated')")
        invalidation_str = CT("""
            # Define the FrameModifier and immediately delete it to trigger the side effect.
            {fm_guarded_call_str}
            if '{fm_var_name}' in locals():
                del {fm_var_name}
            collect()
        """).render(**locals())

        # --- Phase 3: Re-execute ---
        phase3_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] PHASE 3: Re-executing to check for crash."', return_str=True)
        reexecute_call_str = self._generate_guarded_call(f"{target['call_str']}()")

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

# Safely instantiate the target object.
{setup_str}

# Only proceed if the object was successfully created.
if {instance_var}:
    # Phase 1: Warm-up the method.
    {phase1_print}
    {warmup_loop_str}
        {warmup_call_str}

    # Phase 2: Invalidate the method using a __del__ side effect.
    {phase2_print}
    {invalidation_str}

    # Phase 3: Re-execute the now-invalidated method.
    {phase3_print}
    {reexecute_call_str}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _generate_mixed_deep_calls_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a deep call chain with complex logic in each frame.

        This scenario creates a chain of deeply nested functions. Unlike the
        simpler 'deep_calls' scenario, each function in this chain performs its
        own JIT-friendly work, and the deepest function also calls the main
        fuzzed target. This is designed to stress the JIT's ability to
        optimize across many active and complex stack frames.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Mixed Deep Calls" Hostile Scenario targeting: {target["name"]} <<<"""',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Mixed Deep Calls" Scenario >>>"""',
            return_str=True
        )

        setup_str, instance_var = self._write_target_setup(prefix, target)
        depth = 15

        # --- Generate the recursive function chain as a single string block ---
        func_chain_lines = [f"# Define a deep chain of {depth} functions, each with internal JIT-friendly patterns."]

        # Define the base case (deepest function), which calls the fuzzed target.
        base_case_call = self._generate_guarded_call(f"{target['call_str']}(x)")
        target_name = target['name']
        base_case_body = CT(dedent("""
            x = len('base_case') + p
            y = x % 5
            print(f"[{prefix}] Calling fuzzed target '{target_name}' from deep inside the call chain", file=stderr)
            {base_case_call}
            return x - y
        """)).render(**locals())
        func_chain_lines.append(CT("def f_0_{prefix}(p):\n    {base_case_body}").render(**locals()))

        # Define the intermediate functions in the chain.
        for i in range(1, depth):
            intermediate_body = dedent(f"""
                local_val = p * {i}
                s = 'abcdef'
                if local_val > 10 and (s[{i} % len(s)]):
                    local_val += f_{i - 1}_{prefix}(p)
                return local_val
            """)
            func_chain_lines.append(CT("def f_{i}_{prefix}(p):\n    {intermediate_body}").render(**locals()))

        func_chain_str = "\n\n".join(func_chain_lines)
        top_level_func = f"f_{depth - 1}_{prefix}"

        # --- Generate the hot loop using our helper ---
        hot_loop_header_str = self._begin_hot_loop(prefix)
        hot_loop_call_str = dedent(f"""
            try:
                {top_level_func}(i_{prefix})
            except RecursionError:
                print(f"[{prefix}] Caught expected RecursionError.", file=stderr)
                break
        """)

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

# Setup the target for the scenario (if it's a method).
{setup_str}

# Define the deep call chain.
{func_chain_str}

# Execute the top-level function of the complex chain in a hot loop.
{hot_loop_header_str}
    {hot_loop_call_str}

{footer_print}

""")
        # 3. Return the entire assembled block.
        final_code.render(**locals())

    def _generate_deep_call_invalidation_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario that invalidates a JIT trace
        in the middle of a deep call chain.

        This hostile scenario first warms up a deep chain of recursive function
        calls to get the entire trace JIT-compiled. It then redefines one of
        the functions in the middle of the chain and calls the top-level
        function again, testing if the JIT can correctly invalidate the now-broken
        trace.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Deep Call Invalidation" Hostile Scenario <<<"""',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Deep Call Invalidation" Scenario >>>"""',
            return_str=True
        )

        depth = 20
        invalidation_index = depth // 2

        # --- Generate the recursive function chain ---
        func_chain_lines = [f"# Phase 1: Define a deep chain of {depth} functions."]
        func_chain_lines.append(f"def f_0_{prefix}(p): return p + 1")
        for i in range(1, depth):
            func_chain_lines.append(f"def f_{i}_{prefix}(p): return f_{i-1}_{prefix}(p) + 1")

        func_chain_str = "\n".join(func_chain_lines)
        top_level_func = f"f_{depth - 1}_{prefix}"
        invalidation_func_name = f"f_{invalidation_index}_{prefix}"

        # --- Generate the warm-up loop ---
        warmup_loop_str = self._begin_hot_loop(prefix)
        # warmup_call_str = self._generate_guarded_call(f"{top_level_func}(i_{prefix})", catch_recursion_error=True)
        warmup_call_str = self._generate_guarded_call(f"{top_level_func}(i_{prefix})")

        # --- Generate the invalidation logic ---
        invalidation_str = dedent(f"""
            # Redefine the middle function to return a completely different type.
            def {invalidation_func_name}(p):
                return '<< JIT-INVALIDATED >>'
            collect()
        """)

        # --- Generate the re-execution logic ---
        reexecute_str = self._generate_guarded_call(f"{top_level_func}(1)")

        phase_1_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] Warming up the deep call chain..."',
                                                          return_str=True)
        phase_2_print = self.parent.write_print_to_stderr(0,
                                                          f'"[{prefix}] Phase 2: Invalidating {invalidation_func_name}..."',
                                                          return_str=True)
        phase_3_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] Phase 3: Re-executing the chain..."',
                                                           return_str=True)

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

{func_chain_str}

# Phase 1: Warm up the deep call chain to get it JIT-compiled.
{phase_1_print}
{warmup_loop_str}
    {warmup_call_str}

# Phase 2: Invalidate a function in the middle of the chain.
{phase_2_print}
{invalidation_str}

# Phase 3: Re-executing the chain to check for crashes. A TypeError is expected.
{phase_3_print}
{reexecute_str}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _generate_indirect_call_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario to stress the JIT's handling of
        indirect function calls.

        This method creates a harness function that takes a single callable
        argument. It JIT-compiles this harness by calling it in a hot loop.
        Finally, it calls the hot harness one last time, passing the main
        fuzzed target (function or method) as the argument, forcing an
        indirect call on a JIT-optimized path.
        """
        # 1. Generate the component code blocks as strings.
        harness_func_name = f"harness_{prefix}"

        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Indirect Call Scenario ({target["name"]}) <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Indirect Call Scenario >>>"',
            return_str=True
        )

        # --- Generate the harness function definition ---
        # This function takes a callable argument and runs it in a hot loop.
        hot_loop_body = self._generate_guarded_call(f"callable_arg(i_{prefix})")
        harness_def_str = dedent(f"""
            def {harness_func_name}(callable_arg):
                {self._begin_hot_loop(prefix)}
                    {hot_loop_body}
        """)

        # --- Generate the main execution logic ---
        setup_str, _ = self._write_target_setup(prefix, target)
        # The fuzzed callable itself is passed as the argument to the harness.
        execution_str = self._generate_guarded_call(f"{harness_func_name}({target['call_str']})")


        # 2. Assemble the final code block.
        final_code = f"""
{header_print}

# First, define the harness function that will become JIT-hot.
{harness_def_str}

# Next, set up the target callable (e.g., instantiate a class).
{setup_str}

# Finally, call the harness and pass the fuzzed target to it as an argument.
{execution_str}

{footer_print}

"""
        # 3. Return the entire assembled block.
        return final_code

    def _generate_fuzzed_func_invalidation_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a three-phase invalidation attack on an inlined function call.

        This scenario tests the JIT's ability to invalidate a trace when a
        function that was inlined into it is changed. It defines a simple
        wrapper, JIT-compiles it (which may inline the fuzzed target), then
        redefines the original fuzzed target on its module and re-executes
        the wrapper to check for a crash.
        """
        # This attack redefines a function on a module, so we only run it
        # if our target is a function.
        if target['type'] != 'function':
            return self.write_print_to_stderr(
                0, f'"[{prefix}] Skipping Fuzzed Function Invalidation for method target."', return_str=True
            )

        # 1. Generate the component code blocks as strings.
        wrapper_func_name = f"jit_wrapper_{prefix}"

        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Fuzzed Function Invalidation Scenario ({target["name"]}) <<<"',
            return_str=True
        )

        # Phase 1: Wrapper definition and Warmup
        phase1_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] Phase 1: Warming up wrapper function."', return_str=True)
        # The wrapper simply calls our target fuzzed function.
        wrapper_call = self._generate_guarded_call(f"{target['call_str']}()")
        wrapper_def_str = CT(dedent("""
            def {wrapper_func_name}():
                {wrapper_call}
        """)).render(**locals())
        warmup_loop_str = self._begin_hot_loop(f"{prefix}_warmup")
        warmup_call_str = f"{wrapper_func_name}()"

        # Phase 2: Invalidation
        phase2_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] Phase 2: Redefining {target["name"]} on the module..."', return_str=True)
        invalidation_str = self._generate_guarded_call(
            f"setattr({self.module_name}, '{target['name']}', lambda *a, **kw: 'payload')"
        )

        # Phase 3: Re-execution
        phase3_print = self.parent.write_print_to_stderr(0, f'"[{prefix}] Phase 3: Re-executing the wrapper to check for crashes..."', return_str=True)
        reexecute_call_str = self._generate_guarded_call(f"{wrapper_func_name}()")

        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Fuzzed Function Invalidation Scenario >>>"',
            return_str=True
        )

        # 2. Assemble the final code block using a multi-line f-string.
        final_code = CT("""
{header_print}

# Phase 1: Define a wrapper and JIT-compile it.
{wrapper_def_str}

{phase1_print}
{warmup_loop_str}
    {warmup_call_str}

# Phase 2: Invalidate the original fuzzed function.
{phase2_print}
{invalidation_str}
collect()

# Phase 3: Re-execute the wrapper to see if it crashes.
{phase3_print}
{reexecute_call_str}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _generate_polymorphic_call_block_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario to stress the JIT's call-site caching.

        This method creates a hot loop that, on each iteration, calls a
        variety of different *kinds* of callables in sequence: the main fuzzed
        target, a newly defined lambda, and a method on a newly defined class.
        This tests the JIT's ability to handle polymorphic call sites.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Polymorphic Callable Set Scenario <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Polymorphic Callable Set Scenario >>>"',
            return_str=True
        )

        # --- Generate the setup code: define the diverse callables ---
        lambda_name = f"lambda_{prefix}"
        class_name = f"CallableClass_{prefix}"
        instance_name = f"poly_instance_{prefix}"
        target_instance_name = f"target_instance_{prefix}"
        guarded_setup_code = ""
        if target['setup_code']:
            guarded_setup_code = self._generate_guarded_call(target['setup_code'])

        setup_str = CT(dedent("""
            # Define a set of diverse callables for the test.
            {lambda_name} = lambda x: x + 1

            class {class_name}:
                def method(self, x):
                    return x * 2
            {instance_name} = {class_name}()

            # Set up the main fuzzed target as well.
            {target_instance_name} = None
            {guarded_setup_code}
        """)).render(**locals())

        # --- Generate the list of calls for the loop body ---
        # The list includes the fuzzed target, the lambda, and the new method.
        # We need to guard the main target call in case its setup failed.
        if target.get('instance_var'):
            main_target_call = f"if {target['instance_var']}: {target['call_str']}(i_{prefix})"
        else:
            main_target_call = f"{target['call_str']}(i_{prefix})"

        calls_to_make = [
            main_target_call,
            f"{lambda_name}(i_{prefix})",
            f"{instance_name}.method(i_{prefix})",
        ]

        hot_loop_body_calls = []
        for call in calls_to_make:
            hot_loop_body_calls.append(self._generate_guarded_call(call))

        hot_loop_header = self._begin_hot_loop(prefix)
        hot_loop_body = "\n".join(hot_loop_body_calls)

        # 2. Assemble the final code block.
        final_code = CT("""
{header_print}

{setup_str}

# Call each of the different callables inside a hot loop.
{hot_loop_header}
    # The JIT must handle calls to the main fuzzed target, a lambda,
    # and a newly defined instance method in quick succession.
    {hot_loop_body}

{footer_print}

""")
        # 3. Return the assembled block.
        return final_code.render(**locals())

    def _generate_type_version_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario to attack the JIT's attribute caching.

        This scenario defines several classes that all have an attribute with
        the same name ('payload'), but where the nature of that attribute
        differs (e.g., data attribute, property, method). It then accesses
        this attribute polymorphically in a hot loop, testing the JIT's type
        versioning and `LOAD_ATTR` specialization.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Type Version Fuzzing Scenario <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Type Version Fuzzing Scenario >>>"',
            return_str=True
        )

        # --- Generate the setup code (class definitions) as a single block ---
        setup_str = dedent(f"""
            # Define classes with conflicting 'payload' attributes.
            class ShapeA_{prefix}: payload = 123
            class ShapeB_{prefix}:
                @property
                def payload(self): return 'property_payload'
            class ShapeC_{prefix}:
                def payload(self): return id(self)
            class ShapeD_{prefix}:
                __slots__ = ['payload']
                def __init__(self): self.payload = 'slot_payload'
            
            # Create a list of instances to iterate over.
            shapes_{prefix} = [ShapeA_{prefix}(), ShapeB_{prefix}(), ShapeC_{prefix}(), ShapeD_{prefix}()]
        """)

        hot_loop_header_str = self._begin_hot_loop(prefix)
        # --- Generate the hot loop body ---
        # This logic will be placed inside the loop generated by our helper.
        hot_loop_body = dedent(f"""
            obj = shapes_{prefix}[i_{prefix} % len(shapes_{prefix})]
            try:
                # This polymorphic access forces the JIT to constantly check
                # the object's type and the version of its attribute cache.
                payload_val = obj.payload
                # If the payload is a method, call it to make the access meaningful.
                if callable(payload_val):
                    payload_val()
            except Exception:
                pass
        """)

        # 2. Assemble the final code block using a multi-line f-string.
        final_code = CT("""
{header_print}

{setup_str}

# In a hot loop, polymorphically access the 'payload' attribute.
{hot_loop_header_str}
    {hot_loop_body}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _generate_concurrency_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a race condition to test the JIT's thread-safety.

        This scenario creates two competing threads: a "hammer" thread that
        repeatedly accesses an attribute in a JIT-compiled loop, and an
        "invalidator" thread that constantly changes that same attribute
        from another thread. This tests the JIT's attribute caches and type
        versioning mechanisms in a concurrent context.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Concurrency (Race Condition) Scenario <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished JIT Concurrency Scenario >>>"',
            return_str=True
        )

        # --- Generate the setup and thread definitions as a single block ---
        # This makes the relationship between the shared state and the threads very clear.
        setup_and_threads_str = dedent(f"""
            # Shared state for the threads.
            class JITTarget_{prefix}:
                attr = 100
            stop_flag_{prefix} = False

            # Thread 1: The "JIT Hammer"
            # This thread runs a tight loop to get its code JIT-compiled.
            def hammer_thread_{prefix}():
                target = JITTarget_{prefix}()
                print("[{prefix}] Hammer thread starting...", file=stderr)
                while not stop_flag_{prefix}:
                    try:
                        # This simple attribute access will be heavily optimized.
                        _ = target.attr + 1
                    except:
                        pass # Ignore TypeErrors if the attribute is changed.
                print("[{prefix}] Hammer thread stopping.", file=stderr)

            # Thread 2: The "Invalidator"
            # This thread creates a race condition by modifying the attribute
            # that the hammer thread depends on.
            def invalidator_thread_{prefix}():
                print("[{prefix}] Invalidator thread starting...", file=stderr)
                while not stop_flag_{prefix}:
                    JITTarget_{prefix}.attr = randint(1, 1000)
                    time.sleep(0.00001) # Sleep briefly to yield control.
                print("[{prefix}] Invalidator thread stopping.", file=stderr)
        """)

        # --- Generate the main execution logic that runs the threads ---
        execution_str = dedent(f"""
            # Create and start the competing threads.
            hammer = Thread(target=hammer_thread_{prefix})
            invalidator = Thread(target=invalidator_thread_{prefix})
            hammer.start()
            invalidator.start()

            # Let the race condition run for a moment.
            time.sleep(0.1)
            
            # Signal threads to stop and wait for them to finish.
            stop_flag_{prefix} = True
            hammer.join()
            invalidator.join()
        """)

        # 2. Assemble the final code block.
        final_code = f"""
{header_print}

{setup_and_threads_str}

# Main execution logic to run and manage the threads.
{execution_str}

{footer_print}

"""
        # 3. Return the entire assembled block.
        return final_code

    def _generate_side_exit_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates a scenario to stress the JIT's deoptimization guards.

        This method creates a hot loop with a guard condition (`if random() ...`)
        that is designed to fail unpredictably. The JIT will heavily optimize
        the main path, and a failure of the guard forces a "side exit" from
        the optimized code. The scenario also changes a variable's type in the
        side-exit path to further stress the deoptimization mechanism.
        """
        # 1. Generate the component code blocks as strings.
        target_var = f"side_exit_var_{prefix}"

        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Frequent Side Exit Scenario <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Frequent Side Exit Scenario >>>"',
            return_str=True
        )

        hot_loop_header_str = self._begin_hot_loop(prefix)
        # Generate the main hot loop body as a single, readable block.
        # This contains the core logic of the scenario.
        hot_loop_body = dedent(f"""
            # This guard is designed to fail unpredictably (10% chance).
            if random() < 0.1:
                # Inside the failing guard, change the variable's type.
                print(f"[{prefix}] Side exit triggered! Changing variable type.", file=stderr)
                {target_var} = 'corrupted-by-side-exit'

            # This operation is optimized assuming the variable is an int.
            try:
                _ = {target_var} + 1
            except TypeError:
                # After a side exit causes a TypeError, we must reset
                # the variable's type so the loop can become hot again.
                # This allows us to trigger the side exit multiple times.
                {target_var} = i_{prefix}
        """)

        # 2. Assemble the final code block using a multi-line f-string.
        final_code = CT("""
{header_print}

# Initialize a variable with a known, stable type.
{target_var} = 0

# Start the hot loop that will be JIT-compiled.
{hot_loop_header_str}
    {hot_loop_body}

{footer_print}

""")
        # 3. Return the entire assembled block.
        return final_code.render(**locals())

    def _generate_isinstance_attack_scenario(self, prefix: str, target: dict) -> str:
        """
        Generates a grey-box attack on the JIT's `isinstance` elimination.

        This scenario creates a deep inheritance hierarchy and a class whose
        metaclass's `__instancecheck__` method can be monkey-patched. In a
        hot loop, it calls `isinstance` repeatedly, then triggers a `__del__`
        side effect to perform the patch, which injects a call to the fuzzed
        target. This tests for vulnerabilities in the JIT's type-checking
        optimizations.
        """
        # 1. Generate the component code blocks as strings.

        # --- Logging and setup strings ---
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Upgraded `isinstance` Attack targeting {target["name"]} <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished `isinstance` Attack Scenario >>>"',
            return_str=True
        )

        # --- Generate the complex setup code as a single block ---
        # This block defines all the necessary classes and functions for the attack.
        inheritance_depth = randint(100, 500)
        trigger_iteration = self.options.jit_loop_iterations // 2

        # The fuzzed call is now safely guarded inside the __instancecheck__ patch.
        fuzzed_call_str = self._generate_guarded_call(f"{target['call_str']}()")
        guarded_setup_code = ""
        if target["setup_code"]:
            guarded_setup_code = self._generate_guarded_call(target['setup_code'])

        setup_str = CT(dedent("""
            # 1. Define the components for the attack.
            from abc import ABCMeta
            
            # Define the metaclass that we will later modify.
            class EditableMeta_{prefix}(ABCMeta):
                instance_counter = 0
            
            # Create a deep inheritance tree of depth {inheritance_depth}.
            class Base_{prefix}(metaclass=EditableMeta_{prefix}): pass
            last_class_{prefix} = Base_{prefix}
            for _ in range({inheritance_depth}):
                class ClassStepDeeper(last_class_{prefix}): pass
                last_class_{prefix} = ClassStepDeeper
            
            class EditableClass_{prefix}(last_class_{prefix}): pass
            
            # Define the __instancecheck__ method that we will inject later.
            # It now safely calls the fuzzed target.
            def new__instancecheck_{prefix}(self, other):
                print("  [+] Patched __instancecheck__ called!", file=stderr)
                {guarded_setup_code}
                {fuzzed_call_str}
                return True
            
            # Define the Deletable class with the __del__ payload.
            class Deletable_{prefix}:
                def __del__(self):
                    try:
                        print("  [+] __del__ triggered! Patching __instancecheck__ onto metaclass.", file=stderr)
                        EditableMeta_{prefix}.__instancecheck__ = new__instancecheck_{prefix}
                    except Exception:
                        pass
            
            # Arm the trigger and create objects for checking.
            trigger_obj_{prefix} = Deletable_{prefix}()
            objects_to_check_{prefix} = [1, 'a_string', 3.14, Base_{prefix}()]
        """)).render(**locals())

        # --- Generate the hot loop using our helper ---
        hot_loop_str = self._begin_hot_loop(prefix)

        # 2. Assemble the final code block using a multi-line f-string.
        final_code = f"""
{header_print}

{setup_str}

# 2. Run the hot loop to bait, trigger, and trap the JIT.
{hot_loop_str}
    # The Bait: This check has a polymorphic target.
    target_obj = objects_to_check_{prefix}[i_{prefix} % len(objects_to_check_{prefix})]
    is_instance_result = isinstance(target_obj, EditableClass_{prefix})

    # The Trigger: Halfway through, delete the object to fire __del__.
    if i_{prefix} == {trigger_iteration}:
        print("[{prefix}] Deleting trigger object...", file=stderr)
        del trigger_obj_{prefix}
        collect()

    # The Trap: Log the result around the trigger point to observe the change.
    if i_{prefix} > {trigger_iteration} - 5 and i_{prefix} < {trigger_iteration} + 5:
        print(f"[{prefix}][Iter {{i_{prefix}}}] `isinstance(...)` is now: {{is_instance_result}}", file=stderr)

{footer_print}

"""
        # 3. Return the entire assembled block.
        return final_code

    def _generate_jit_pattern_block_with_check(self, prefix: str, target: dict) -> str:
        """Delegates to the unified engine with the 'jit_friendly_math' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'jit_friendly_math',
                                                           BUG_PATTERNS['jit_friendly_math'], {})

    def _generate_evil_jit_pattern_block_with_check(self, prefix: str, target: dict) -> str:
        """Prepares evil constants and delegates to the unified engine."""
        extra_mutations = {
            'val_a': self.arg_generator.genInterestingValues()[0],
            'val_b': self.arg_generator.genInterestingValues()[0],
            'val_c': self.arg_generator.genInterestingValues()[0],
            'str_d': self.arg_generator.genString()[0],
        }
        return self._generate_paired_ast_mutation_scenario(prefix, 'evil_boundary_math',
                                                           BUG_PATTERNS['evil_boundary_math'], extra_mutations)

    def _generate_deleter_scenario_with_check(self, prefix: str, target: dict) -> str:
        """Delegates to the unified engine with the 'deleter_side_effect' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'deleter_side_effect',
                                                           BUG_PATTERNS['deleter_side_effect'], {})

    def _generate_deep_calls_scenario_with_check(self, prefix: str, target: dict) -> str:
        """Prepares deep call setup and delegates to the unified engine."""
        mutations = self._get_mutations_for_deep_calls(prefix, {}, target, is_evil=False)
        return self._generate_paired_ast_mutation_scenario(prefix, 'deep_calls_correctness',
                                                           BUG_PATTERNS['deep_calls_correctness'], mutations)

    def _generate_evil_deep_calls_scenario_with_check(self, prefix: str, target: dict) -> str:
        """Prepares evil deep call setup and delegates to the unified engine."""
        mutations = self._get_mutations_for_deep_calls(prefix, {}, target, is_evil=True)
        return self._generate_paired_ast_mutation_scenario(prefix, 'evil_deep_calls_correctness',
                                                           BUG_PATTERNS['evil_deep_calls_correctness'], mutations)

    def _generate_inplace_add_attack_scenario_with_check(self, prefix: str, target: dict) -> str:
        """Delegates to the unified engine with the 'inplace_add_attack' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'inplace_add_attack',
                                                           BUG_PATTERNS['inplace_add_attack'], {})

    def _generate_global_invalidation_scenario_with_check(self, prefix: str, target: dict) -> str:
        """Delegates to the unified engine with the 'global_invalidation' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'global_invalidation',
                                                           BUG_PATTERNS['global_invalidation'], {})

    def _generate_managed_dict_attack_scenario_with_check(self, prefix: str, target: dict) -> str:
        """Delegates to the unified engine with the 'managed_dict_attack' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'managed_dict_attack',
                                                           BUG_PATTERNS['managed_dict_attack'], {})

    def _generate_decref_escapes_scenario(self, prefix: str, target: dict) -> str:
        """
        (Legacy Mode) Generates the specific, hard-coded scenario to reproduce
        the crash from CPython bug GH-124483 (test_decref_escapes).

        This method is preserved as a targeted regression test. It creates the
        minimal `FrameModifier` class and loop structure known to trigger the
        original bug.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting `test_decref_escapes` Re-discovery Scenario <<<"', return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished `test_decref_escapes` Re-discovery Scenario >>>"', return_str=True
        )

        loop_var = f"i_{prefix}"
        loop_iterations = 500
        trigger_iteration = loop_iterations - 2

        # --- Generate the FrameModifier class definition ---
        # This is the minimal version with no __init__ that we discovered was necessary.
        frame_modifier_def = dedent(f"""
            class FrameModifier_{prefix}:
                def __del__(self):
                    try:
                        frame = sys._getframe(1)
                        # Hardcoded check for the trigger iteration
                        if frame.f_locals.get('{loop_var}') == {trigger_iteration}:
                            print("  [Side Effect] Triggered! Modifying `{loop_var}` to None", file=stderr)
                            frame.f_locals['{loop_var}'] = None
                    except Exception:
                        pass
        """)

        # --- Generate the harness function that contains the attack ---
        harness_func_name = f"harness_{prefix}"
        harness_def_str = dedent(f"""
            def {harness_func_name}():
                # The hot loop
                try:
                    for {loop_var} in range({loop_iterations}):
                        # Instantiate and destroy the FrameModifier on EACH iteration.
                        FrameModifier_{prefix}()
                        # Perform the operation that gets optimized.
                        _ = {loop_var} + {loop_var}
                except Exception:
                    # Catch potential TypeErrors after the corruption.
                    pass
        """)

        # 2. Assemble the final code block.
        final_code = f"""
{header_print}

# 1. Define the minimal FrameModifier class.
{frame_modifier_def}

# 2. Define the main function harness containing the attack logic.
{harness_def_str}

# 3. Execute the test harness.
{self._generate_guarded_call(f'{harness_func_name}()')}

{footer_print}

"""
        # 3. Return the entire assembled block.
        return final_code

    def _generate_variational_scenario(self, prefix: str, pattern_names: str, target: dict) -> str:
        """
        Acts as the master dispatcher for all pattern-based fuzzing.

        This method orchestrates the full lifecycle of generating a test from
        the bug_patterns.py library. Its responsibilities include:
        1.  Selecting a pattern from the library.
        2.  Reading the pattern's metadata 'tags' to understand its requirements.
        3.  Calling the appropriate specialized mutation helpers (e.g.,
            _get_mutations_for_many_vars) based on the pattern's tags.
        4.  Injecting the unified 'target' callable's information into the
            mutation dictionary.
        5.  Dispatching to either the crash-test generator or the "Twin
            Execution" correctness-test generator based on the pattern's tags.
        """
        # --- 1. Pattern Selection ---
        if pattern_names == "ALL":
            all_patterns = list(BUG_PATTERNS.keys())
            pattern_name = choice(all_patterns)
        else:
            pattern_name = choice(pattern_names.split(","))

        pattern = BUG_PATTERNS.get(pattern_name)
        if not pattern:
            self.write_print_to_stderr(0, f'"[!] Unknown bug pattern name: {pattern_name}"')
            return

        tags = pattern.get('tags', {'standard'})
        has_payload_placeholder = '{corruption_payload}' in pattern['setup_code'] or \
                                  '{corruption_payload}' in pattern['body_code']

        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Fuzzing Pattern: {pattern_name} (Tags: {", ".join(tags)}) <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Fuzzing Pattern: {pattern_name} >>>"',
            return_str=True
        )

        final_code_blocks = [header_print]

        # --- 2. Dispatch to Generation Strategy ---

        # --- STRATEGY: Systematic Value Iteration ---
        if self.options.jit_fuzz_systematic_values and has_payload_placeholder:
            iter_header = self.parent.write_print_to_stderr(0,
                                                            f'"[{prefix}] Core Strategy: Systematic Value Iteration"',
                                                            return_str=True)
            final_code_blocks.append(iter_header)

            for i, payload in enumerate(fusil.python.values.INTERESTING):
                iter_prefix = f"{prefix}_{i}"
                mutations = self._get_mutated_values_for_pattern(iter_prefix, [])
                mutations['corruption_payload'] = payload

                setup_code = dedent(pattern['setup_code']).format(**mutations)
                body_code = dedent(pattern['body_code']).format(**mutations)

                iter_print = self.parent.write_print_to_stderr(0,
                                                               f'"""--- Iteration {i}: Corrupting with payload = {payload} ---"""',
                                                               return_str=True)
                pattern_block = self.write_pattern(setup_code, body_code, return_str=True)
                final_code_blocks.extend([iter_print, pattern_block])

        # --- STRATEGY: Type-Aware Iteration ---
        elif self.options.jit_fuzz_type_aware and has_payload_placeholder:
            iter_header = self.parent.write_print_to_stderr(0, f'"[{prefix}] Core Strategy: Type-Aware Iteration"',
                                                            return_str=True)
            final_code_blocks.append(iter_header)

            original_type = pattern.get('payload_variable_type')
            if not original_type:
                error_print = self.parent.write_print_to_stderr(0,
                                                                f'"[!] Pattern {pattern_name} is missing "payload_variable_type" metadata."',
                                                                return_str=True)
                final_code_blocks.append(error_print)
            else:
                type_generators = {
                    'str': self.arg_generator.genString,
                    'bytes': self.arg_generator.genBytes,
                    'float': self.arg_generator.genFloat,
                    'list': self.arg_generator.genList,
                    'NoneType': lambda: ['None'],
                    'tricky': self.arg_generator.genTrickyObjects,
                }
                if original_type in type_generators: del type_generators[original_type]

                for type_name, generator_func in type_generators.items():
                    iter_prefix = f"{prefix}_{type_name}"
                    payload_str = " ".join(generator_func())
                    mutations = self._get_mutated_values_for_pattern(iter_prefix, [])
                    mutations['corruption_payload'] = payload_str

                    setup_code = dedent(pattern['setup_code']).format(**mutations)
                    body_code = dedent(pattern['body_code']).format(**mutations)

                    iter_print = self.parent.write_print_to_stderr(0,
                                                                   f'"""--- Corrupting with type {type_name}: Payload = {payload_str} ---"""',
                                                                   return_str=True)
                    pattern_block = self.write_pattern(setup_code, body_code, return_str=True)
                    final_code_blocks.extend([iter_print, pattern_block])

        # --- STRATEGY: Default Single-Shot (AST or Random) ---
        else:
            # --- 2. ALWAYS Generate Base and Parameter Mutations First ---
            params = self._generate_mutated_parameters(prefix, target)
            mutations = self._get_mutated_values_for_pattern(prefix, params['param_names'])
            mutations.update(params)

            # --- 3. Dispatch to Specialized Helpers to ADD or OVERWRITE mutations ---
            if 'needs-many-vars-setup' in tags:
                # The helper now receives the base 'mutations' dict to modify.
                mutations = self._get_mutations_for_many_vars(prefix, mutations)
            elif 'needs-evil-deep-calls-setup' in tags:
                mutations = self._get_mutations_for_deep_calls(prefix, mutations, target, is_evil=True)
            elif 'needs-deep-calls-setup' in tags:
                mutations = self._get_mutations_for_deep_calls(prefix, mutations, target, is_evil=False)
            elif 'needs-evil-math-setup' in tags:
                mutations = self._get_mutations_for_evil_math(prefix, mutations)
            else:  # Default path
                params = self._generate_mutated_parameters(prefix, target)
                mutations = self._get_mutated_values_for_pattern(prefix, params['param_names'])
                mutations.update(params)

            mutations['fuzzed_func_name'] = target['name']
            mutations['fuzzed_func_setup'] = target['setup_code']
            mutations['fuzzed_func_call'] = target['call_str']

            setup_code = pattern['setup_code'].format(**mutations)
            body_code = pattern['body_code'].format(**mutations)

            if self.options.jit_fuzz_ast_mutation:
                body_code = self.ast_mutator.mutate(body_code)

            env_code = self._write_mutated_code_in_environment(prefix, setup_code, body_code, mutations)
            final_code_blocks.append(env_code)

        final_code_blocks.append(footer_print)

        # 3. Return the entire assembled code.
        return "\n\n".join(final_code_blocks)

    def _get_mutations_for_many_vars(self, prefix: str, mutations: dict) -> dict:
        """
        Receives a base mutation dictionary and adds keys specific to the
        'many-vars' pattern, including the `{var_definitions}` placeholder
        and a complex `{expression}` that uses the new variables.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] Using specialized generator: many_vars"')

        num_vars = 260
        var_names = [f"var_{i}_{prefix}" for i in range(num_vars)]
        mutations['var_definitions'] = "\n".join([f"{name} = {i}" for i, name in enumerate(var_names)])

        # Regenerate the expression to use these new variables.
        expression_ast = self._generate_expression_ast(available_vars=var_names)
        try:
            mutations['expression'] = ast.unparse(expression_ast)
        except AttributeError:
            mutations['expression'] = "# AST unparsing failed"

        return mutations  # Return the modified dictionary

    def _get_mutations_for_evil_math(self, prefix: str, mutations: dict) -> dict:
        """
        Receives a base mutation dictionary and adds keys specific to the
        'evil_boundary_math' pattern.

        This helper generates several "interesting" boundary values (like NaN,
        inf, maxint) and injects them into the mutation dictionary for use in
        the pattern's setup code.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] Using specialized generator: evil_math"')
        mutations.update({
            'val_a': self.arg_generator.genInterestingValues()[0],
            'val_b': self.arg_generator.genInterestingValues()[0],
            'val_c': self.arg_generator.genInterestingValues()[0],
            'str_d': self.arg_generator.genString()[0],
        })
        return mutations

    def _get_mutations_for_deep_calls(self, prefix: str, mutations: dict, target: dict, is_evil: bool = False) -> dict:
        """
        Receives a base mutation dictionary and adds keys specific to
        'deep-calls' patterns.

        This helper programmatically generates a string containing a chain of
        deeply nested function definitions (`{function_chain}`) and injects
        it into the mutation dictionary for use in the pattern's setup code.
        The 'evil' version incorporates more complex logic into each frame.
        """
        generator_name = "evil_deep_calls" if is_evil else "deep_calls"
        self.write_print_to_stderr(0, f'"[{prefix}] Using specialized generator: {generator_name}"')

        depth = 15
        func_chain_lines = []

        # Build the string for the function chain that will be injected into the setup_code.

        # First, define the base case (the deepest function)
        base_case_body = ""
        if is_evil:
            # The "evil" version has more complex logic and calls the target.
            base_case_body = dedent(f"""
                res = list(p_tuple)
                try:
                    op = OPERATOR_SUITE[0]
                    const = CONSTANTS[0]
                    res[0] = op(res[0], const)
                    # Use the provided target's call string here
                    {target['call_str']}()
                except Exception:
                    pass
                return tuple(res)
            """)
        else:
            # The standard version is a simple recursive addition.
            base_case_body = "return p + 1"

        param_name = 'p_tuple' if is_evil else 'p'
        base_case_def = CT("def f_0_{prefix}({param_name}):\n    {base_case_body}").render(**locals())
        func_chain_lines.append(dedent(base_case_def))

        # Now, generate the intermediate functions in the chain.
        for i in range(1, depth):
            func_name = f"f_{i}_{prefix}"
            prev_func_name = f"f_{i - 1}_{prefix}"

            if is_evil:
                func_body = dedent(f"""
                    res = list(p_tuple)
                    try:
                        op = OPERATOR_SUITE[{i % 4}]
                        const = CONSTANTS[{i % 4}]
                        res[1] = op(res[1], const)
                        if {i} == EXCEPTION_LEVEL: raise ValueError(('evil_deep_call_probe',))
                        return {prev_func_name}(tuple(res))
                    except Exception:
                        return p_tuple
                """)
                func_def = CT("def {func_name}(p_tuple):\n    {func_body}").render(**locals())
            else:
                func_def = f"def {func_name}(p): return {prev_func_name}(p) + 1"

            func_chain_lines.append(dedent(func_def))

        # Update the mutations dictionary with all the special keys needed by these patterns.
        mutations.update({
            'function_chain': "\n".join(func_chain_lines),
            'depth': depth,
            'depth_minus_1': depth - 1,
        })

        if is_evil:
            mutations.update({
                'operator_suite': "['operator.add', 'operator.sub', 'operator.mul', 'operator.truediv']",
                'constants': [self.arg_generator.genInterestingValues()[0] for _ in range(4)],
                'exception_level': randint(5, 12),
            })

        return mutations

    def _get_mutated_values_for_pattern(self, prefix: str, param_names: list[str]) -> dict:
        """"
        Creates the base dictionary of randomized placeholders for a pattern.

        This is the standard mutation generator. It is responsible for creating
        the common placeholders used by most patterns, such as `{loop_var}`,
        `{expression}`, `{loop_iterations}`, and `{corruption_payload}`. It
        also includes necessary context like `{module_name}`.
        """
        # --- Hybrid Operator/Expression Mutation ---
        operator_pairs = [
            ('+', 'operator.add'), ('-', 'operator.sub'), ('*', 'operator.mul'),
            ('/', 'operator.truediv'), ('//', 'operator.floordiv'), ('%', 'operator.mod'),
            ('**', 'operator.pow'), ('<<', 'operator.lshift'), ('>>', 'operator.rshift'),
            ('&', 'operator.and_'), ('|', 'operator.or_'), ('^', 'operator.xor'),
            ('<', 'operator.lt'), ('<=', 'operator.le'), ('==', 'operator.eq'),
            ('!=', 'operator.ne'), ('>', 'operator.gt'), ('>=', 'operator.ge'),
        ]

        chosen_infix, chosen_func = choice(operator_pairs)
        loop_var = f"i_{prefix}"

        if random() < 0.4:
            expression_str = f"{loop_var} {chosen_infix} {loop_var}"
        elif random() < 0.8:
            # Use the AST generator, passing the available variables.
            available_vars = [loop_var] + param_names
            expression_ast = self._generate_expression_ast(available_vars=available_vars)
            try:
                expression_str = ast.unparse(expression_ast)
            except AttributeError:
                expression_str = f"{loop_var} # unparse failed"
        else:
            expression_str = f"{chosen_func}({loop_var}, {loop_var})"

        # --- Assemble the final dictionary ---
        return {
            'prefix': prefix,
            'loop_var': loop_var,
            'loop_iterations': randint(500, max(self.options.jit_loop_iterations, 550)),
            'trigger_iteration': randint(400, 498),
            'corruption_payload': self.arg_generator.genInterestingValues()[0],
            'expression': expression_str,
            'inheritance_depth': randint(50, 500),
            'warmup_calls': self.options.jit_loop_iterations // 10,
            # Always include module context for any pattern that might need it.
            'module_name': self.module_name,
        }

    def _write_mutated_code_in_environment(self, prefix: str, setup_code: str, body_code: str, params: dict = None,
                                           return_str: bool = False) -> str:
        """
        Wraps a generated block of code in a randomly chosen execution environment.

        This method takes the core logic of a test case and embeds it within
        one of several environmental templates (e.g., a top-level function, a
        nested function, a class method, an async function). This increases
        test diversity by changing the context in which the JIT analyzes the code.
        """
        if params is None:
            params = {'def_str': '', 'call_str': '', 'setup_code': ''}

        param_def = params['def_str']
        param_call = params['call_str']
        param_setup = params['setup_code']

        # First, get the guarded body of the harness function as a string.
        guarded_body = self.write_pattern(setup_code, body_code, return_str=True)

        # Choose an environment template.
        env_choice = randint(0, 5)

        # Assemble the final code block using the chosen template.
        final_code = ""
        if env_choice == 0:  # Top-Level Function
            final_code = CT(dedent("""
                def harness_{prefix}({param_def}):
                    {guarded_body}

                harness_{prefix}({param_call})
            """)).render(**locals())
        elif env_choice == 1:  # Nested Function
            final_code = CT(dedent("""
                def outer_{prefix}():
                    def harness_{prefix}({param_def}):
                        {guarded_body}
                    harness_{prefix}({param_call})

                outer_{prefix}()
            """)).render(**locals())
        elif env_choice == 2:  # Class Method
            method_param_def = f"self, {param_def}" if param_def else "self"
            final_code = CT(dedent("""
                class Runner_{prefix}:
                    def harness({method_param_def}):
                        {guarded_body}

                Runner_{prefix}().harness({param_call})
            """)).render(**locals())
        elif env_choice == 3:  # Async Function
            final_code = CT(dedent("""
                import asyncio
                async def harness_{prefix}({param_def}):
                    {guarded_body}

                asyncio.run(harness_{prefix}({param_call}))
            """)).render(**locals())
        elif env_choice == 4:  # Generator Function
            generator_body = f"{guarded_body}\n    yield"
            final_code = CT(dedent("""
                def harness_{prefix}({param_def}):
                    {generator_body}

                # Consume the generator for its code to execute.
                for _ in harness_{prefix}({param_call}):
                    pass
            """)).render(**locals())
        else:  # Lambda-called Function
            final_code = CT(dedent("""
                def harness_{prefix}({param_def}):
                    {guarded_body}

                caller = lambda: harness_{prefix}({param_call})
                caller()
            """)).render(**locals())

        # Prepend any parameter setup code.
        if param_setup:
            final_code = f"{param_setup}\n{final_code}\n"

        return final_code

    def write_pattern(self, setup_code: str, body_code: str, level: int = 0, return_str: bool = False) -> str:
        """
        Takes setup and body code and wraps it in a robust try...except block.

        This is a low-level helper that provides the primary safety harness for
        all generated test cases. It ensures that benign runtime exceptions are
        caught and ignored, while our specific `JITCorrectnessError` signal is
        allowed to propagate.
        """
        # Assemble the final try...except structure as a single f-string.
        final_code_block = CT(dedent("""
            try:
            # setup_code
                {setup_code}
            
            # body_code
                {body_code}
            except JITCorrectnessError:
                raise
            except (Exception, SystemExit):
                pass
        """)).render(**locals())

        if return_str:
            return final_code_block

        # Write the assembled block to the output at the specified level.
        self.write_block(level, final_code_block)
        return ""

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

    def _generate_mutated_parameters(self, prefix: str, target: dict) -> dict:
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
            raise ValueError(f"Function named {func_name_prefix}... not found in {code=}.")
        except (SyntaxError, AttributeError) as e:
            print(f"{e.__class__.__name__}: {e}")
            print(f"{code=}")
            return ""
        return ""

    def _generate_guarded_call(self, call_str: str) -> str:
        """
        Wraps a string representing a function call in a robust try...except
        block and returns the complete block as a string.
        """
        return CT(dedent("""
            try:
                {call_str}
            except Exception:
                pass
        """)).render(**locals())

    def _begin_hot_loop(self, prefix: str) -> str:
        """
        Returns the standard boilerplate for a JIT-warming hot loop as a string.
        """
        loop_var = f"i_{prefix}"
        loop_iterations = self.options.jit_loop_iterations

        return f"for {loop_var} in range({loop_iterations}):\n"

    def _generate_paired_ast_mutation_scenario(self, prefix: str, pattern_name: str, pattern: dict, mutations: dict) -> str:
        """
        The unified engine for all 'body-based' correctness-checking patterns.

        This method orchestrates the entire "Twin Execution" model. It takes a
        pattern's core logic, uses a seeded AST mutation to create two
        identical but mutated versions, wraps them in `jit_target` and
        `control` functions, and generates the harness code to run both and
        compare their results.
        """
        # 1. Generate the component code blocks as strings.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> JIT Correctness Scenario: {pattern_name} <<<"',
            return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario ({pattern_name}) Passed >>>"',
            return_str=True
        )

        # Get setup code for the target callable (e.g., class instantiation).
        target_setup_str, _ = self._write_target_setup(prefix, mutations)

        # Get setup code from the pattern itself.
        pattern_setup_str = dedent(pattern['setup_code']).format(**mutations)

        # Get the core logic from the pattern's body and mutate it.
        initial_body_code = dedent(pattern['body_code']).format(**mutations)
        mutation_seed = randint(0, 2**32 - 1)
        mutated_code = self.ast_mutator.mutate(initial_body_code, seed=mutation_seed)
        if not mutated_code.strip():
            mutated_code = "pass"

        # --- Generate the JIT and Control function definitions as strings ---
        param_def = pattern.get('param_def', "")
        jit_func_name = f"jit_target_{prefix}"
        control_func_name = f"control_{prefix}"

        jit_func_def = CT(dedent("""\
            def {jit_func_name}({param_def}):
                {mutated_code}
            """)).render(**locals())

        control_func_def = CT(dedent("""\
            def {control_func_name}({param_def}):
                {mutated_code}
            """)).render(**locals())

        # --- Generate the harness logic as a string ---
        param_call = mutations.get('param_call', pattern.get('param_call', ""))
        harness_str = dedent(f"""
            # 1. Warm up the JIT target function so it gets compiled.
            jit_harness({jit_func_name}, {self.options.jit_loop_iterations}, {param_call})

            # 2. Get the final result from both versions.
            jit_result = {jit_func_name}({param_call})
            control_result = no_jit_harness({control_func_name}, {param_call})

            # 3. The crucial assertion.
            if not compare_results(jit_result, control_result):
                raise JITCorrectnessError(f"JIT CORRECTNESS BUG ({pattern_name})! JIT: {{jit_result}}, Control: {{control_result}}")
        """)

        guarded_harness_str = self._generate_guarded_call(harness_str)

        # 2. Assemble the final code block using a single, large f-string.
        final_code = f"""
{header_print}

# Define a custom exception for our correctness check.
class JITCorrectnessError(AssertionError): pass

# Run all setup code.
{target_setup_str}
{pattern_setup_str}

# Define the JIT and Control functions with identical (mutated) logic.
{jit_func_def}  

{control_func_def}

# Execute the 'Twin Execution' harness.
{guarded_harness_str}

{footer_print}

"""
        # 3. Return the entire assembled block.
        return final_code

    def _discover_and_filter_classes(self) -> list:
        """
        Scans the target module for classes and filters them to find ones
        that are suitable for automated instantiation and fuzzing.

        Returns:
            A list of class objects that can be safely fuzzed.
        """
        # If we have already discovered the classes, return the cached result.
        if self.fuzzable_classes is not None:
            return self.fuzzable_classes

        self.write_print_to_stderr(0, '"[+] Discovering and filtering classes for JIT fuzzing..."')

        discovered_classes = []
        if not self.parent.module_classes:
            self.fuzzable_classes = []
            return []

        for class_name in self.parent.module_classes:
            try:
                class_obj = getattr(self.parent.module, class_name)

                # --- Filtering Logic ---

                # Filter 1: Skip abstract base classes
                if inspect.isabstract(class_obj):
                    continue

                # Filter 2: Skip exceptions
                if isinstance(class_obj, type) and issubclass(class_obj, BaseException):
                    continue

                # Filter 3: Analyze the __init__ method for instantiability
                if hasattr(class_obj, '__init__'):
                    init_sig = inspect.signature(class_obj.__init__)
                    can_instantiate = True
                    for param in init_sig.parameters.values():
                        # Skip 'self' and other implicit parameters
                        if param.name in ('self', 'cls'):
                            continue
                        # If a parameter has no default value and is not *args or **kwargs,
                        # it's too hard to instantiate automatically for now.
                        if (param.default is inspect.Parameter.empty and
                                param.kind not in (inspect.Parameter.VAR_POSITIONAL,
                                                   inspect.Parameter.VAR_KEYWORD)):
                            can_instantiate = False
                            break

                    if not can_instantiate:
                        continue

                # If all filters passed, add the class object to our list.
                discovered_classes.append(class_obj)

            except (TypeError, ValueError, AttributeError):
                # Some objects can't be inspected easily; skip them.
                continue

        self.write_print_to_stderr(0, f'"[+] Found {len(discovered_classes)} fuzzable classes."')
        self.fuzzable_classes = discovered_classes
        return self.fuzzable_classes

    def _generate_args_for_method(self, method_obj: Any) -> str:
        """
        Inspects a method's signature and generates a string of plausible
        arguments for calling it. Implements a "mostly smart, sometimes chaotic"
        strategy to balance successful calls with JIT-stressing type confusion.

        Args:
            method_obj: The method object to be inspected.

        Returns:
            A string containing the arguments for the call (e.g., "'path/to/file', 100").
        """
        args_list = []
        try:
            sig = inspect.signature(method_obj)
            for param in sig.parameters.values():
                # Skip 'self', 'cls', *args, **kwargs
                if param.name in ('self', 'cls') or param.kind in (inspect.Parameter.VAR_POSITIONAL,
                                                                   inspect.Parameter.VAR_KEYWORD):
                    continue

                # With a small probability, inject a random "evil" value
                if random() < 0.1:
                    args_list.append(self.arg_generator.genInterestingValues()[0])
                    continue

                # --- "Smart" Generation based on parameter name ---
                # This is a simple heuristic-based approach.
                param_name = param.name.lower()
                if 'path' in param_name or 'file' in param_name or 'name' in param_name:
                    args_list.append(self.arg_generator.genString()[0])
                elif 'count' in param_name or 'index' in param_name or 'size' in param_name or 'len' in param_name:
                    args_list.append(self.arg_generator.genSmallUint()[0])
                elif 'flag' in param_name or 'enable' in param_name:
                    args_list.append(self.arg_generator.genBool()[0])
                else:
                    # Default to a simple integer if we have no better heuristic.
                    args_list.append(self.arg_generator.genInt()[0])

        except (TypeError, ValueError):
            # If signature inspection fails, fall back to generating a single random arg.
            args_list.append(self.arg_generator.genInterestingValues()[0])

        return ", ".join(map(str, args_list))

    def _generate_class_fuzzing_scenario(self, prefix: str) -> str:
        """
        Generates a scenario that stresses the JIT with method calls.

        This scenario discovers and filters suitable classes from the target
        module, safely instantiates one, and then calls one of its methods
        repeatedly in a JIT-warming hot loop. It uses a "smart" argument
        generator that generates plausible arguments for the method's
        signature most of the time, but occasionally injects "evil" values
        to test for type-confusion bugs.
        """
        # 1. Discover and select a target class.
        fuzzable_classes = self._discover_and_filter_classes()
        if not fuzzable_classes:
            return self.write_print_to_stderr(
                0, '"[-] No suitable classes found for JIT fuzzing in this module."', return_str=True
            )

        target_class = choice(fuzzable_classes)
        class_name = target_class.__name__

        # 2. Discover a suitable method on the class to call.
        methods = self.parent._get_object_methods(target_class, class_name)
        if not methods:
            return self.write_print_to_stderr(
                0, f'"[-] No suitable methods found on class {class_name}."', return_str=True
            )

        method_name = choice(list(methods.keys()))
        method_obj = methods[method_name]

        # 3. Generate the component code blocks as strings using our new helpers.

        # Create a dummy target dict for the setup helper.
        instance_var = f"instance_{prefix}"
        setup_target = {
            'instance_var': instance_var,
            'name': class_name,
            'setup_code': f"{instance_var} = {self.module_name}.{class_name}()"
        }
        setup_str, _ = self._write_target_setup(prefix, setup_target)

        # Get arguments and the guarded method call.
        args_str = self._generate_args_for_method(method_obj)
        call_str = self._generate_guarded_call(f"{instance_var}.{method_name}({args_str})")

        # Get the hot loop boilerplate.
        hot_loop_str = self._begin_hot_loop(prefix)

        # Get the header and footer prints.
        header_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Class Fuzzing for: {class_name} <<<"', return_str=True
        )
        target_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] Targeting method: {class_name}.{method_name}"', return_str=True
        )
        footer_print = self.parent.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished JIT Class Fuzzing for: {class_name} >>>"', return_str=True
        )

        # 4. Assemble the final code block using a multi-line f-string.
        final_code = f"""
{header_print}

# Safely instantiate the target class.
{setup_str}

# If instantiation was successful, proceed to fuzz the method.
if {instance_var}:
    {target_print}
    
    # Generate the JIT-warming hot loop.
    {hot_loop_str}
        # Call the method inside the loop.
        {call_str}

{footer_print}

"""
        # 5. Return the entire assembled block.
        return final_code

    def _select_fuzzing_target(self, prefix: str) -> dict:
        """
        Selects a callable to be used as the "payload" for a JIT scenario.

        This method probabilistically chooses between a simple module-level
        function and a method from a class instance. It returns a unified

        dictionary describing the chosen target, abstracting away the
        difference between a function and a method for the scenario
        generators that consume it.
        """
        if self.parent.module_classes and random() < 0.2:
            fuzzable_classes = self._discover_and_filter_classes()
            if fuzzable_classes:
                target_class = choice(fuzzable_classes)
                methods = self.parent._get_object_methods(target_class, target_class.__name__)
                if methods:
                    method_name = choice(list(methods.keys()))
                    instance_var = f"target_instance_{prefix}"  # Define the name here

                    return {
                        'type': 'method',
                        'name': f"{target_class.__name__}.{method_name}",
                        'instance_var': instance_var,  # <-- NEW: Add to dictionary
                        'setup_code': f"{instance_var} = {self.module_name}.{target_class.__name__}()",
                        'call_str': f"{instance_var}.{method_name}",
                    }

        # Fallback to module-level functions remains the same
        if self.parent.module_functions:
            func_name = choice(self.parent.module_functions)
            return {
                'type': 'function',
                'name': func_name,
                'instance_var': None,  # No instance for functions
                'setup_code': "",
                'call_str': f"{self.module_name}.{func_name}",
            }
        return {}

    def _write_target_setup(self, prefix: str, target: dict) -> tuple[str, str | None]:
        """
        Safely generates the setup code for a fuzzing target.

        It takes a target dictionary, pre-initializes the instance variable
        to None, and wraps the instantiation code (from target['setup_code'])
        in a try...except block. It returns the generated code as a string.
        """
        instance_var = target.get('instance_var')
        setup_code = target.get('setup_code')

        if not instance_var or not setup_code:
            return "", None

        # Generate the full, guarded instantiation block as a string.
        code = dedent(f"""
            # Safely instantiate the target for this scenario.
            {instance_var} = None
            try:
                {setup_code}
            except Exception as e:
                print(f"[-] NOTE: Instantiation failed for {target['name']}: {{e.__class__.__name__}}", file=stderr)
        """)
        return code, instance_var

