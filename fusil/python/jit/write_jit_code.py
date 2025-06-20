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
        self.write = parent.write
        self.addLevel = parent.addLevel
        self.restoreLevel = parent.restoreLevel
        self.emptyLine = parent.emptyLine
        self.write_print_to_stderr = parent.write_print_to_stderr

        self.jit_warmed_targets = []
        self.fuzzable_classes = None

    def generate_scenario(self, prefix: str) -> None:
        """
        (Final Version)
        Main entry point for all JIT scenario generation.
        It selects a target (function or method) and then dispatches to the
        appropriate generation engine based on the --jit-mode flag.
        """
        # 1. Select a target to be fuzzed. This can be a function or a method.
        target = self._select_fuzzing_target(prefix)
        if not target:
            self.write_print_to_stderr(0, '"[-] No suitable functions or methods found to fuzz."')
            return

        # 2. Dispatch to the main generation logic based on the chosen mode.
        mode = self.options.jit_mode

        # This helper is now only used for `--jit-mode=all`
        if mode == 'all':
            self._execute_randomized_strategy(prefix, target)

        elif mode == 'synthesize':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: AST Pattern Synthesis"')
            body_code = self.ast_pattern_generator.generate_pattern()
            params = self._generate_mutated_parameters(prefix, target)
            self._write_mutated_code_in_environment(prefix, "", body_code, params)

        elif mode == 'variational':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Variational Pattern Fuzzing"')
            self._generate_variational_scenario(prefix, self.options.jit_pattern_name, target)

        elif mode == 'legacy':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Legacy Scenario Generation"')
            self._generate_legacy_scenario(prefix, target)

    def _execute_randomized_strategy(self, prefix: str, target: dict) -> None:
        """
        Called by --jit-mode=all. It now includes class fuzzing in its
        pool of random choices.
        """
        chosen_mode = choice(['synthesize', 'variational', 'legacy'])
        self.write_print_to_stderr(0, f'"[{prefix}] JIT-MODE=ALL: Randomly selected mode: {chosen_mode}"')

        # Store original values and set temporary random ones
        flags_to_modify = [
            "jit_fuzz_ast_mutation", "jit_wrap_statements"
        ]
        original_flag_values = {flag: getattr(self.options, flag) for flag in flags_to_modify}
        for flag in flags_to_modify:
            setattr(self.options, flag, choice([True, False]))

        # Dispatch to the chosen mode's logic
        if chosen_mode == 'synthesize':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: AST Pattern Synthesis"')
            body_code = self.ast_pattern_generator.generate_pattern()
            params = self._generate_mutated_parameters(prefix, target)
            self._write_mutated_code_in_environment(prefix, "", body_code, params)
        elif chosen_mode == 'variational':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Variational Pattern Fuzzing"')
            self._generate_variational_scenario(prefix, 'ALL', target)
        elif chosen_mode == 'legacy':
            self.write_print_to_stderr(0, f'"[{prefix}] STRATEGY: Legacy Scenario Generation"')
            self._generate_legacy_scenario(prefix, target)

        # Restore original flag values
        for flag, value in original_flag_values.items():
            setattr(self.options, flag, value)

    def _generate_legacy_scenario(self, prefix: str, target: dict) -> None:
        """
        Executes the original "legacy" fuzzing logic. It chooses between
        correctness, hostile, or friendly scenarios based on the original
        set of command-line flags. This is preserved for regression testing.
        """
        # Handle specific re-discovery flag ---
        if self.options.rediscover_decref_crash:
            self.write_print_to_stderr(0, f'"[{prefix}] LEGACY MODE: Generating Re-discovery Scenario"')
            self._generate_decref_escapes_scenario(prefix, target)
            return

        # 1. First, check if we should run a correctness test.
        if self.options.jit_correctness_testing and random() < self.options.jit_correctness_prob:
            self.write_print_to_stderr(0, f'"[{prefix}] LEGACY MODE: Generating Correctness Scenario"')
            # We can pick a random correctness pattern to run here.
            corr_pattern = choice(list(BUG_PATTERNS.keys()))
            self._generate_paired_ast_mutation_scenario(prefix, corr_pattern, BUG_PATTERNS[corr_pattern], {})
            return

        # Decide whether to generate a hostile scenario.
        hostile_prob = self.options.jit_hostile_prob
        if random() < hostile_prob:
            self.write_print_to_stderr(0, f'"[{prefix}] LEGACY MODE: Generating Hostile Scenario"')
            self._generate_hostile_scenario(prefix, target)
        else:
            self.write_print_to_stderr(0, f'"[{prefix}] LEGACY MODE: Generating Friendly Scenario"')
            self._generate_friendly_scenario(prefix, target)

    def _generate_correctness_scenario(self, prefix: str, target: dict) -> None:
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
        chosen(prefix, target)

    def _generate_hostile_scenario(self, prefix: str, target: dict) -> None:
        """
        (This method is preserved for legacy mode)
        Chooses and generates one of the hostile (crash-finding) scenarios.
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
        chosen_generator(prefix, target)

    def _generate_friendly_scenario(self, prefix: str, target: dict) -> None:
        """
        (This method is now simplified for legacy mode)
        Chooses and generates one of the JIT-friendly (warm-up) scenarios.
        """
        if random() < 0.0:
            # Use the simple polymorphic call block.
            self._generate_polymorphic_call_block(prefix, target)
        else:
            # Use the JIT pattern block, which is now powered by the variational engine.
            self._generate_jit_pattern_block(prefix, target)

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

    def _generate_jit_pattern_block(self, prefix: str, target: dict) -> None:
        """
        Generates a friendly block of code by feeding a general-purpose
        pattern into our advanced variational/AST mutation engine.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] Generating friendly JIT patterns via variational engine."'
        )
        # We now treat the "friendly" scenario as just another variational pattern.
        # This ensures even our simplest mode is powerful and diverse.
        # (This assumes a 'friendly_base' pattern is added to bug_patterns.py)
        self._generate_variational_scenario(prefix, 'friendly_base', target)

    def _generate_polymorphic_call_block(self, prefix: str, target: dict) -> None:
        """
        Generates a hot loop with calls to one function using args of different types.
        This is now simplified using the hot loop helper.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] Generating polymorphic call block for: {target["name"]}"'
        )

        # Write the setup code for the target (e.g., instantiating the class).
        self._write_target_setup(prefix, target)

        # Warm up with one simple call.
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"{target['call_str']}(1)")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception: pass")
        self.emptyLine()

        base_level = self.parent.base_level
        # Use the hot loop helper
        self._begin_hot_loop(prefix)
        self.addLevel(1)

        # Inside the loop, call the target with different typed args
        poly_gens = [self.arg_generator.genInt, self.arg_generator.genString, self.arg_generator.genList]
        for gen_func in poly_gens:
            arg_str = " ".join(gen_func())
            self.write(1, f"try: {target['call_str']}({arg_str})")
            self.write(1, "except Exception: pass")

        # Cleanly exit all levels opened by the helper
        self.restoreLevel(base_level)
        if self.options.jit_raise_exceptions:
            # Add the matching 'except' block for the 'try' in the helper
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)

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
        self.write(0, f"{instance_var} = callFunc('{prefix}_init', '{class_name}')")

        # Use the new helper to create the loop structure
        self.write(0, f"if {instance_var} is not None and {instance_var} is not SENTINEL_VALUE:")
        self.addLevel(1)
        self._begin_hot_loop(prefix, level=0)  # Use the helper
        # if self.options.jit_raise_exceptions:
        self.addLevel(1)

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
        self.restoreLevel(self.parent.base_level - 1)
        self.restoreLevel(self.parent.base_level - 1)  # try

        # Cleanly exit all levels opened by the helper
        # self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            # Add the matching 'except' block for the 'try' in the helper
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

        # +++ NEW: Diversify the invalidation payload +++
        payloads = [
            "lambda *a, **kw: 'invalidation payload'",  # The original lambda
            self.arg_generator.genInt()[0],              # An integer
            self.arg_generator.genString()[0],           # A string
            "None",                                      # None
        ]
        chosen_payload = choice(payloads)

        self.write(0, "# Maliciously replacing the method on the class to invalidate JIT cache")
        self.write(0, "try:")
        self.write(1,
                   f"setattr({self.module_name}.{class_name}, '{method_name}', {chosen_payload})")
        self.write(1, "collect() # Encourage cleanup")
        self.write(0, "except Exception as e:")
        self.write_print_to_stderr(1, f'f"[{prefix}] PHASE 2: Exception invalidating {target_info["class_name"]}: {{ e }}"')
        self.emptyLine()

    def _generate_phase3_reexecute(self, prefix: str, target_info: dict) -> None:
        self.write_print_to_stderr(0,
                                   f'"[{prefix}] PHASE 3: Re-executing {target_info["method_name"]} to check for crash"')

        instance_var = target_info['instance_var']
        method_name = target_info['method_name']

        # Use the new helper to create the loop structure
        self.write(0, f"if {instance_var} is not None and {instance_var} is not SENTINEL_VALUE:")
        self.addLevel(1)
        base_level = self.parent.base_level
        self._begin_hot_loop(prefix, level=0)

        self.write(1, "try:")
        self.addLevel(1)

        # Re-execute the original call.
        self.write(1, f"getattr({instance_var}, '{method_name}')()")

        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(1, f'f"[{prefix}] Caught expected exception: {{e.__class__.__name__}}"')
        self.write(1, "break")  # Exit loop if it fails

        # Cleanly exit all levels
        self.restoreLevel(base_level)
        if self.options.jit_raise_exceptions:
            # Add the matching 'except' block for the 'try' in the helper
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

    def _generate_invalidation_scenario(self, prefix: str, target: dict) -> None:
        """
        Orchestrates the generation of a three-phase JIT invalidation scenario.

        This method calls helper methods to generate code for each phase:
        1. Warm-up: JIT-compile a target method.
        2. Invalidate: Change a dependency of the compiled code.
        3. Re-execute: Call the target method again to check for crashes.
        """
        if target['type'] != 'method':
            self.write_print_to_stderr(0,
                                       f'"[{prefix}] Skipping standard Invalidation Scenario for non-method target."')
            return

        self.write_print_to_stderr(0,
                                   f'"[{prefix}] >>> Starting JIT Invalidation Scenario targeting {target["name"]} <<<"')
        self.emptyLine()

        # --- Phase 1: Warm-up and JIT Compilation ---
        # The warmup phase now uses the target's setup code.
        self.write(0, f"# Phase 1: Warming up the target method.")
        instance_var = f"target_instance_{prefix}"

        # 1. Pre-initialize the instance variable to None.
        self.write(0, f"{instance_var} = None")

        # 2. Wrap the instantiation call in a try...except block.
        self.write(0, "try:")
        self.addLevel(1)
        # The target['setup_code'] contains the `instance = Class()` line.
        self._write_target_setup(prefix, target)
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(0,
                                   f'"[-] NOTE: Failed to instantiate for invalidation scenario: {{e.__class__.__name__}}"')
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        instance_var = f"target_instance_{prefix}"  # Assume instance is created in setup_code
        self.write(0, f"if {instance_var}:")
        # base_level = self.parent.base_level
        self.addLevel(1)
        self._begin_hot_loop(f"{prefix}_warmup", level=1)
        self.write(1, f"try: {target['call_str']}()")
        self.write(1, "except: pass")
        # self.restoreLevel(base_level)  # Exit hot loop
        # ... (end of hot loop boilerplate) ...
        self.restoreLevel(self.parent.base_level - 2)  # Exit if
        self.emptyLine()

        # --- Phase 2: Invalidate Dependency ---
        self.write_print_to_stderr(0, f'"[{prefix}] PHASE 2: Invalidating method on class."')
        # We need to get the class name from the target's setup string. A bit fragile but works.
        class_name = target['setup_code'].split('.')[-1].split('(')[0]
        method_name = target['name'].split('.')[-1]

        payloads = ["lambda *a, **kw: 'payload'", "123", "'a string'", "None"]
        self.write(0, f"try: setattr({self.module_name}.{class_name}, '{method_name}', {choice(payloads)})")
        self.write(0, "except: pass")
        self.write(0, "collect()")
        self.emptyLine()

        # --- Phase 3: Re-execute ---
        self.write_print_to_stderr(0, f'"[{prefix}] PHASE 3: Re-executing to check for crash."')
        self.write(0, f"if {instance_var}:")
        self.addLevel(1)
        self.write(0, f"try: {target['call_str']}()")
        self.write(0, "except Exception as e:")
        self.write(1, f"print(f'[{prefix}] Caught expected exception: {{e.__class__.__name__}}', file=stderr)")
        self.restoreLevel(self.parent.base_level - 1)

        self.write_print_to_stderr(0, f'"[{prefix}] <<< Finished Invalidation Scenario >>>"')
        self.emptyLine()

    def _generate_deleter_scenario(self, prefix: str, target: dict) -> None:
        """
        Generates a sophisticated scenario that uses a __del__ side effect
        to induce type confusion.

        This is now implemented by delegating to our more powerful variational
        engine using the 'decref_escapes' bug pattern.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] Delegating to variational engine for __del__ side effect scenario."')
        self._generate_variational_scenario(prefix, 'decref_escapes', target)

    def _generate_many_vars_scenario(self, prefix: str, target: dict) -> None:
        """
        Generates a function with >256 local variables and a complex,
        AST-mutated body that operates on them.
        """
        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Many Vars" Generative Scenario <<<"""')

        # 1. Generate the variable definitions.
        num_vars = 260
        var_names = [f"var_{i}_{prefix}" for i in range(num_vars)]
        var_defs = "\n".join([f"{name} = {i}" for i, name in enumerate(var_names)])

        # 2. Get the 'many_vars_base' pattern.
        pattern = BUG_PATTERNS['many_vars_base']

        # 3. Get a complex expression from the AST mutator, giving it ALL the variables.
        mutations = self._get_mutated_values_for_pattern(prefix, var_names)
        mutations['var_definitions'] = var_defs

        # 4. Format and write the complete, powerful scenario.
        setup_code = dedent(pattern['setup_code']).format(**mutations)
        body_code = dedent(pattern['body_code']).format(**mutations)

        func_name = f"many_vars_func_{prefix}"
        self.write(0, f"def {func_name}():")
        self.addLevel(1)
        self.write_pattern(setup_code, body_code)
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, f"{func_name}()")  # Execute the function

    def _generate_deep_calls_scenario(self, prefix: str, target: dict) -> None:
        """
        Generates a deep call chain where each function contains a
        different, AST-mutated expression.
        """
        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Generative Deep Calls" Scenario <<<"""')

        self._write_target_setup(prefix, target)

        depth = 20

        # 1. Generate the chain of functions.
        for i in range(depth):
            func_name = f"f_{i}_{prefix}"
            # At each level, generate a NEW mutated expression.
            mutations = self._get_mutated_values_for_pattern(prefix, [f'p_{prefix}'])
            expression = mutations['expression']

            self.write(0, f"def {func_name}(p_{prefix}):")
            self.addLevel(1)
            self.write(0, "try:")
            self.addLevel(1)
            # The next call is embedded inside the expression.
            if i > 0:
                next_call = f"f_{i - 1}_{prefix}(p_{prefix})"
                self.write(0, f"res = {expression} + {next_call}")
            else:  # Base case
                self.write(0, f"res = {expression}")
            self.write(0, "return res")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "except Exception: return 1")
            self.restoreLevel(self.parent.base_level - 1)

        # 2. Use our hot loop helper to call the top-level function.
        top_level_func = f"f_{depth - 1}_{prefix}"
        self._begin_hot_loop(prefix)
        self.addLevel(1)
        self.write(1, "try:")
        self.addLevel(1)
        self.write(1, f"{top_level_func}({self.arg_generator.genSmallUint()[0]})")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except RecursionError: break")
        self.restoreLevel(self.parent.base_level - 1)

        # Finalize the hot loop block
        self.restoreLevel(self.parent.base_level - 1)

        if self.options.jit_raise_exceptions:
            # self.restoreLevel(self.parent.base_level - 1)  # try
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

    def _generate_mixed_many_vars_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_del_invalidation_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_mixed_deep_calls_scenario(self, prefix: str, target: dict) -> None:
        """
        (Refactored)
        Generates a deep call chain where each function performs complex work,
        and the deepest function calls the selected fuzzing target (which can
        be a function or a method).
        """
        self.write_print_to_stderr(
            0, f'"""[{prefix}] >>> Starting "Mixed Deep Calls" targeting: {target["name"]} <<<"""'
        )

        # 1. Write the setup code for the target.
        #    If the target is a method, this will generate the `instance = ...` line.
        self._write_target_setup(prefix, target)

        depth = 15
        loop_iterations = self.options.jit_loop_iterations // 100

        self.write(0, f"# Define a deep chain of {depth} functions, each with internal JIT-friendly patterns.")

        # 2. Define the base case (the final function in the chain).
        #    This is where we inject the call to our fuzzed target.
        self.write(0, f"def f_0_{prefix}(p):")
        self.addLevel(1)
        self.write(0, "x = len('base_case') + p")
        self.write(0, "y = x % 5")
        self.write_print_to_stderr(0,
                                   f'''f"[{prefix}] Calling fuzzed target '{target["name"]}' from deep inside the call chain"''')
        # Use the target's call string, which can be a function or method.
        self.write(0, f"try: {target['call_str']}(x)")
        self.write(0, "except Exception: pass")
        self.write(0, "return x - y")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 3. Generate the intermediate functions in the chain.
        for i in range(1, depth):
            self.write(0, f"def f_{i}_{prefix}(p):")
            self.addLevel(1)
            self.write(0, f"local_val = p * {i}")
            self.write(0, "s = 'abcdef'")
            self.write(0, f"if local_val > 10 and (s[{i} % len(s)]):")
            self.addLevel(1)
            self.write(1, f"local_val += f_{i - 1}_{prefix}(p)")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "return local_val")
            self.restoreLevel(self.parent.base_level - 1)
            self.emptyLine()

        top_level_func = f"f_{depth - 1}_{prefix}"

        # 4. Call the top-level function inside a hot loop using our helper.
        base_level = self.parent.base_level
        self._begin_hot_loop(prefix)
        self.addLevel(1)
        self.write(1, "try:")
        self.addLevel(1)
        self.write(1, f"{top_level_func}(i_{prefix})")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except RecursionError:")
        self.addLevel(1)
        self.write_print_to_stderr(1, f'"[{prefix}] Caught expected RecursionError."')
        self.write(1, "break")

        # Cleanly exit all levels opened by the helper.
        self.restoreLevel(base_level)
        # self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            self.write(0, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(0, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)

        self.write_print_to_stderr(
            0, f'"""[{prefix}] <<< Finished "Mixed Deep Calls" Scenario >>>"""'
        )
        self.emptyLine()

    def _generate_deep_call_invalidation_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_indirect_call_scenario(self, prefix, target: dict):
        harness_func_name = f"harness_{prefix}"
        self.write_print_to_stderr(0, f'"[{prefix}] >>> Starting Indirect Call Scenario ({target["name"]}) <<<"')

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
        fuzzed_func_path = f"{self.module_name}.{target["name"]}"
        self.write(0, f"{harness_func_name}({fuzzed_func_path})")

    def _generate_fuzzed_func_invalidation_scenario(self, prefix: str, target: dict) -> None:
        """
        (Refactored)
        A three-phase invalidation attack where the fuzzed callable itself
        is the dependency that gets invalidated.

        This scenario is now only suitable for module-level functions, as invalidating
        a method on a class has a different mechanism.
        """
        # This attack is designed to redefine a function on a module,
        # so we only run it if our target is a function.
        if target['type'] != 'function':
            self.write_print_to_stderr(0, f'"[{prefix}] Skipping Fuzzed Function Invalidation for method target."')
            return

        wrapper_func_name = f"jit_wrapper_{prefix}"
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Fuzzed Function Invalidation Scenario ({target["name"]}) <<<"'
        )
        self.emptyLine()

        # --- Phase 1: Define a Wrapper and Warm It Up ---
        self.write(0, f"# Phase 1: Define a wrapper and JIT-compile it.")
        self.write(0, f"def {wrapper_func_name}():")
        self.addLevel(1)
        # Use the unified target call string.
        self.write(0, f"try: {target['call_str']}()")
        self.write(0, "except: pass")
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # Use our hot loop helper to warm up the wrapper.
        self._begin_hot_loop(prefix)
        self.addLevel(1)
        self.write(1, f"{wrapper_func_name}()")
        self.restoreLevel(self.parent.base_level - 2)
        # ... (end of hot loop boilerplate) ...

        # --- Phase 2: Invalidate the Fuzzed Function ---
        self.write_print_to_stderr(0, f'"[{prefix}] Phase 2: Redefining {target["name"]} on the module..."')
        self.write(0, f"# Maliciously redefine the fuzzed function on its own module.")
        # The 'name' field from the target dict gives us the function name.
        self.write(0, f"setattr({self.module_name}, '{target['name']}', lambda *a, **kw: 'payload')")
        self.write(0, "collect()")
        self.emptyLine()

        # --- Phase 3: Re-execute the Wrapper ---
        self.write_print_to_stderr(0, f'"[{prefix}] Phase 3: Re-executing the wrapper to check for crashes..."')
        self.write(0, f"try: {wrapper_func_name}()")
        self.write(0, "except Exception: pass")
        self.emptyLine()

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Fuzzed Function Invalidation Scenario >>>"'
        )

    def _generate_polymorphic_call_block_scenario(self, prefix: str, target: dict) -> None:
        """
        Generates a hot loop that makes calls to different KINDS of callables
        (fuzzed function, lambda, instance method) to stress call-site caching.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting Polymorphic Callable Set Scenario ({target["name"]}) <<<"'
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
            f"{self.module_name}.{target["name"]}",
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

    def _generate_type_version_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_concurrency_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_side_exit_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_isinstance_attack_scenario(self, prefix: str, target: dict) -> None:
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

        # Write the setup code for the target (if it's a method call).
        self._write_target_setup(prefix, target)

        self.write(0, "try:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f"'    -> Calling fuzzed target: {target['name']}'")
        # Use the unified call string, which works for both functions and methods.
        self.write(0, f"{target['call_str']}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except: pass")
        self.write(0, f"return True")  # Always return True after being patched
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
        self.write(0, f"fuzzed_obj_instance = {self.module_name}.{target["name"]}")
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

    def _generate_jit_pattern_block_with_check(self, prefix: str, target: dict) -> None:
        """Delegates to the unified engine with the 'jit_friendly_math' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'jit_friendly_math',
                                                           BUG_PATTERNS['jit_friendly_math'], {})

    def _generate_evil_jit_pattern_block_with_check(self, prefix: str, target: dict) -> None:
        """Prepares evil constants and delegates to the unified engine."""
        extra_mutations = {
            'val_a': self.arg_generator.genInterestingValues()[0],
            'val_b': self.arg_generator.genInterestingValues()[0],
            'val_c': self.arg_generator.genInterestingValues()[0],
            'str_d': self.arg_generator.genString()[0],
        }
        return self._generate_paired_ast_mutation_scenario(prefix, 'evil_boundary_math',
                                                           BUG_PATTERNS['evil_boundary_math'], extra_mutations)

    def _generate_deleter_scenario_with_check(self, prefix: str, target: dict) -> None:
        """Delegates to the unified engine with the 'deleter_side_effect' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'deleter_side_effect',
                                                           BUG_PATTERNS['deleter_side_effect'], {})

    def _generate_deep_calls_scenario_with_check(self, prefix: str, target: dict) -> None:
        """Prepares deep call setup and delegates to the unified engine."""
        mutations = self._get_mutations_for_deep_calls(prefix, {}, target, is_evil=False)
        return self._generate_paired_ast_mutation_scenario(prefix, 'deep_calls_correctness',
                                                           BUG_PATTERNS['deep_calls_correctness'], mutations)

    def _generate_evil_deep_calls_scenario_with_check(self, prefix: str, target: dict) -> None:
        """Prepares evil deep call setup and delegates to the unified engine."""
        mutations = self._get_mutations_for_deep_calls(prefix, {}, target, is_evil=True)
        return self._generate_paired_ast_mutation_scenario(prefix, 'evil_deep_calls_correctness',
                                                           BUG_PATTERNS['evil_deep_calls_correctness'], mutations)

    def _generate_inplace_add_attack_scenario_with_check(self, prefix: str, target: dict) -> None:
        """Delegates to the unified engine with the 'inplace_add_attack' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'inplace_add_attack',
                                                           BUG_PATTERNS['inplace_add_attack'], {})

    def _generate_global_invalidation_scenario_with_check(self, prefix: str, target: dict) -> None:
        """Delegates to the unified engine with the 'global_invalidation' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'global_invalidation',
                                                           BUG_PATTERNS['global_invalidation'], {})

    def _generate_managed_dict_attack_scenario_with_check(self, prefix: str, target: dict) -> None:
        """Delegates to the unified engine with the 'managed_dict_attack' pattern."""
        return self._generate_paired_ast_mutation_scenario(prefix, 'managed_dict_attack',
                                                           BUG_PATTERNS['managed_dict_attack'], {})

    def _generate_decref_escapes_scenario(self, prefix: str, target: dict) -> None:
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

    def _generate_variational_scenario(self, prefix: str, pattern_names: str, target: dict) -> None:
        """
        Acts as a master dispatcher. It now ensures that parameter mutations are
        always generated before being passed to specialized helpers.
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
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Fuzzing Pattern: {pattern_name} (Tags: {", ".join(tags)}) <<<<"'
        )

        # --- 2. ALWAYS Generate Base and Parameter Mutations First ---
        # This ensures 'def_str', 'call_str', etc. are always present.
        params = self._generate_mutated_parameters(prefix, target)
        mutations = self._get_mutated_values_for_pattern(prefix, params['param_names'])
        mutations.update(params)

        if 'needs-many-vars-setup' in tags:
            mutations = self._get_mutations_for_many_vars(prefix, mutations)
        elif 'needs-evil-deep-calls-setup' in tags:
            mutations = self._get_mutations_for_deep_calls(prefix, mutations, target, is_evil=True)
        elif 'needs-deep-calls-setup' in tags:
            mutations = self._get_mutations_for_deep_calls(prefix, mutations, target, is_evil=False)
        elif 'needs-evil-math-setup' in tags:
            mutations = self._get_mutations_for_evil_math(prefix, mutations)

        mutations['fuzzed_func_name'] = target['name']
        mutations['fuzzed_func_call'] = target['call_str']
        mutations['fuzzed_func_setup'] = target['setup_code']

        # --- 4. Code Generation (Dispatch based on tags) ---
        if 'correctness' in tags:
            self._generate_paired_ast_mutation_scenario(prefix, pattern_name, pattern, mutations)
        else:
            setup_code = dedent(pattern['setup_code']).format(**mutations)
            body_code = dedent(pattern['body_code']).format(**mutations)

            if self.options.jit_fuzz_ast_mutation:
                self.write_print_to_stderr(0, f'"[{prefix}] Applying AST structural mutations."')
                body_code = self.ast_mutator.mutate(body_code)

            self._write_mutated_code_in_environment(prefix, setup_code, body_code, mutations)

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished Fuzzing Pattern: {pattern_name} >>>"'
        )
        self.emptyLine()

    def _get_mutations_for_many_vars(self, prefix: str, mutations: dict) -> dict:
        """
        Generates mutations specifically for patterns tagged with 'many-vars'.
        This includes the variable definitions and a complex expression using them.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] Using specialized generator: many_vars"')
        num_vars = 260
        var_names = [f"var_{i}_{prefix}" for i in range(num_vars)]
        mutations['var_definitions'] = "\n".join([f"{name} = {i}" for i, name in enumerate(var_names)])

        expression_ast = self._generate_expression_ast(available_vars=var_names)
        try:
            mutations['expression'] = ast.unparse(expression_ast)
        except AttributeError:
            mutations['expression'] = " # AST unparsing failed"
        return mutations

    def _get_mutations_for_evil_math(self, prefix: str, mutations: dict) -> dict:
        """
        Generates mutations for patterns tagged with 'boundary-values'.
        This involves selecting several "interesting" values from our list.
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
        (Updated)
        Generates mutations for 'deep-calls' patterns. This includes dynamically
        building a string that defines a chain of recursive functions, which can
        now call the provided 'target' callable.
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

        base_case_def = f"def f_0_{prefix}({'p_tuple' if is_evil else 'p'}):\n    {base_case_body.replace(chr(10), chr(10) + '    ')}"
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
                func_def = f"def {func_name}(p_tuple):\n    {func_body.replace(chr(10), chr(10) + '    ')}"
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
        """
        (Corrected)
        Creates a dictionary of randomized values to be injected into
        a bug pattern template. It now includes all necessary static context.
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

    def _write_mutated_code_in_environment(self, prefix: str, setup_code: str, body_code: str,
                                           params: dict = None) -> None:
        """
        Takes the final generated code and wraps it in a randomly chosen
        execution environment, correctly applying mutated parameters.
        """
        # If no specific parameters were generated (e.g., for simple iterative modes),
        # use empty defaults.
        if params is None:
            params = {'def_str': '', 'call_str': '', 'setup_code': ''}

        param_def = params['def_str']
        param_call = params['call_str']
        param_setup = params['setup_code']

        # Prepend any setup code needed for the parameters (e.g., defining an aliased list).
        if param_setup:
            self.write(0, param_setup)

        env_choice = randint(0, 5)
        env_map = {
            0: "Top-Level Function", 1: "Nested Function", 2: "Class Method",
            3: "Async Function", 4: "Generator Function", 5: "Lambda-called Function"
        }
        self.write_print_to_stderr(0, f'"[{prefix}] Environment Strategy: {env_map[env_choice]}"')

        # --- Environment 1: Simple top-level function ---
        if env_choice == 0:
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(setup_code, body_code)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"harness_{prefix}({param_call})")

        # --- Environment 2: Nested function ---
        elif env_choice == 1:
            self.write(0, f"def outer_{prefix}():")
            self.addLevel(1)
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(setup_code, body_code)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"harness_{prefix}({param_call})")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"outer_{prefix}()")

        # --- Environment 3: Class method ---
        elif env_choice == 2:
            self.write(0, f"class Runner_{prefix}:")
            self.addLevel(1)
            # Add 'self' to the parameter definition for the method.
            method_param_def = f"self, {param_def}" if param_def else "self"
            self.write(0, f"def harness(self, {param_def}):")
            self.addLevel(1)
            self.write_pattern(setup_code, body_code)
            self.restoreLevel(self.parent.base_level - 2)
            self.write(0, f"Runner_{prefix}().harness({param_call})")

        # --- Environment 4: Asynchronous Function ---
        elif env_choice == 3:
            self.write(0, "import asyncio")
            self.write(0, f"async def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(setup_code, body_code)
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, f"asyncio.run(harness_{prefix}({param_call}))")

        # --- Environment 5: Generator Function ---
        elif env_choice == 4:
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(setup_code, body_code)
            self.write(0, "yield # Make this a generator")
            self.restoreLevel(self.parent.base_level - 1)
            self.write(0, "# We must consume the generator for its code to execute.")
            self.write(0, f"for _ in harness_{prefix}({param_call}): pass")

        # --- Environment 6: Lambda-called Function ---
        else:  # env_choice == 5
            self.write(0, f"def harness_{prefix}({param_def}):")
            self.addLevel(1)
            self.write_pattern(setup_code, body_code)
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
        # Catch our specific signal and let it bubble up.
        self.write(level, "except JITCorrectnessError:")
        self.addLevel(1)
        self.write(level, "raise")
        self.restoreLevel(self.parent.base_level - 1)
        # Catch all other exceptions, INCLUDING normal AssertionErrors, and ignore them.
        self.write(level, "except (Exception, SystemExit):")
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
            return None
        return None

    def _begin_hot_loop(self, prefix: str, level: int = 0) -> None:
        """
        Writes the standard boilerplate for a JIT-warming hot loop, including
        optional aggressive GC and exception raising.
        """
        loop_var = f"i_{prefix}"
        loop_iterations = self.options.jit_loop_iterations

        if self.options.jit_raise_exceptions:
            self.write(level, "try:")
            self.addLevel(1)

        self.write(level, f"for {loop_var} in range({loop_iterations}):")
        self.addLevel(1)

        if self.options.jit_aggressive_gc:
            self.write(level, f"if {loop_var} % {self.options.jit_gc_frequency} == 0:")
            self.addLevel(1)
            self.write(level, "collect()")
            self.restoreLevel(self.parent.base_level - 1)

        if self.options.jit_raise_exceptions:
            self.write(level, f"if random() < {self.options.jit_exception_prob}:")
            self.addLevel(1)
            self.write_print_to_stderr(level, f'"[{prefix}] Intentionally raising exception in hot loop!"')
            self.write(level, "raise ValueError('JIT fuzzing probe')")
            self.restoreLevel(self.parent.base_level - 1)
            self.restoreLevel(self.parent.base_level - 1)

    def _generate_paired_ast_mutation_scenario(self, prefix: str, pattern_name: str, pattern: dict,
                                               mutations: dict) -> None:
        """
        (Corrected)
        Generates a 'Twin Execution' correctness test, now ensuring that all
        setup code, including instantiation, is guarded by a try...except block.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] >>> JIT Correctness Scenario: {pattern_name} <<<"')

        # --- THE FIX ---
        # The main 'try' block now wraps EVERYTHING, including setup code.
        self.write(0, "try:")
        self.addLevel(1)

        # 1. Format and write the setup code for the pattern AND the target inside the try block.
        fuzzed_func_setup = mutations.get('fuzzed_func_setup', '')
        if fuzzed_func_setup:
            self.write(0, fuzzed_func_setup)

        setup_code = dedent(pattern['setup_code']).format(**mutations)
        if setup_code:
            for line in setup_code.splitlines():
                self.write(0, line)

        self.emptyLine()

        # 2. Get the core logic from the pattern's body.
        initial_body_code = dedent(pattern['body_code']).format(**mutations)

        # 3. Use a single seed to create one mutated version of the logic.
        mutation_seed = randint(0, 2 ** 32 - 1)
        mutated_code = self.ast_mutator.mutate(initial_body_code, seed=mutation_seed)
        if not mutated_code.strip():
            mutated_code = "pass"

        # 4. Define the JIT and Control functions.
        param_def = pattern.get('param_def', "")
        jit_func_name = f"jit_target_{prefix}"
        control_func_name = f"control_{prefix}"

        self.write(0, f"def {jit_func_name}({param_def}):")
        self.addLevel(1)
        for line in mutated_code.splitlines(): self.write(1, line)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        self.write(0, f"def {control_func_name}({param_def}):")
        self.addLevel(1)
        for line in mutated_code.splitlines(): self.write(1, line)
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # 5. Generate the "Twin Execution" harness.
        param_call = mutations.get('param_call', pattern.get('param_call', ""))

        self.write(0, f"jit_harness({jit_func_name}, {self.options.jit_loop_iterations}, {param_call})")
        self.write(0, f"jit_result = {jit_func_name}({param_call})")
        self.write(0, f"control_result = no_jit_harness({control_func_name}, {param_call})")
        self.emptyLine()
        self.write(0, "if not compare_results(jit_result, control_result):")
        self.addLevel(1)
        self.write(0,
                   '    raise JITCorrectnessError(f"JIT CORRECTNESS BUG ({pattern_name})! JIT: {{jit_result}}, Control: {{control_result}}")')

        # Close the main try...except block
        self.restoreLevel(self.parent.base_level - 2)
        self.write(0, "except JITCorrectnessError: raise")
        self.write(0, "except (Exception, SystemExit): pass")

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< JIT Correctness Scenario ({pattern_name}) Passed >>>"'
        )
        self.emptyLine()

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

    def _generate_args_for_method(self, method_obj: object) -> str:
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

    def _generate_class_fuzzing_scenario(self, prefix: str) -> None:
        """
        Selects a class, instantiates it safely, and calls one of its methods
        repeatedly in a JIT-warming hot loop with "smart" arguments.
        """
        fuzzable_classes = self._discover_and_filter_classes()
        if not fuzzable_classes:
            self.write_print_to_stderr(0, '"[-] No suitable classes found for JIT fuzzing in this module."')
            return

        target_class = choice(fuzzable_classes)
        class_name = target_class.__name__
        self.write_print_to_stderr(0, f'"[{prefix}] >>> Starting JIT Class Fuzzing for: {class_name} <<<"')

        # --- THE FIX ---
        instance_var = f"instance_{prefix}"

        # 1. Pre-initialize the instance variable to None. This prevents
        #    UnboundLocalError if instantiation fails.
        self.write(0, f"{instance_var} = None")

        # 2. Wrap the instantiation call in a try...except block.
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"# Instantiate a target class from the module.")
        self.write(0, f"{instance_var} = {self.module_name}.{class_name}()")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[-] NOTE: Failed to instantiate {class_name}: {{e.__class__.__name__}}"')
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

        # Discover a suitable method on the class to call.
        methods = self.parent._get_object_methods(target_class, class_name)
        if not methods:
            self.write_print_to_stderr(0, f'"[-] No suitable methods found on class {class_name}."')
            return

        method_name = choice(list(methods.keys()))
        method_obj = methods[method_name]

        # Generate "smart" arguments for the chosen method.
        args_str = self._generate_args_for_method(method_obj)
        self.write_print_to_stderr(0, f'"[{prefix}] Targeting method: {class_name}.{method_name}"')

        # Generate the JIT-warming hot loop. The `if instance_var:` check
        # now safely handles instantiation failures.
        self.write(0, f"if {instance_var}:")
        self.addLevel(1)
        self._begin_hot_loop(prefix, level=1)

        self.write(1, "try:")
        self.addLevel(1)
        self.write(1, f"getattr({instance_var}, '{method_name}')({args_str})")
        self.restoreLevel(self.parent.base_level - 1)
        self.write(1, "except Exception: pass")

        # Cleanly exit the levels opened by the helper.
        self.restoreLevel(self.parent.base_level - 1)
        if self.options.jit_raise_exceptions:
            # Add the matching 'except' block for the 'try' in the helper
            self.write(1, "except ValueError as e_val_err:")
            self.addLevel(1)
            self.write(1, "if e_val_err.args == ('JIT fuzzing probe',):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"[{prefix}] Intentionally raised ValueError in hot loop caught!"')
            self.restoreLevel(self.parent.base_level - 1)
            self.write(1, "else: raise")
            self.restoreLevel(self.parent.base_level - 1)

        self.restoreLevel(self.parent.base_level - 1)  # Closes the initial `if instance_var:`
        self.write_print_to_stderr(0, f'"[{prefix}] <<< Finished JIT Class Fuzzing for: {class_name} >>>"')
        self.emptyLine()

    def _select_fuzzing_target(self, prefix: str) -> dict | None:
        """
        (Upgraded)
        Selects a callable to be used as the "payload" for a JIT scenario.
        It now explicitly returns the variable name for any created instance.
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
        return None

    def _write_target_setup(self, prefix: str, target: dict):
        """
        Safely writes the setup code for a fuzzing target, wrapping any
        instantiation in a try...except block.
        """
        instance_var = target.get('instance_var')
        setup_code = target.get('setup_code')

        if not instance_var or not setup_code:
            return  # Nothing to set up

        self.write(0, f"# Safely instantiate the target for this scenario.")
        self.write(0, f"{instance_var} = None")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, setup_code)
        self.restoreLevel(self.parent.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        self.write_print_to_stderr(0,
                                   f'"[-] NOTE: Instantiation failed for {target["name"]}: {{e.__class__.__name__}}"')
        self.restoreLevel(self.parent.base_level - 1)
        self.emptyLine()

