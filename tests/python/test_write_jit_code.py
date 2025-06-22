import unittest
import ast
import builtins
import math
from abc import ABC, abstractmethod
from unittest.mock import MagicMock, patch

# Import the classes we want to test
from fusil.python.jit.write_jit_code import WriteJITCode
from fusil.python.write_python_code import WritePythonCode
from fusil.python.argument_generator import ArgumentGenerator
from fusil.python.jit.bug_patterns import BUG_PATTERNS
from fusil.python.jit.ast_mutator import OperatorSwapper


class TestWriteJITCode(unittest.TestCase):
    """
    Unit tests for the JIT code generation logic.
    """

    def setUp(self):
        """
        Set up a mock environment to instantiate WriteJITCode for testing.
        """
        # Create a mock for the command-line options object.
        mock_options = MagicMock()
        mock_options.jit_mode = 'legacy'
        mock_options.jit_correctness_testing = False
        mock_options.jit_loop_iterations = 100
        mock_options.jit_hostile_prob = 0.5
        mock_options.jit_fuzz_classes = True
        mock_options.jit_fuzz_ast_mutation = False
        mock_options.jit_wrap_statements = False
        mock_options.jit_pattern_name = 'ALL'

        real_arg_generator = ArgumentGenerator(mock_options, [], False, False, False)

        # 2. Create the mock parent, but now we will configure its arg_generator.
        mock_parent = MagicMock()
        mock_parent.options = mock_options
        mock_parent.module = math
        mock_parent.module_name = 'math'
        # Add the real BUG_PATTERNS to the mock module so it can be found.
        mock_parent.module.BUG_PATTERNS = BUG_PATTERNS

        # 3. Configure the mock arg_generator's methods to use the real one.
        mock_parent.arg_generator.genInt.side_effect = real_arg_generator.genInt
        mock_parent.arg_generator.genString.side_effect = real_arg_generator.genString
        mock_parent.arg_generator.genSmallUint.side_effect = real_arg_generator.genSmallUint
        mock_parent.arg_generator.genBool.side_effect = real_arg_generator.genBool
        mock_parent.arg_generator.genFloat.side_effect = real_arg_generator.genFloat
        mock_parent.arg_generator.genBytes.side_effect = real_arg_generator.genBytes
        mock_parent.arg_generator.genList.side_effect = real_arg_generator.genList
        mock_parent.arg_generator.genInterestingValues.side_effect = real_arg_generator.genInterestingValues
        # Add a simple return for genTrickyObjects to avoid its complexity for now.
        mock_parent.arg_generator.genTrickyObjects.return_value = ["'tricky_object'"]

        def print_side_effect(level, msg, return_str=False):
            if return_str:
                return f"print({msg}, file=stderr)"
            return None

        mock_parent.write_print_to_stderr.side_effect = print_side_effect

        mock_parent.module_functions, mock_parent.module_classes, _ = WritePythonCode._get_module_members(mock_parent)

        self.jit_writer = WriteJITCode(mock_parent)

    def _assert_is_valid_python(self, code: str):
        """Helper assertion to check for valid Python syntax."""
        self.assertIsNotNone(code)
        self.assertIsInstance(code, str)
        self.assertTrue(len(code.strip()) > 0, "Generator produced empty code.")
        try:
            ast.parse(code)
        except SyntaxError as e:
            self.fail(f"Generated code failed to parse with SyntaxError: {e}\n--- Code ---\n{code}")

    def test_smoke_test_legacy_scenario_generation(self):
        """
        Smoke Test: Ensures that --jit-mode=legacy generates valid Python.
        """
        self.jit_writer.options.jit_mode = 'legacy'
        self.jit_writer.options.rediscover_decref_crash = True

        generated_code = self.jit_writer.generate_scenario("f1")
        self._assert_is_valid_python(generated_code)

    def test_smoke_test_synthesize_mode(self):
        """
        Smoke Test: Ensures that --jit-mode=synthesize generates valid Python.
        """
        self.jit_writer.options.jit_mode = 'synthesize'

        generated_code = self.jit_writer.generate_scenario("f2")
        self._assert_is_valid_python(generated_code)

    def test_smoke_test_variational_mode(self):
        """
        Smoke Test: Ensures that --jit-mode=variational generates valid Python.
        """
        self.jit_writer.options.jit_mode = 'variational'
        # Force a simple pattern to avoid KeyErrors from complex ones in this basic test
        self.jit_writer.options.jit_pattern_name = 'friendly_base'

        generated_code = self.jit_writer.generate_scenario("f3")
        self._assert_is_valid_python(generated_code)

    def test_smoke_test_correctness_mode(self):
        """
        Smoke Test: Ensures that the correctness checking path generates valid Python.
        """
        self.jit_writer.options.jit_mode = 'variational'
        self.jit_writer.options.jit_pattern_name = 'jit_friendly_math'

        # We don't need to enable --jit-correctness-testing. We can directly
        # call the generator for paired mutation scenarios.
        pattern = BUG_PATTERNS['jit_friendly_math']
        mutations = self.jit_writer._get_mutated_values_for_pattern("f4", [])

        generated_code = self.jit_writer._generate_paired_ast_mutation_scenario("f4", "jit_friendly_math", pattern,
                                                                                mutations)
        self._assert_is_valid_python(generated_code)

    def test_select_fuzzing_target_selects_both_functions_and_methods(self):
        """
        Logic Test: Ensures that _select_fuzzing_target correctly chooses
        both module-level functions and class methods over multiple runs.
        """
        # To test method selection, we need to mock the class discovery process
        # to ensure there's always a valid class and method to be found.
        mock_class = MagicMock()
        mock_class.__name__ = 'MyFuzzableClass'

        # We patch the two helpers involved in class/method discovery.
        with patch.object(self.jit_writer, '_discover_and_filter_classes', return_value=[mock_class]):
            with patch.object(self.jit_writer.parent, '_get_object_methods', return_value={'my_method': lambda: None}):
                with patch.object(self.jit_writer.parent, 'module_classes', (mock_class,)):

                    selected_types = set()
                    # Run the selection many times to account for randomness.
                    for _ in range(100):
                        target = self.jit_writer._select_fuzzing_target("t1")
                        if target:
                            selected_types.add(target['type'])

                    # Assert that over 100 runs, both 'function' and 'method'
                    # targets were selected at least once.
                    self.assertIn('function', selected_types, "The target selector never chose a module-level function.")
                    self.assertIn('method', selected_types, "The target selector never chose a class method.")

    def test_generate_args_for_method_is_smart(self):
        """
        Logic Test: Verifies that _generate_args_for_method uses its
        heuristics to generate plausible arguments based on parameter names.
        """
        with patch("fusil.python.jit.write_jit_code.random", return_value=0.2):
        # --- Test Case 1: Parameter name suggests an integer ---
            def func_with_count(count, index, size, length):
                pass

            args_str_for_int = self.jit_writer._generate_args_for_method(func_with_count)
            args = args_str_for_int.split(',')
            # Check that all generated arguments are valid integers
            for arg in args:
                try:
                    int(arg.strip())
                except ValueError:
                    self.fail(f"Expected integer argument for name 'count', but got '{arg.strip()}'")

            # --- Test Case 2: Parameter name suggests a string ---
            def func_with_path(path, file, name):
                pass
            args_str_for_str = self.jit_writer._generate_args_for_method(func_with_path)
            args = args_str_for_str.split(',')
            # Check that all generated arguments are quoted strings
            for arg in args:
                arg = arg.strip()
                self.assertTrue(
                    (arg.startswith("'") and arg.endswith("'")) or \
                    (arg.startswith('"') and arg.endswith('"')),
                    f"Expected string argument for name 'path', but got '{arg}'"
                )

            # --- Test Case 3: Parameter name suggests a boolean ---
            def func_with_flag(flag, enabled):
                pass

            args_str_for_bool = self.jit_writer._generate_args_for_method(func_with_flag)
            args = args_str_for_bool.split(',')
            # Check that all generated arguments are 'True' or 'False'
            for arg in args:
                self.assertIn(
                    arg.strip(),
                    ['True', 'False'],
                    f"Expected boolean argument for name 'flag', but got '{arg.strip()}'"
                )

    def test_discover_and_filter_classes_logic(self):
        """
        Logic Test: Verifies that _discover_and_filter_classes correctly
        filters out abstract classes and exceptions.
        """
        # 1. Create a mock module object to hold our test classes.
        mock_module = MagicMock()

        # 2. Define a set of test classes directly on the mock module.
        class FuzzableClass:
            def __init__(self): pass

            def method(self): pass

        class MyTestException(Exception):
            pass

        class MyAbstractClass(ABC):
            @abstractmethod
            def method(self): pass

        mock_module.FuzzableClass = FuzzableClass
        mock_module.MyTestException = MyTestException
        mock_module.MyAbstractClass = MyAbstractClass

        # 3. Temporarily replace the jit_writer's parent module with our mock.
        original_module = self.jit_writer.parent.module
        self.jit_writer.parent.module = mock_module

        # We also need to update the list of class names on the parent mock.
        self.jit_writer.parent.module_classes = ['FuzzableClass', 'MyTestException', 'MyAbstractClass']

        # Reset the cache in the jit_writer
        self.jit_writer.fuzzable_classes = None

        try:
            # 4. Call the method we want to test.
            result = self.jit_writer._discover_and_filter_classes()

            # 5. Assert that the result is what we expect.
            self.assertEqual(len(result), 1, "The filter should have only returned one class.")
            self.assertIs(result[0], FuzzableClass, "The only returned class should be FuzzableClass.")

        finally:
            # 6. Clean up by restoring the original module.
            self.jit_writer.parent.module = original_module

    def test_discover_and_filter_classes_instantiability(self):
        """
        Logic Test: Stresses the __init__ signature analysis to ensure only
        truly instantiable classes are considered fuzzable.
        """

        # 1. Define a suite of tricky classes.

        # --- These should PASS the filter ---
        class GoodClassNoInit:
            pass

        class GoodClassEmptyInit:
            def __init__(self): pass

        class GoodClassWithDefaults:
            def __init__(self, x=1, y="a"): pass

        class GoodClassWithVarargs:
            def __init__(self, *args, **kwargs): pass

        # --- These should FAIL the filter ---
        class BadClassWithRequiredArg:
            def __init__(self, required_arg): pass

        class BadClassWithMixedArgs:
            def __init__(self, x, y=1): pass

        # 2. Set up the mock module.
        mock_module = MagicMock()
        mock_module.GoodClassNoInit = GoodClassNoInit
        mock_module.GoodClassEmptyInit = GoodClassEmptyInit
        mock_module.GoodClassWithDefaults = GoodClassWithDefaults
        mock_module.GoodClassWithVarargs = GoodClassWithVarargs
        mock_module.BadClassWithRequiredArg = BadClassWithRequiredArg
        mock_module.BadClassWithMixedArgs = BadClassWithMixedArgs

        # 3. Temporarily replace the jit_writer's parent module and clear cache.
        original_module = self.jit_writer.parent.module
        self.jit_writer.parent.module = mock_module
        self.jit_writer.parent.module_classes = [
            'GoodClassNoInit', 'GoodClassEmptyInit', 'GoodClassWithDefaults',
            'GoodClassWithVarargs', 'BadClassWithRequiredArg', 'BadClassWithMixedArgs'
        ]
        self.jit_writer.fuzzable_classes = None

        try:
            # 4. Call the method we want to test.
            result = self.jit_writer._discover_and_filter_classes()

            # 5. Assert that the results are correct.
            result_names = {c.__name__ for c in result}
            expected_names = {
                'GoodClassNoInit', 'GoodClassEmptyInit',
                'GoodClassWithDefaults', 'GoodClassWithVarargs'
            }

            self.assertEqual(len(result), 4, "The filter kept the wrong number of classes.")
            self.assertEqual(result_names, expected_names,
                             "The filter did not correctly identify all fuzzable classes.")

        finally:
            # 6. Clean up.
            self.jit_writer.parent.module = original_module

    def test_ast_pattern_generator_creates_control_flow(self):
        """
        Logic Test: Ensures the ASTPatternGenerator can synthesize code
        containing both 'if' and 'for' statements.
        """
        found_if = False
        found_for = False

        # Run the generator many times to ensure we see all outcomes.
        for _ in range(100):
            # We call the generator directly for a focused unit test.
            code_str = self.jit_writer.ast_pattern_generator.generate_pattern()
            self._assert_is_valid_python(code_str)

            tree = ast.parse(code_str)
            for node in ast.walk(tree):
                if isinstance(node, ast.If):
                    found_if = True
                if isinstance(node, ast.For):
                    found_for = True

            if found_if and found_for:
                break  # We've seen both, no need to keep looping

        self.assertTrue(found_if, "ASTPatternGenerator failed to generate an 'if' statement after 100 attempts.")
        self.assertTrue(found_for, "ASTPatternGenerator failed to generate a 'for' statement after 100 attempts.")

    def test_ast_mutator_operator_swapper(self):
        """
        Logic Test: Unit tests the OperatorSwapper transformer to ensure it
        correctly replaces a binary operator in a given AST.
        """
        # 1. Define a simple input code string.
        input_code = "result = 100 + 200"

        # 2. Parse it into an AST.
        tree = ast.parse(input_code)

        # 3. Create an instance of the specific transformer we are testing.
        swapper = OperatorSwapper()

        # 4. Apply the transformation.
        # We patch random.random to always be < 0.3 to ensure the swap always happens.
        with patch('random.random', return_value=0.2):
            mutated_tree = swapper.visit(tree)

        # 5. Unparse the mutated tree back into a code string.
        ast.fix_missing_locations(mutated_tree)
        mutated_code = ast.unparse(mutated_tree)

        # 6. Assert that the transformation worked as expected.
        self.assertIn("result = 100", mutated_code)
        self.assertNotIn("+", mutated_code, "OperatorSwapper failed to replace the '+' operator.")

        # Check if one of the possible replacements is present.
        possible_replacements = ['-', '*', '/', '//', '%']
        self.assertTrue(
            any(op in mutated_code for op in possible_replacements),
            f"Mutated code '{mutated_code}' did not contain any expected replacement operators."
        )

    def test_ast_pattern_generator_uses_known_variables(self):
        """
        Logic Test: Ensures the ASTPatternGenerator only generates expressions
        that use variables previously defined in the scope, preventing
        UnboundLocalError.
        """
        # 1. Generate a pattern from scratch.
        code_str = self.jit_writer.ast_pattern_generator.generate_pattern()
        self._assert_is_valid_python(code_str)

        tree = ast.parse(code_str)

        # 2. Walk the tree and collect all assigned and loaded variable names.
        assigned_vars = set()
        loaded_vars = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    assigned_vars.add(node.id)
                elif isinstance(node.ctx, ast.Load):
                    loaded_vars.add(node.id)
            # Loop variables are also assignments
            elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                 assigned_vars.add(node.target.id)

        # 3. Assert that the set of used (loaded) variables is a subset
        #    of the set of created (assigned) variables.
        #    This proves we are not using variables before they are defined.

        # We ignore builtins which are "loaded" but not assigned in our scope and the fuzzed module name.
        undefined_and_used = loaded_vars - assigned_vars - set(dir(builtins)) - {self.jit_writer.parent.module_name}

        self.assertEqual(
            undefined_and_used,
            set(),
            f"ASTGenerator produced code that uses variables before assignment: {undefined_and_used}\n--- Code ---\n{code_str}"
        )

    def test_generate_invalidation_scenario_logic(self):
        """
        Logic Test: Verifies that _generate_invalidation_scenario correctly
        constructs the full three-phase invalidation attack.
        """
        # 1. Create a mock target dictionary for a class method.
        prefix = "f_inv_test"
        instance_var = f"instance_{prefix}"
        class_name = "MyTargetClass"
        method_name = "my_method"

        mock_target = {
            'type': 'method',
            'name': f'{class_name}.{method_name}',
            'instance_var': instance_var,
            'setup_code': f"{instance_var} = {self.jit_writer.module_name}.{class_name}()",
            'call_str': f"{instance_var}.{method_name}"
        }

        # 2. Call the scenario generator to get the code string.
        with patch('random.choice', return_value="'invalidated_payload'"):
            generated_code = self.jit_writer._generate_invalidation_scenario(prefix, mock_target)

        # 3. Perform assertions.
        self._assert_is_valid_python(generated_code)

        # Assert that the key components of the three-phase attack are present.
        self.assertIn(f"PHASE 1: Warming up", generated_code)
        self.assertIn(f"PHASE 2: Invalidating", generated_code)

        # --- THE FIX ---
        # Use the semantic marker comments to check for correct ordering.
        invalidation_marker = f"PHASE 2: Invalidating method on class."
        reexecute_marker = f"PHASE 3: Re-executing to check for crash."

        invalidation_index = generated_code.find(invalidation_marker)
        reexecute_index = generated_code.find(reexecute_marker)

        self.assertTrue(invalidation_index != -1, "Phase 2 marker not found in generated code.")
        self.assertTrue(reexecute_index != -1, "Phase 3 marker not found in generated code.")

        self.assertTrue(reexecute_index > invalidation_index, "Re-execution call must happen after invalidation.")

