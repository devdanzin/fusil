"""
Provides the generative pattern synthesis engine for the JIT fuzzer.

This module contains the `ASTPatternGenerator`, which is the most advanced
component of the JIT fuzzing framework. Unlike the `ASTMutator`, which modifies
existing code, this generator creates entirely new fuzzing patterns from scratch
by programmatically constructing an Abstract Syntax Tree (AST) based on a
weighted grammar of Python statements and expressions.

Its key features include:
- A stateful, two-pass generation process to ensure logical correctness
  (e.g., pre-initializing all variables).
- Synthesis of complex control flow structures (nested loops and conditionals).
- JIT-specific awareness, allowing it to autonomously generate known-buggy
  constructs like `__del__` side-effect attacks and "Twin Execution"
  correctness tests.

This engine is activated by the `--jit-mode=synthesize` command-line option.
"""

import ast
import copy
import random
from textwrap import dedent
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from fusil.python.write_python_code import WritePythonCode

UOP_MAP = {
    '_STORE_ATTR': "target_obj.x = 1",
    '_LOAD_ATTR_MODULE': "math.pi",
    '_DELETE_ATTR': "del target_obj.x",
}


class ASTPatternGenerator:
    """
    Synthesizes novel JIT-fuzzing patterns from scratch.

    This class programmatically builds a complete Python script as an
    Abstract Syntax Tree (AST) from first principles, based on a weighted
    grammar of Python statements and expressions. It is our most advanced
    generative tool.

    Its key architectural features include:
    - A stateful, two-pass generation process: It first generates the main
      logic of the code, discovering all variable names it uses. It then
      prepends a block of initialization statements (`var = None`) to ensure
      the generated code is free of `UnboundLocalError`.
    - The ability to recursively generate complex and nested control flow,
      including `if/else` blocks and `for` loops.
    - JIT-specific awareness, allowing it to autonomously synthesize patterns
      that are known to be stressful for the JIT, such as `__del__`
      side-effect attacks and "Twin Execution" correctness tests.
    """
    def __init__(self, parent: "WritePythonCode"):
        self.parent = parent
        self.arg_generator = parent.arg_generator
        self.scope_variables: set[str] = set()
        self.known_objects: dict[str, set[str]] = {}
        self.prefix_counter = 0

    def _get_prefix(self) -> str:
        """Generates a unique prefix for variable names."""
        self.prefix_counter += 1
        return f"v{self.prefix_counter}"

    def _generate_expression_ast(self, depth: int = 0) -> ast.expr:
        """
        Recursively builds an AST for a random expression.

        This method probabilistically chooses between generating a simple,
        non-recursive expression (e.g., 'var + 5') or a complex, deeply
        nested expression. It ensures that it only uses variables that are
        guaranteed to be in scope to avoid UnboundLocalError.
        """
        # If no variables are known, we MUST return a constant.
        if not self.scope_variables:
            return ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))

        # Base Case for recursion
        if depth > random.randint(1, 2):
            # When ending recursion, we can choose a known variable or a new constant.
            if random.random() < 0.7:
                return ast.Name(id=random.choice(list(self.scope_variables)), ctx=ast.Load())
            else:
                return ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))

        # Recursive Step: We know variables exist, so we can build a complex expression.
        ast_ops = [
            ast.Add(), ast.Sub(), ast.Mult(), ast.Div(), ast.FloorDiv(), ast.Mod(),
            ast.BitAnd(), ast.BitOr(), ast.BitXor(), ast.LShift(), ast.RShift()
        ]
        chosen_op = random.choice(ast_ops)

        # Operands can be new recursive expressions.
        left_operand = self._generate_expression_ast(depth + 1)
        right_operand = self._generate_expression_ast(depth + 1)

        return ast.BinOp(left=left_operand, op=chosen_op, right=right_operand)

    def _create_assignment_node(self) -> ast.Assign:
        """
        Creates an 'ast.Assign' node. This method is now the primary way
        that variables become "known" to the generator.
        """
        new_var_name = f"var_{self._get_prefix()}"
        self.scope_variables.add(new_var_name)

        # If we have known variables, maybe use them in the expression.
        if self.scope_variables and random.random() < 0.8:
            value = self._generate_expression_ast()
        else:
            # Otherwise, force the value to be a simple constant to avoid UnboundLocalError.
            value = ast.Constant(value=int(self.arg_generator.genInt()[0]))

        # After the value is determined, create the target and mark the new variable as known.
        target = ast.Name(id=new_var_name, ctx=ast.Store())
        self.scope_variables.add(new_var_name)

        return ast.Assign(targets=[target], value=value)

    def _create_call_node(self) -> ast.Expr | None:
        """Creates an 'ast.Expr' node wrapping a function call."""
        if not self.parent.module_functions:
            return None

        # Choose a real function from the fuzzed module.
        func_name = random.choice(self.parent.module_functions)

        # Generate arguments for the call.
        num_args = random.randint(0, 2)
        args = []
        for _ in range(num_args):
            # Arguments can be existing variables or new constants.
            args.append(self._generate_expression_ast(depth=2))  # Keep args simple

        call_node = ast.Call(
            func=ast.Attribute(
                value=ast.Name(id=self.parent.module_name, ctx=ast.Load()),
                attr=func_name,
                ctx=ast.Load()
            ),
            args=args,
            keywords=[]
        )
        return ast.Expr(value=call_node)

    def _generate_comparison_ast(self) -> ast.Compare:
        """Generates a random comparison expression, e.g., 'a < b'."""
        if not self.scope_variables:
            # If no variables exist yet, compare two constants.
            left = ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))
        else:
            left = ast.Name(id=random.choice(list(self.scope_variables)), ctx=ast.Load())

        right = self._generate_expression_ast(depth=2)  # Keep comparison simple

        ops = [ast.Eq(), ast.NotEq(), ast.Lt(), ast.LtE(), ast.Gt(), ast.GtE()]
        return ast.Compare(left=left, ops=[random.choice(ops)], comparators=[right])

    def _create_if_node(self, depth: int) -> ast.If:
        """Creates an 'ast.If' node, ensuring the body is never empty."""
        test_condition = self._generate_comparison_ast()

        # Recursively generate the 'if' body.
        body_statements = self.generate_statement_list(random.randint(1, 3), depth + 1)

        if not body_statements:
            body_statements = [ast.Pass()]

        # Randomly decide whether to include an 'else' block.
        orelse_statements = []
        if random.random() < 0.5:
            orelse_statements = self.generate_statement_list(random.randint(1, 2), depth + 1)

        return ast.If(test=test_condition, body=body_statements, orelse=orelse_statements)

    def _create_for_node(self, depth: int) -> ast.For:
        """Creates an 'ast.For' node, ensuring the body is never empty."""
        loop_var_name = f"i_{self._get_prefix()}"
        self.scope_variables.add(loop_var_name)
        target = ast.Name(id=loop_var_name, ctx=ast.Store())

        iterator = ast.Call(
            func=ast.Name(id='range', ctx=ast.Load()),
            args=[ast.Constant(value=random.randint(5, 50))],
            keywords=[]
        )

        # Recursively generate the loop body.
        body_statements = self.generate_statement_list(random.randint(2, 5), depth + 1)

        if not body_statements:
            body_statements = [ast.Pass()]

        return ast.For(target=target, iter=iterator, body=body_statements, orelse=[])

    # --- REVISED Core Generation Loop ---

    def generate_statement_list(self, num_statements: int, depth: int = 0) -> List[ast.stmt]:
        """
        The core generation loop. Creates a sequence of statements, now with
        the potential for nested control flow.
        """
        statements = []

        statement_grammar = {
            self._create_assignment_node: 0.5,
            self._create_call_node: 0.2,
            self._create_attribute_assignment_node: 0.2,
            self._create_attribute_deletion_node: 0.1,
            self._create_if_node: 0.15,
            self._create_for_node: 0.15,
        }

        # To prevent infinite recursion, limit the depth of control flow.
        max_depth = 2
        if depth >= max_depth:
            # At max depth, only allow simple, non-recursive statements.
            statement_grammar = {
                self._create_assignment_node: 0.5,
                self._create_attribute_assignment_node: 0.3,
                self._create_call_node: 0.2,
            }

        for _ in range(num_statements):
            chosen_generator = random.choices(
                population=list(statement_grammar.keys()),
                weights=list(statement_grammar.values()),
                k=1
            )[0]

            # Pass the current depth to generators that need it.
            if chosen_generator in (self._create_if_node, self._create_for_node):
                new_node = chosen_generator(depth)
            else:
                new_node = chosen_generator()

            if new_node:
                if self.parent.options.jit_wrap_statements:
                    # We only wrap simple statements, not control flow structures
                    # as that could lead to invalid syntax (e.g., try: if ...: ...).
                    if isinstance(new_node, (ast.Assign, ast.Expr, ast.Delete)):
                        handler = ast.ExceptHandler(
                            type=ast.Name(id='Exception', ctx=ast.Load()),
                            name=None,
                            body=[ast.Pass()]
                        )
                        # Replace the node with a Try block containing the node.
                        new_node = ast.Try(body=[new_node], handlers=[handler], orelse=[], finalbody=[])

                # ast.Delete returns a single node, others might return a list
                if isinstance(new_node, list):
                    statements.extend(new_node)
                else:
                    statements.append(new_node)
        return statements

    def _synthesize_del_attack(self) -> List[ast.stmt]:
        """
        Synthesizes a full __del__ side-effect attack from scratch.

        This method programmatically constructs the AST for the FrameModifier
        class, a target loop, and the del trigger, recreating the logic of
        our `decref_escapes` pattern generatively.
        """
        # 1. Define the FrameModifier class programmatically.
        fm_class_def_str = dedent("""
            class FrameModifier:
                def __init__(self, name, val):
                    self.name = name
                    self.val = val
                def __del__(self):
                    try:
                        sys._getframe(1).f_locals[self.name] = self.val
                    except Exception:
                        pass
        """)
        fm_class_nodes = ast.parse(fm_class_def_str).body

        # 2. Generate a simple loop body to be the target of the attack.
        body_logic = self.generate_statement_list(num_statements=3)

        # 3. Choose a variable created in the loop body to be the victim.
        target_var = random.choice(list(self.scope_variables)) if self.scope_variables else 'x'

        # 4. Create the setup for the attack.
        fm_instance_creation = ast.Assign(
            targets=[ast.Name(id='fm', ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id='FrameModifier', ctx=ast.Load()),
                args=[ast.Constant(value=target_var), ast.Constant(value='corrupted')],
                keywords=[]
            )
        )

        # 5. Create the trigger.
        del_trigger = ast.Delete(targets=[ast.Name(id='fm', ctx=ast.Del())])

        # 6. Assemble the final attack structure within a loop.
        loop = ast.For(
            target=ast.Name(id='i_del', ctx=ast.Store()),
            iter=ast.Call(func=ast.Name(id='range', ctx=ast.Load()), args=[ast.Constant(value=500)], keywords=[]),
            body=[
                *body_logic,
                # On the penultimate iteration, delete the frame modifier.
                ast.If(
                    test=ast.Compare(left=ast.Name(id='i_del', ctx=ast.Load()), ops=[ast.Eq()],
                                     comparators=[ast.Constant(value=498)]),
                    body=[del_trigger],
                    orelse=[]
                )
            ],
            orelse=[]
        )

        return [*fm_class_nodes, fm_instance_creation, loop]

    def _synthesize_correctness_test(self) -> List[ast.stmt]:
        """
        Synthesizes a full 'Twin Execution' correctness test harness.

        This method generates a random block of code, creates two copies of it,
        wraps them in 'jit_target' and 'control' functions, and appends the
        necessary harness code to warm up the JIT and assert the results.
        """
        # 1. Generate a random block of code to be the test subject.
        test_body_ast = self.generate_statement_list(num_statements=random.randint(4, 8))

        if not test_body_ast:
            test_body_ast = [ast.Pass()]

        # 2. Create the JIT target function.
        jit_target_func = ast.FunctionDef(
            name='jit_target',
            args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=test_body_ast,
            decorator_list=[]
        )

        # 3. Create the Control function with an identical body.
        control_func = ast.FunctionDef(
            name='control',
            args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=copy.deepcopy(test_body_ast),  # Use a deep copy
            decorator_list=[]
        )

        # 4. Programmatically build the harness calls and assertion.
        harness_str = dedent("""
            jit_harness(jit_target, 500)
            jit_result = jit_target()
            control_result = no_jit_harness(control)
            if not compare_results(jit_result, control_result):
                raise JITCorrectnessError(f"JIT CORRECTNESS BUG! JIT: {jit_result}, Control: {control_result}")
        """)
        harness_nodes = ast.parse(harness_str).body

        return [jit_target_func, control_func, *harness_nodes]

    def _create_class_and_instance_nodes(self) -> List[ast.stmt]:
        """Generates a simple class definition and an instance of it."""
        class_name = f"SynthClass_{self._get_prefix()}"
        instance_name = f"synth_instance_{self._get_prefix()}"

        class_def = ast.ClassDef(
            name=class_name,
            bases=[],
            keywords=[],
            body=[ast.Pass()],
            decorator_list=[]
        )

        instance_creation = ast.Assign(
            targets=[ast.Name(id=instance_name, ctx=ast.Store())],
            value=ast.Call(func=ast.Name(id=class_name, ctx=ast.Load()), args=[], keywords=[])
        )

        # Track the new instance and initialize its attribute set
        self.known_objects[instance_name] = set()
        self.scope_variables.add(instance_name)

        return [class_def, instance_creation]

    def _create_attribute_assignment_node(self) -> ast.Assign | None:
        """Creates an 'ast.Assign' node for an attribute (e.g., obj.x = 1)."""
        if not self.known_objects:
            return None  # Can't assign an attribute if no objects exist

        target_obj_name = random.choice(list(self.known_objects.keys()))

        # Decide whether to create a new attribute or reassign an existing one
        if self.known_objects[target_obj_name] and random.random() < 0.5:
            attr_name = random.choice(list(self.known_objects[target_obj_name]))
        else:
            attr_name = f"attr_{self._get_prefix()}"
            self.known_objects[target_obj_name].add(attr_name)

        target = ast.Attribute(
            value=ast.Name(id=target_obj_name, ctx=ast.Load()),
            attr=attr_name,
            ctx=ast.Store()
        )
        value = self._generate_expression_ast()
        return ast.Assign(targets=[target], value=value)

    def _create_attribute_deletion_node(self) -> ast.Delete | None:
        """Creates an 'ast.Delete' node for an attribute (e.g., del obj.x)."""
        # Find an object that has attributes we can delete
        eligible_objects = [name for name, attrs in self.known_objects.items() if attrs]
        if not eligible_objects:
            return None

        target_obj_name = random.choice(eligible_objects)
        attr_to_delete = random.choice(list(self.known_objects[target_obj_name]))

        # Remove the attribute from our known state
        self.known_objects[target_obj_name].remove(attr_to_delete)

        target = ast.Attribute(
            value=ast.Name(id=target_obj_name, ctx=ast.Load()),
            attr=attr_to_delete,
            ctx=ast.Del()
        )
        return ast.Delete(targets=[target])

    def generate_pattern(self) -> str:
        """
        Main public method. Synthesizes a full, novel fuzzing pattern from
        scratch and returns it as a string of Python code.

        This method orchestrates the entire synthesis process. It makes a
        high-level strategic choice (e.g., generate a crash test or a
        correctness test) and then calls the appropriate synthesizer to
        build the pattern's AST. It also manages the two-pass generation
        process to prevent UnboundLocalError.
        """
        # Reset state for the new pattern.
        self.scope_variables = set()
        self.known_objects = {}
        self.prefix_counter = 0

        # --- PASS 1: Generate the main logic ---
        # This will populate self.scope_variables as a side effect.
        num_statements = random.randint(2, 15)
        main_statement_nodes = self.generate_statement_list(num_statements)

        # --- PASS 2: Create and Prepend Initializer Nodes ---
        initializers = []
        for var_name in sorted(list(self.scope_variables)):
            # Create an AST node for `var_name = None`
            assign_node = ast.Assign(
                targets=[ast.Name(id=var_name, ctx=ast.Store())],
                value=ast.Constant(value=None)
            )
            initializers.append(assign_node)

        # Combine the initializers with the main logic.
        final_statement_nodes = initializers + main_statement_nodes

        # Safeguard against empty generation.
        if not final_statement_nodes:
            final_statement_nodes = [ast.Pass()]

        # Unparse the final, complete AST.
        module_node = ast.Module(body=final_statement_nodes, type_ignores=[])
        ast.fix_missing_locations(module_node)

        try:
            return ast.unparse(module_node)
        except AttributeError:
            return "# AST unparsing failed."

    def _collect_assigned_variables(self, nodes: List[ast.stmt]) -> set[str]:
        """
        Walks a list of AST nodes and returns a set of all variable names
        that are assigned to, created in a for loop, or created as a class/function.
        """
        assigned_vars = set()
        for node in nodes:
            # Look for assignment targets (x = ..., y.attr = ...)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned_vars.add(target.id)
            # Look for for-loop variables (for x in ...)
            elif isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    assigned_vars.add(node.target.id)
            # Look for function and class definitions
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assigned_vars.add(node.name)

            # Recursively check inside control flow blocks
            if hasattr(node, 'body'):
                assigned_vars.update(self._collect_assigned_variables(node.body))
            if hasattr(node, 'orelse'):
                assigned_vars.update(self._collect_assigned_variables(node.orelse))

        return assigned_vars

    def generate_uop_targeted_pattern(self, uop_name: str) -> str:
        """
        Generates a pattern specifically designed to stress the given uop.
        """
        self.scope_variables = {'target_obj'}  # Assume a target object exists
        self.prefix_counter = 0

        # 1. Get the minimal Python snippet for the target uop.
        base_snippet = UOP_MAP.get(uop_name)
        if not base_snippet:
            return f"# ERROR: No mapping found for uop '{uop_name}'"

        try:
            # 2. Parse the snippet into an AST node.
            base_ast_node = ast.parse(base_snippet).body[0]
        except (SyntaxError, IndexError):
            return f"# ERROR: Failed to parse snippet for uop '{uop_name}'"

        # 3. Generate a list of "supporting" statements around the core snippet.
        #    This creates a more complex and realistic context for the test.
        num_prefix_statements = random.randint(0, 2)
        num_suffix_statements = random.randint(0, 2)

        prefix_statements = self.generate_statement_list(num_prefix_statements, depth=2)
        suffix_statements = self.generate_statement_list(num_suffix_statements, depth=2)

        # 4. Assemble the final pattern.
        #    Define a simple class for 'target_obj' to operate on.
        setup_nodes = ast.parse(dedent("""
            class Target: pass
            target_obj = Target()
        """)).body

        repeat_base = random.randint(1, 96)
        # The final code places the targeted AST node within other random statements.
        final_statement_nodes = setup_nodes + prefix_statements + [base_ast_node] * repeat_base + suffix_statements

        # 5. Pre-initialize all variables and unparse the final AST.
        all_vars_in_scope = self._collect_assigned_variables(final_statement_nodes)
        initializers = []
        for var_name in sorted(list(all_vars_in_scope)):
            value = random.randint(-2 ** 15, 2 ** 15)
            assign_node = ast.Assign(targets=[ast.Name(id=var_name, ctx=ast.Store())], value=ast.Constant(value=value))
            initializers.append(assign_node)

        final_statement_nodes = initializers + final_statement_nodes

        module_node = ast.Module(body=final_statement_nodes, type_ignores=[])
        ast.fix_missing_locations(module_node)

        return ast.unparse(module_node)
