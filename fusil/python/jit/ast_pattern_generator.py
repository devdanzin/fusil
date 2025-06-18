import ast
import copy
import random
from textwrap import dedent
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from fusil.python.write_python_code import WritePythonCode


class ASTPatternGenerator:
    """
    Generates novel JIT-fuzzing patterns from scratch by programmatically
    building an Abstract Syntax Tree.
    """

    def __init__(self, parent: "WritePythonCode"):
        self.parent = parent
        self.arg_generator = parent.arg_generator
        self.known_variables = set()
        self.known_objects: dict[str, set[str]] = {}
        self.prefix_counter = 0

    def _get_prefix(self) -> str:
        """Generates a unique prefix for variable names."""
        self.prefix_counter += 1
        return f"v{self.prefix_counter}"

    def _generate_expression_ast(self, depth: int = 0) -> ast.expr:
        """
        Recursively builds an AST for a random expression. It now has a
        significant chance to generate a simple, non-recursive expression
        to increase the variety of generated tests.
        """
        # --- NEW: Probabilistic choice between simple and complex expressions ---
        # With a 40% chance, generate a very simple expression.
        if random.random() < 0.4 and self.known_variables:

            # Choose between a simple binary operation, or just a single variable/constant.
            if random.random() < 0.7:
                # --- Generate a simple binary operation (e.g., var + 5) ---
                left = ast.Name(id=random.choice(list(self.known_variables)), ctx=ast.Load())

                # The right operand can be another variable or a new constant.
                if random.random() < 0.5 and len(self.known_variables) > 1:
                    right = ast.Name(id=random.choice(list(self.known_variables)), ctx=ast.Load())
                else:
                    right = ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))

                ast_ops = [ast.Add(), ast.Sub(), ast.Mult(), ast.BitAnd(), ast.BitOr(), ast.BitXor()]
                return ast.BinOp(left=left, op=random.choice(ast_ops), right=right)

            else:
                # --- Generate just a single variable or constant ---
                if random.random() < 0.8:
                    return ast.Name(id=random.choice(list(self.known_variables)), ctx=ast.Load())
                else:
                    return ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))

        # --- EXISTING: Fallback to the recursive complex expression generator ---
        if depth > random.randint(1, 2):
            # Base Case for recursion
            if self.known_variables:
                return ast.Name(id=random.choice(list(self.known_variables)), ctx=ast.Load())
            else:
                return ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))

        # Recursive Step for complex expressions
        ast_ops = [
            ast.Add(), ast.Sub(), ast.Mult(), ast.Div(), ast.FloorDiv(), ast.Mod(),
            ast.BitAnd(), ast.BitOr(), ast.BitXor(), ast.LShift(), ast.RShift()
        ]
        chosen_op = random.choice(ast_ops)
        left_operand = self._generate_expression_ast(depth + 1)
        right_operand = self._generate_expression_ast(depth + 1)
        return ast.BinOp(left=left_operand, op=chosen_op, right=right_operand)

    def _create_assignment_node(self) -> ast.Assign:
        """Creates an 'ast.Assign' node (e.g., x = a + b)."""
        # Generate a new variable name and add it to our scope.
        new_var_name = f"var_{self._get_prefix()}"
        self.known_variables.add(new_var_name)

        target = ast.Name(id=new_var_name, ctx=ast.Store())
        value = self._generate_expression_ast()

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
        if not self.known_variables:
            # If no variables exist yet, compare two constants.
            left = ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))
        else:
            left = ast.Name(id=random.choice(list(self.known_variables)), ctx=ast.Load())

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
        target = ast.Name(id=loop_var_name, ctx=ast.Store())
        self.known_variables.add(loop_var_name)

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
                # ast.Delete returns a single node, others might return a list
                if isinstance(new_node, list):
                    statements.extend(new_node)
                else:
                    statements.append(new_node)
        return statements

    def _synthesize_del_attack(self) -> List[ast.stmt]:
        """Synthesizes a full __del__ side-effect attack from scratch."""
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
        target_var = random.choice(list(self.known_variables)) if self.known_variables else 'x'

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
        """Synthesizes a full 'Twin Execution' correctness test."""
        # 1. Generate a random block of code to be the test subject.
        test_body_ast = self.generate_statement_list(num_statements=random.randint(4, 8))

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
            assert compare_results(jit_result, control_result), "JIT correctness bug synthesized!"
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
        self.known_variables.add(instance_name)

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
        Main public method. Makes a high-level strategic choice and calls the
        appropriate synthesizer.
        """
        self.known_variables = set()
        self.known_objects = {}
        self.prefix_counter = 0

        # High-level strategy choice
        if random.random() < 0.3:
            # --- Generate a Correctness Test ---
            statement_nodes = self._synthesize_correctness_test()
        else:
            # --- Generate a Crash/Standard Test ---
            if random.random() < 0.2:
                # With a small chance, synthesize a targeted __del__ attack.
                statement_nodes = self._synthesize_del_attack()
            else:
                # Otherwise, generate a standard block of code.
                statement_nodes = self.generate_statement_list(num_statements=random.randint(2, 15))

        if not statement_nodes:
            statement_nodes = [ast.Pass()]

        module_node = ast.Module(body=statement_nodes, type_ignores=[])
        ast.fix_missing_locations(module_node)

        try:
            return ast.unparse(module_node)
        except AttributeError:
            return "# AST unparsing failed."
