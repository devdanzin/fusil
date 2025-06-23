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

from fusil.write_code import CodeTemplate as CT
if TYPE_CHECKING:
    from fusil.python.write_python_code import WritePythonCode

UOP_RECIPES = {
    # --- Attribute and Subscript Operations ---
    '_STORE_ATTR': {
        'pattern': "{target_obj}.x = {value}",
        'placeholders': {'target_obj': 'object', 'value': 'any'}
    },
    '_LOAD_ATTR_METHOD_WITH_VALUES': {
        'pattern': "_ = {target_obj}.get_value()",
        'placeholders': {'target_obj': 'object_with_method'}
    },
    '_BINARY_SUBSCR_LIST_INT': {
        'pattern': "_ = {target_list}[{index}]",
        'placeholders': {'target_list': 'list', 'index': 'small_int'}
    },
    '_BINARY_OP_SUBSCR_GETITEM': {
        'pattern': "_ = {target_obj}[{key}]",
        'placeholders': {'target_obj': 'object_with_getitem', 'key': 'any'}
    },
    '_DELETE_ATTR': {
        'pattern': "del {target_obj}.x; {target_obj}.x = 1",  # We cannot simply delete sequentially
        'placeholders': {'target_obj': 'object_with_attr'}
    },

    # --- Binary Operations ---
    '_BINARY_OP_ADD_INT': {
        'pattern': "{result_var} = {operand_a} + {operand_b}",
        'placeholders': {'result_var': 'new_variable', 'operand_a': 'int', 'operand_b': 'int'}
    },
    '_BINARY_OP_ADD_FLOAT': {
        'pattern': "{result_var} = {operand_a} + {operand_b}",
        'placeholders': {'result_var': 'new_variable', 'operand_a': 'float', 'operand_b': 'float'}
    },
    '_BINARY_OP_MULTIPLY_TUPLE_INT': {
        'pattern': "{result_var} = {operand_a} * {operand_b}",
        'placeholders': {'result_var': 'new_variable', 'operand_a': 'tuple', 'operand_b': 'small_int'}
    },

    # --- Collection and Iteration ---
    '_BUILD_LIST': {
        'pattern': "{result_var} = [{val_a}, {val_b}, {val_c}]",
        'placeholders': {'result_var': 'new_variable', 'val_a': 'any', 'val_b': 'any', 'val_c': 'any'}
    },
    '_CONTAINS_OP_DICT': {
        'pattern': "_ = {key} in {target_dict}",
        'placeholders': {'key': 'any', 'target_dict': 'dict'}
    },
    '_CALL_LIST_APPEND': {
        'pattern': "{target_list}.append({value})",
        'placeholders': {'target_list': 'list', 'value': 'any'}
    },
    '_FOR_ITER_LIST': {
        'pattern': "for {loop_var} in {target_list}: pass",
        'placeholders': {'loop_var': 'new_variable', 'target_list': 'list'}
    },

    # --- Compare and Boolean Operations ---
    '_COMPARE_OP_INT': {
        'pattern': "_ = {operand_a} > {operand_b}",
        'placeholders': {'operand_a': 'int', 'operand_b': 'int'}
    },
    '_TO_BOOL_INT': {
        'pattern': "if {target_int}: pass",
        'placeholders': {'target_int': 'int'}
    },
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
        Generates a pattern specifically designed to stress the given uop
        by using a template from the UOP_RECIPES library.
        """
        self.scope_variables = set()
        self.prefix_counter = 0

        # 1. Get the recipe for the target uop.
        recipe = UOP_RECIPES.get(uop_name)
        if not recipe:
            return f"# ERROR: No recipe found for uop '{uop_name}'"

        # Generate setup code and substitutions for the placeholders.
        setup_template = CT("""
                    # --- Setup for {uop_name} ---
                    a = 1
                    b = 2

                    class Target: pass
                    target_obj = Target()

                    class TargetWithMethod:
                        value = 5
                        def get_value(self):
                            return self.value
                    target_obj_with_method = TargetWithMethod()

                    class TargetWithAttr:
                        x = 5
                    target_obj_with_attr = TargetWithAttr()

                    class TargetWithGetItem:
                        def __getitem__(self, item):
                            return 5
                    target_obj_with_getitem = TargetWithGetItem()

                    target_list = list(range(-100, 101))
                    target_dict = {x: x for x in target_list}
                    target_tuple = tuple(target_list)

                """)
        setup_code = setup_template.render(uop_name=uop_name)

        substitutions = {}
        # We need a predictable set of variables to use.
        # This can be expanded later to be more dynamic.
        var_map = {
            'int': ['a', 'b'],
            'object': ['target_obj'],
            'object_with_method': ['target_obj_with_method'],
            'object_with_attr': ['target_obj_with_attr'],
            'object_with_getitem': ['target_obj_with_getitem'],
            'list': ['target_list'],
            'dict': ['target_dict'],
            'tuple': ['target_tuple'],
        }

        for placeholder, type_hint in recipe['placeholders'].items():
            if type_hint == 'new_variable':
                substitutions[placeholder] = f"res_{uop_name.lower().replace('_', '')}"
                continue

            use_variable = type_hint in var_map and random.random() < 0.5
            if use_variable:
                substitutions[placeholder] = random.choice(var_map[type_hint])
            else:
                if type_hint == 'int':
                    substitutions[placeholder] = self.arg_generator.genInt()[0]
                elif type_hint == 'small_int':
                    substitutions[placeholder] = self.arg_generator.genSmallUint()[0]
                elif type_hint == 'float':
                    substitutions[placeholder] = self.arg_generator.genFloat()[0]
                elif type_hint == 'object':
                    substitutions[placeholder] = "target_obj"
                elif type_hint == 'object_with_method':
                    substitutions[placeholder] = "target_obj_with_method"
                elif type_hint == 'object_with_attr':
                    substitutions[placeholder] = "target_obj_with_attr"
                elif type_hint == 'object_with_getitem':
                    substitutions[placeholder] = "target_obj_with_getitem"
                elif type_hint == 'list':
                    substitutions[placeholder] = "target_list"
                elif type_hint == 'dict':
                    substitutions[placeholder] = "target_dict"
                elif type_hint == 'tuple':
                    substitutions[placeholder] = "target_tuple"
                else:  # Default 'any' or other types to a simple integer.
                    substitutions[placeholder] = self.arg_generator.genInt()[0]

            # --- Core Pattern Generation ---
        core_code_str = recipe['pattern'].format(**substitutions)
        core_repeats = random.randint(67, 134) # Repeat the core op many times

        # --- NEW: Evil Snippet Injection Logic ---
        final_core_logic_nodes = []
        # First, parse the "friendly" core pattern into AST nodes.
        core_ast_nodes = ast.parse(dedent(core_code_str)).body * core_repeats

        # Decide whether to inject an evil snippet.
        # This will be controlled by the --jit-uop-evilness-prob flag later.
        evil_print = ""
        if random.random() < 1.25: # 25% chance of being evil for now
            evil_print = self.parent.write_print_to_stderr(
                0, f'"[{self._get_prefix()}] Injecting EVIL snippet into uop-targeted pattern!"', return_str=True
            )

            # Find a suitable variable to attack from the recipe's placeholders.
            target_var_placeholder = next((p for p, t in recipe['placeholders'].items() if 'object' in t), None)

            if target_var_placeholder:
                target_var_name = substitutions.get(target_var_placeholder)
                target_var_type = recipe['placeholders'][target_var_placeholder]

                # Generate the evil AST nodes.
                evil_nodes = self._generate_evil_snippet(target_var_name, target_var_type)

                # Inject the evil snippet right before the last core operation.
                final_core_logic_nodes.extend(core_ast_nodes[:-1])
                final_core_logic_nodes.extend(evil_nodes)
                final_core_logic_nodes.append(core_ast_nodes[-1])
            else:
                # If no suitable variable to attack, just generate the friendly code.
                final_core_logic_nodes.extend(core_ast_nodes)
        else:
            final_core_logic_nodes.extend(core_ast_nodes)

        module_node = ast.Module(body=final_core_logic_nodes, type_ignores=[])
        ast.fix_missing_locations(module_node)
        # Unparse the final list of core logic nodes back into a string.
        core_code = ast.unparse(module_node)

        # --- Final Assembly ---
        final_template = CT("""
            # Uop-targeted test for: {uop_name}
            {evil_print}
            {setup}

            # --- Core Pattern ---
            {core}
        """)

        final_code = final_template.render(
            uop_name=uop_name,
            setup=setup_code,
            core=core_code,
            evil_print=evil_print,
        )
        return final_code


    def _generate_evil_snippet(self, target_var: str, target_var_type: str) -> List[ast.stmt]:
        """
        Selects and generates a random "evil snippet" of code designed to
        violate the JIT's assumptions about a target variable.

        Args:
            target_var: The name of the variable to attack.
            target_var_type: A hint about the variable's original type
                             (e.g., 'object_with_method', 'int').

        Returns:
            A list of AST statement nodes representing the evil snippet.
        """
        # This is our menu of evil actions. We can add more over time.
        evil_actions = [
            self._create_type_corruption_node,
            self._create_uop_attribute_deletion_node,
            self._create_method_patch_node,
        ]

        # Some actions only make sense for objects.
        if target_var_type not in ('object', 'object_with_method', 'object_with_attr'):
            # For simple types like 'int', only type corruption is applicable.
            chosen_action = self._create_type_corruption_node
        else:
            chosen_action = random.choice(evil_actions)

        return chosen_action(target_var)

    def _create_type_corruption_node(self, target_var: str) -> List[ast.stmt]:
        """Generates code to corrupt the type of a variable (e.g., `x = 'string'`)."""
        # Choose a random, incompatible type to corrupt the variable with.
        corruption_value = random.choice([
            ast.Constant(value="corrupted by string"),
            ast.Constant(value=None),
            ast.Constant(value=123.456),
        ])

        return [ast.Assign(
            targets=[ast.Name(id=target_var, ctx=ast.Store())],
            value=corruption_value
        )]

    def _create_uop_attribute_deletion_node(self, target_var: str) -> List[ast.stmt]:
        """Generates code to delete an attribute (e.g., `del obj.x`)."""
        # Try to delete a common but potentially unexpected attribute.
        attr_to_delete = random.choice(['x', 'value', 'payload', '_private'])

        return [ast.Delete(targets=[ast.Attribute(
            value=ast.Name(id=target_var, ctx=ast.Load()),
            attr=attr_to_delete,
            ctx=ast.Del()
        )])]

    def _create_method_patch_node(self, target_var: str) -> List[ast.stmt]:
        """Generates code to monkey-patch a method (e.g., `obj.meth = ...`)."""
        # Target a common method name.
        method_to_patch = 'get_value'

        # The payload is a simple lambda that returns a constant.
        lambda_payload = ast.Lambda(
            args=ast.arguments(args=[], posonlyargs=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
            body=ast.Constant(value='patched!')
        )

        # Generate: `target_var.__class__.get_value = lambda: 'patched!'`
        # Patching the class is more effective for JIT invalidation.
        return [ast.Assign(
            targets=[ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id=target_var, ctx=ast.Load()),
                    attr='__class__',
                    ctx=ast.Load()
                ),
                attr=method_to_patch,
                ctx=ast.Store()
            )],
            value=lambda_payload
        )]