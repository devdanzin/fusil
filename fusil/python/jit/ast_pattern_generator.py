import ast
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
        self.prefix_counter = 0

    def _get_prefix(self) -> str:
        """Generates a unique prefix for variable names."""
        self.prefix_counter += 1
        return f"v{self.prefix_counter}"

    def _generate_expression_ast(self, depth: int = 0) -> ast.expr:
        """
        Recursively builds an AST for a complex, random expression.
        (This is a copy of the helper from our ASTMutator, now used for generation).
        """
        # Base Case: If we are deep enough, return a variable or a constant.
        if depth > random.randint(1, 2):
            if self.known_variables and random.random() < 0.7:
                # Use a variable that we know has been defined.
                return ast.Name(id=random.choice(list(self.known_variables)), ctx=ast.Load())
            else:
                # Create a new, simple constant.
                return ast.Constant(value=int(self.arg_generator.genSmallUint()[0]))

        # Recursive Step: Create a binary operation with new sub-expressions.
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
        """Creates an 'ast.If' node with recursively generated body/orelse blocks."""
        test_condition = self._generate_comparison_ast()

        # Recursively generate the 'if' body.
        body_statements = self.generate_statement_list(random.randint(1, 3), depth + 1)

        # Randomly decide whether to include an 'else' block.
        orelse_statements = []
        if random.random() < 0.5:
            orelse_statements = self.generate_statement_list(random.randint(1, 2), depth + 1)

        return ast.If(test=test_condition, body=body_statements, orelse=orelse_statements)

    def _create_for_node(self, depth: int) -> ast.For:
        """Creates an 'ast.For' node with a recursively generated body."""
        # Create a loop variable, e.g., 'for i_v3 in ...'
        loop_var_name = f"i_{self._get_prefix()}"
        target = ast.Name(id=loop_var_name, ctx=ast.Store())
        self.known_variables.add(loop_var_name)  # The loop var is now in scope

        # Create the iterator, e.g., 'range(10)'.
        iterator = ast.Call(
            func=ast.Name(id='range', ctx=ast.Load()),
            args=[ast.Constant(value=random.randint(5, 50))],
            keywords=[]
        )

        # Recursively generate the loop body.
        body_statements = self.generate_statement_list(random.randint(2, 5), depth + 1)

        return ast.For(target=target, iter=iterator, body=body_statements, orelse=[])

    # --- REVISED Core Generation Loop ---

    def generate_statement_list(self, num_statements: int, depth: int = 0) -> List[ast.stmt]:
        """
        The core generation loop. Creates a sequence of statements, now with
        the potential for nested control flow.
        """
        statements = []

        # The grammar now includes control flow statements.
        statement_grammar = {
            self._create_assignment_node: 0.5,
            self._create_call_node: 0.2,
            self._create_if_node: 0.15,
            self._create_for_node: 0.15,
        }

        # To prevent infinite recursion, limit the depth of control flow.
        max_depth = 2
        if depth >= max_depth:
            # At max depth, only allow simple, non-recursive statements.
            statement_grammar = {
                self._create_assignment_node: 0.7,
                self._create_call_node: 0.3,
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
                statements.append(new_node)
        return statements

    def generate_pattern(self) -> str:
        """
        Main public method. Generates a full pattern as a string.
        """
        self.known_variables = set()  # Reset scope for each new pattern
        self.prefix_counter = 0

        # Generate the body of our new pattern.
        num_statements = random.randint(5, 15)
        statement_nodes = self.generate_statement_list(num_statements)

        # Wrap the statements in a Module node to create a valid tree.
        module_node = ast.Module(body=statement_nodes, type_ignores=[])
        ast.fix_missing_locations(module_node)

        # Unparse the final AST back into a string of Python code.
        try:
            return ast.unparse(module_node)
        except AttributeError:
            return "# AST unparsing failed."

