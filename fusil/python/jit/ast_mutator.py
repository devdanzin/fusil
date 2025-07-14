"""
Provides the AST-based structural mutation engine for the JIT fuzzer.

This module contains the `ASTMutator` class and its library of `NodeTransformer`
subclasses. Its purpose is to take a string of valid Python code, parse it into
an Abstract Syntax Tree (AST), and then apply a randomized pipeline of
transformations to structurally alter the code.

This allows the fuzzer to generate novel variations of existing bug patterns
that go beyond simple value or operator changes. The transformations include
swapping operators, perturbing constants, duplicating statements, and changing
container types, among others.

This engine is primarily used by the variational fuzzer when the
`--jit-fuzz-ast-mutation` flag is enabled.
"""

import ast
import builtins
import random
import copy
import sys
from textwrap import dedent


class OperatorSwapper(ast.NodeTransformer):
    """Swaps binary operators like + with *, avoiding ast.Pow."""

    # A rich suite of plausible substitutions for arithmetic and bitwise operators.
    OP_MAP = {
        # Arithmetic Operators, without Pow because it generates huge numbers
        ast.Add: [ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod],
        ast.Sub: [ast.Add, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod],
        ast.Mult: [ast.Add, ast.Sub, ast.Div, ast.FloorDiv],
        ast.Div: [ast.Mult, ast.Add, ast.Sub, ast.FloorDiv],
        ast.FloorDiv: [ast.Div, ast.Mult, ast.Add, ast.Sub, ast.Mod],
        ast.Mod: [ast.FloorDiv, ast.Add, ast.Sub],

        # Bitwise Operators, without LShift because it generates huge numbers
        ast.LShift: [ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor],
        ast.RShift: [ast.BitAnd, ast.BitOr, ast.BitXor],
        ast.BitAnd: [ast.BitOr, ast.BitXor, ast.RShift],
        ast.BitOr: [ast.BitAnd, ast.BitXor, ast.RShift],
        ast.BitXor: [ast.BitAnd, ast.BitOr, ast.RShift],
    }

    def visit_BinOp(self, node):
        op_type = type(node.op)
        if op_type in self.OP_MAP and random.random() < 0.3:
            new_op_class = random.choice(self.OP_MAP[op_type])
            node.op = new_op_class()
        return node


class ComparisonSwapper(ast.NodeTransformer):
    """Swaps comparison operators like < with >="""
    OP_MAP = {
        ast.Lt: ast.GtE, ast.GtE: ast.Lt,
        ast.Gt: ast.LtE, ast.LtE: ast.Gt,
        ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
        ast.Is: ast.IsNot, ast.IsNot: ast.Is,
    }

    def visit_Compare(self, node):
        if random.random() < 0.5:
            new_ops = [self.OP_MAP.get(type(op), type(op))() for op in node.ops]
            node.ops = new_ops
        return node


class ConstantPerturbator(ast.NodeTransformer):
    """Slightly modifies numeric and string constants."""

    def visit_Constant(self, node):
        if isinstance(node.value, int) and random.random() < 0.3:
            node.value += random.choice([-1, 1, 2])
        elif isinstance(node.value, str) and node.value and random.random() < 0.3:
            pos = random.randint(0, len(node.value) - 1)
            char_val = ord(node.value[pos])
            new_char = chr(char_val + random.choice([-1, 1]))
            node.value = node.value[:pos] + new_char + node.value[pos + 1:]
        return node


class GuardInjector(ast.NodeTransformer):
    """Wraps random statements in an 'if' block."""

    def visit(self, node):
        # First, visit children to avoid infinite recursion
        node = super().visit(node)
        # Only wrap nodes that are statements
        if isinstance(node, ast.stmt) and not isinstance(node, ast.FunctionDef) and random.random() < 0.05:
            test = ast.Compare(
                left=ast.Call(func=ast.Name(id='random', ctx=ast.Load()), args=[], keywords=[]),
                ops=[ast.Lt()],
                comparators=[ast.Constant(value=0.9)]
            )
            return ast.If(test=test, body=[node], orelse=[])
        return node


class ContainerChanger(ast.NodeTransformer):
    """Changes container types, e.g., list to tuple or set."""

    def visit_List(self, node):
        if random.random() < 0.5:
            return ast.Set(elts=node.elts)
        elif random.random() < 0.5:
            return ast.Tuple(elts=node.elts, ctx=node.ctx)
        return node

    def visit_ListComp(self, node):
        if random.random() < 0.5:
            return ast.SetComp(elt=node.elt, generators=node.generators)
        return node


class VariableSwapper(ast.NodeTransformer):
    """Swaps occurrences of two variable names in a scope."""

    _static_protected_names = frozenset({
        'print', 'random', 'next', 'isinstance', 'sys', 'operator',
        'range', 'len', 'object', 'Exception', 'BaseException', 'collect'
    })

    _exception_names = {
        name for name, obj in builtins.__dict__.items()
        if isinstance(obj, type) and issubclass(obj, BaseException)
    }

    PROTECTED_NAMES = _static_protected_names.union(_exception_names)

    def __init__(self):
        self.var_map = {}

    def visit_Module(self, node):
        # Scan for all names used in the module
        all_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

        # Filter out the protected names to get our list of swappable candidates
        swappable_names = sorted(list(all_names - self.PROTECTED_NAMES))

        if len(swappable_names) >= 2:
            # Only choose from the safe, swappable names
            a, b = random.sample(swappable_names, 2)
            self.var_map = {a: b, b: a}

        self.generic_visit(node)
        return node

    def visit_Name(self, node):
        node.id = self.var_map.get(node.id, node.id)
        return node


class StatementDuplicator(ast.NodeTransformer):
    """Duplicates a statement."""

    def visit(self, node):
        node = super().visit(node)
        if isinstance(node, ast.stmt) and not isinstance(node, (ast.FunctionDef, ast.ClassDef,
                                                                ast.Module)) and random.random() < 0.1:
            return [node, copy.deepcopy(node)]
        return node


class VariableRenamer(ast.NodeTransformer):
    """
    A NodeTransformer that renames variables based on a provided mapping.
    This is used by the splicing strategy to make a donor harness compatible
    with a recipient's setup code.
    """
    def __init__(self, remapping_dict: dict[str, str]):
        self.remapping_dict = remapping_dict

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """
        If this node's ID is in our remapping dictionary, rename it.
        This affects variables being loaded, stored, or deleted.
        """
        if node.id in self.remapping_dict:
            node.id = self.remapping_dict[node.id]
        return node


# ==============================================================================
# Stress Pattern Injection Engine
# ==============================================================================

# Note: These functions are adapted from ASTPatternGenerator and made generic.

def _create_type_corruption_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generates code to corrupt the type of a variable (e.g., `x = 'string'`)."""
    corruption_value = random.choice([
        ast.Constant(value="corrupted by string"),
        ast.Constant(value=None),
        ast.Constant(value=123.456),
    ])
    return [ast.Assign(targets=[ast.Name(id=target_var, ctx=ast.Store())], value=corruption_value)]


def _create_uop_attribute_deletion_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generates code to delete an attribute (e.g., `del obj.x`)."""
    attr_to_delete = random.choice(['value', 'x', 'y'])
    return [ast.Delete(targets=[ast.Attribute(
        value=ast.Name(id=target_var, ctx=ast.Load()),
        attr=attr_to_delete,
        ctx=ast.Del()
    )])]


def _create_method_patch_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generates code to monkey-patch a method (e.g., `obj.meth = ...`)."""
    method_to_patch = random.choice(['get_value', 'meth', '__repr__'])
    lambda_payload = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[], vararg=ast.arg(arg='a'), kwarg=ast.arg(arg='kw'), kw_defaults=[],
                           defaults=[]),
        body=ast.Constant(value='patched!')
    )
    return [ast.Assign(
        targets=[ast.Attribute(
            value=ast.Attribute(value=ast.Name(id=target_var, ctx=ast.Load()), attr='__class__', ctx=ast.Load()),
            attr=method_to_patch,
            ctx=ast.Store()
        )],
        value=lambda_payload
    )]


def _create_dict_swap_node(var1_name: str, var2_name: str, **kwargs) -> list[ast.stmt]:
    """Generates AST for: obj1.__dict__, obj2.__dict__ = obj2.__dict__, obj1.__dict__"""
    return [ast.Assign(
        targets=[ast.Tuple(
            elts=[
                ast.Attribute(value=ast.Name(id=var1_name, ctx=ast.Load()), attr='__dict__', ctx=ast.Store()),
                ast.Attribute(value=ast.Name(id=var2_name, ctx=ast.Load()), attr='__dict__', ctx=ast.Store())
            ],
            ctx=ast.Store()
        )],
        value=ast.Tuple(
            elts=[
                ast.Attribute(value=ast.Name(id=var2_name, ctx=ast.Load()), attr='__dict__', ctx=ast.Load()),
                ast.Attribute(value=ast.Name(id=var1_name, ctx=ast.Load()), attr='__dict__', ctx=ast.Load())
            ],
            ctx=ast.Load()
        )
    )]


def _create_class_reassignment_node(target_var: str, **kwargs) -> list[ast.stmt]:
    """Generates AST for: class NewClass: pass; obj.__class__ = NewClass"""
    new_class_name = f"SwappedClass_{random.randint(1000, 9999)}"
    class_def_node = ast.ClassDef(
        name=new_class_name, bases=[], keywords=[], body=[ast.Pass()], decorator_list=[]
    )
    assign_node = ast.Assign(
        targets=[ast.Attribute(value=ast.Name(id=target_var, ctx=ast.Load()), attr='__class__', ctx=ast.Store())],
        value=ast.Name(id=new_class_name, ctx=ast.Load())
    )
    return [class_def_node, assign_node]


class StressPatternInjector(ast.NodeTransformer):
    """
    A NodeTransformer that, with a small probability, injects a hand-crafted
    "evil" stress pattern into a function's body.
    """

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # First, visit children to allow them to be transformed.
        self.generic_visit(node)

        # Probabilistically decide whether to inject a pattern into this function.
        if random.random() < 0.15:  # 15% chance
            # 1. Find all variables that are assigned to in this function's scope.
            local_vars = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            if not local_vars:
                return node  # No variables to target.

            target_var = random.choice(list(local_vars))

            # 2. Choose an evil action to perform.
            # Note: _create_dict_swap_node requires two variables.
            single_target_actions = [
                _create_type_corruption_node, _create_uop_attribute_deletion_node,
                _create_method_patch_node, _create_class_reassignment_node
            ]
            if len(local_vars) >= 2:
                action = random.choice(single_target_actions + [_create_dict_swap_node])
            else:
                action = random.choice(single_target_actions)

            print(f"    -> Injecting stress pattern '{action.__name__}' targeting '{target_var}'", file=sys.stderr)

            # 3. Generate the evil snippet's AST nodes.
            if action == _create_dict_swap_node:
                var1, var2 = random.sample(list(local_vars), 2)
                snippet_nodes = action(var1_name=var1, var2_name=var2)
            else:
                snippet_nodes = action(target_var=target_var)

            # 4. Insert the snippet at a random point in the function body.
            if node.body:
                insert_pos = random.randint(0, len(node.body))
                node.body[insert_pos:insert_pos] = snippet_nodes

        return node


class ASTMutator:
    """
    An engine for structurally modifying Python code at the AST level.

    This class takes a string of valid Python code, parses it into an
    Abstract Syntax Tree (AST), and then applies a randomized pipeline of
    `ast.NodeTransformer` subclasses to it. Each transformer is responsible
    for a specific kind of mutation, such as swapping operators, perturbing
    constants, or duplicating statements.

    The final, mutated AST is then unparsed back into a string of Python code,
    which can be executed by the fuzzer. This allows for the creation of
    novel and unpredictable variations of existing bug patterns.
    """
    def __init__(self):
        self.transformers = [
            OperatorSwapper,
            ComparisonSwapper,
            ConstantPerturbator,
            GuardInjector,
            ContainerChanger,
            VariableSwapper,
            # StatementDuplicator,
        ]

    def mutate_ast(self, tree: ast.AST, seed: int = None, mutations: int | None = None) -> tuple[ast.AST, list[type]]:
        """
        Applies a random pipeline of AST mutations directly to an AST object.

        This is a more efficient version of mutate() for use when the AST
        is already available, avoiding an unparse/re-parse cycle.

        Args:
            tree: The AST object to be mutated.
            seed: An optional integer to seed the random number generator.
            mutations: An optional integer to specify the number of mutations.

        Returns:
            The new, mutated AST object.
        """
        if seed is not None:
            random.seed(seed)

        # Randomly select 1 to 3 transformers to apply
        num_mutations = mutations if mutations is not None else random.randint(1, 3)
        chosen_transformers = random.choices(self.transformers, k=num_mutations)

        if isinstance(tree, list):
            tree = ast.Module(body=tree, type_ignores=[])

        for transformer_class in chosen_transformers:
            transformer_instance = transformer_class()
            tree = transformer_instance.visit(tree)

        ast.fix_missing_locations(tree)
        return tree.body, chosen_transformers

    def mutate(self, code_string: str, seed: int = None, mutations: int | None = None) -> str:
        """
        Parses code, applies a random pipeline of AST mutations, and unparses
        it back into a string.

        This is the main public method of the mutator. It takes a string of
        Python code and applies a randomized sequence of 1 to 3 different
        NodeTransformer subclasses to its AST, structurally altering the code.

        Args:
            code_string: The Python code to be mutated.
            seed: An optional integer to seed the random number generator,
                  ensuring a deterministic (reproducible) mutation pipeline.

        Returns:
            A string containing the new, mutated Python code.
        """
        try:
            tree = ast.parse(dedent(code_string))
        except SyntaxError:
            return f"# Original code failed to parse:\n# {'#'.join(code_string.splitlines())}"

        mutated_tree, _ = self.mutate_ast(tree, seed=seed, mutations=mutations)

        try:
            return ast.unparse(mutated_tree)
        except AttributeError:
            return f"# AST unparsing failed. Original code was:\n# {code_string}"
