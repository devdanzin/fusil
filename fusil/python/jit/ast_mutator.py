import ast
import builtins
import random
import copy


# --- Step 3: A Library of Initial Mutation Strategies ---

class OperatorSwapper(ast.NodeTransformer):
    """Swaps binary operators like + with *."""
    OP_MAP = {
        ast.Add: [ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod],
        ast.Sub: [ast.Add, ast.Mult],
        ast.Mult: [ast.Add, ast.Sub, ast.Pow],
        # Add more mappings as needed...
    }

    def visit_BinOp(self, node):
        op_type = type(node.op)
        if op_type in self.OP_MAP and random.random() < 0.5:
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
        if isinstance(node, ast.stmt) and not isinstance(node, ast.FunctionDef) and random.random() < 0.1:
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
        'range', 'len', 'object', 'Exception', 'BaseException'
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


# --- Step 1 & 4: The Main Mutator Class and Pipeline ---

class ASTMutator:
    def __init__(self):
        self.transformers = [
            OperatorSwapper,
            ComparisonSwapper,
            ConstantPerturbator,
            GuardInjector,
            ContainerChanger,
            VariableSwapper,
            StatementDuplicator,
        ]

    def mutate(self, code_string: str) -> str:
        """
        Parses code, applies a random pipeline of AST mutations,
        and unparses it back to a string.
        """
        try:
            tree = ast.parse(code_string)
        except SyntaxError:
            return f"# Original code failed to parse:\n# {code_string}"

        # Randomly select 1 to 3 transformers to apply
        num_mutations = random.randint(1, 3)
        chosen_transformers = random.sample(self.transformers, num_mutations)

        for transformer_class in chosen_transformers:
            transformer_instance = transformer_class()
            tree = transformer_instance.visit(tree)

        ast.fix_missing_locations(tree)

        try:
            return ast.unparse(tree)
        except AttributeError:
            return f"# AST unparsing failed. Original code was:\n# {code_string}"
