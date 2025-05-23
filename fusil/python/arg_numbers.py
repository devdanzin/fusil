"""
Constants and functions to determine numbers of arguments.
"""

import inspect
import re
from random import randint

MAX_ARG = 6
MAX_VAR_ARG = 5
PARSE_PROTOTYPE = True
PROTOTYPE_REGEX = re.compile(r"[A-Za-z]+[A-Za-z_0-9]*\(([^)]*)\)", re.MULTILINE)

METHODS_NB_ARG = {
    "__abs__": 0,
    "__add__": 1,
    "__aenter__": 0,
    "__aexit__": 0,
    "__aiter__": 0,
    "__and__": 1,
    "__anext__": 0,
    "__await__": 0,
    "__bool__": 0,
    "__buffer__": 1,
    "__bytes__": 0,
    "__ceil__": 0,
    "__class_getitem__": 1,
    "__complex__": 0,
    "__contains__": 1,
    "__copy__": 0,
    "__deepcopy__": 1,
    "__delattr__": 1,
    "__delete__": 1,
    "__delitem__": 1,
    "__dir__": 0,
    "__div__": 1,
    "__divmod__": 1,
    "__enter__": 0,
    "__eq__": 1,
    "__exit__": 3,
    "__float__": 0,
    "__floor__": 1,
    "__floordiv__": 0,
    "__format__": 1,
    "__fspath__": 0,
    "__ge__": 1,
    "__get__": 2,
    "__getattr__": 1,
    "__getattribute__": 1,
    "__getitem__": 1,
    "__getnewargs__": 0,
    "__getnewargs_ex__": 0,
    "__getslice__": 2,
    "__getstate__": 0,
    "__gt__": 1,
    "__hash__": 0,
    "__iadd__": 1,
    "__iand__": 1,
    "__idiv__": 1,
    "__ifloordiv__": 0,
    "__ilshift__": 1,
    "__imatmul__": 1,
    "__imod__": 1,
    "__index__": 0,
    "__init_subclass__": 1,
    "__instancecheck__": 1,
    "__int__": 0,
    "__invert__": 0,
    "__ior__": 1,
    "__irshift__": 1,
    "__isub__": 1,
    "__iter__": 0,
    "__itruediv__": 1,
    "__ixor__": 1,
    "__le__": 1,
    "__len__": 0,
    "__length_hint__": 0,
    "__lshift__": 1,
    "__lt__": 1,
    "__matmul__": 1,
    "__missing__": 1,
    "__mod__": 1,
    "__mro_entries__": 0,
    "__ne__": 1,
    "__neg__": 0,
    "__new__": 3,
    "__next__": 1,
    "__or__": 1,
    "__pos__": 0,
    "__post_init__": 2,
    "__prepare__": 0,
    "__radd__": 1,
    "__rand__": 1,
    "__rdivmod__": 1,
    "__reduce__": 0,
    "__reduce_ex__": (0, 1),
    "__release_buffer__": 1,
    "__replace__": 1,
    "__repr__": 0,
    "__reversed__": 0,
    "__rfloordiv__": 0,
    "__rlshift__": 1,
    "__rmatmul__": 1,
    "__rmod__": 1,
    "__ror__": 1,
    "__round__": 0,
    "__rrshift__": 1,
    "__rshift__": 1,
    "__rsub__": 1,
    "__rtruediv__": 1,
    "__rxor__": 1,
    "__set__": 2,
    "__set_name__": 2,
    "__setattr__": 2,
    "__setitem__": 2,
    "__setstate__": 1,
    "__sizeof__": 0,
    "__str__": 0,
    "__sub__": 1,
    "__subclasscheck__": 1,
    "__subclasshook__": 1,
    "__truediv__": 1,
    "__trunc__": 0,
    "__xor__": 1,
    "abs": 1,
    "add": 1,
    "all": 1,
    "any": 1,
    "append": 1,
    "ascii": 1,
    "bin": 1,
    "callable": 1,
    "chr": 1,
    "clear": 0,
    "close": 0,
    "compile": (3, 6),
    "decode": 0,
    "delattr": 2,
    "dir": 1,
    "divmod": 2,
    "encode": 0,
    "eval": (1, 3),
    "exec": 3,
    "format": (1, 2),
    "get": (1, 2),
    "getattr": (2, 3),
    "getvalue": 0,
    "hasattr": 2,
    "hash": 1,
    "hex": 1,
    "isinstance": 2,
    "issubclass": 2,
    "items": 0,
    "iter": (1, 2),
    "join": 1,
    "keys": 0,
    "len": 1,
    "match": 1,
    "max": (1, 4),
    "min": (1, 4),
    "next": (1, 2),
    "oct": 1,
    "open": (1, 8),
    "ord": 1,
    "pop": (0, 1),
    "read": (0, 1),
    "replace": 2,
    "repr": 1,
    "round": (1, 2),
    "setattr": 3,
    "sort": 0,
    "sorted": 1,
    "split": 1,
    "strip": (0, 1),
    "sum": (1, 2),
    "update": 1,
    "values": 0,
    "write": 1,
}
CLASS_NB_ARG = {
    "bool": (1, 1),
    "bytearray": (0, 3),
    "bytes": (0, 3),
    "classmethod": (1, 1),
    "complex": (0, 2),
    "dict": (0, 1),
    "enumerate": (1, 2),
    "filter": (2, 2),
    "float": (1, 1),
    "frozenset": (0, 1),
    "int": (0, 2),
    "list": (0, 1),
    "map": (2, 5),
    "memoryview": (1, 1),
    "object": (0, 0),
    "property": (1, 4),
    "range": (1, 3),
    "reversed": (1, 1),
    "set": (1, 1),
    "slice": (1, 3),
    "staticmethod": (1, 1),
    "str": (0, 3),
    "super": (1, 2),
    "tuple": (0, 1),
    "type": (0, 3),
    "zip": (1, 3),
}


def parseArguments(arguments, defaults):
    for arg in arguments.split(","):
        arg = arg.strip(" \n[]")
        if not arg:
            continue
        if "=" in arg:
            arg, value = arg.split("=", 1)
            defaults[arg] = value
        yield arg


def parsePrototype(doc):
    r"""
    >>> parsePrototype("test([x])")
    ((), None, ('x',), {})
    >>> parsePrototype('dump(obj, file, protocol=0)')
    (('obj', 'file'), None, ('protocol',), {'protocol': '0'})
    >>> parsePrototype('setitimer(which, seconds[, interval])')
    (('which', 'seconds'), None, ('interval',), {})
    >>> parsePrototype("decompress(string[, wbits[, bufsize]])")
    (('string',), None, ('wbits', 'bufsize'), {})
    >>> parsePrototype("decompress(string,\nwbits)")
    (('string', 'wbits'), None, (), {})
    >>> parsePrototype("get_referents(*objs)")
    ((), '*objs', (), {})
    >>> parsePrototype("nothing")
    """
    if not doc:
        return None
    if not isinstance(doc, str):
        return None
    doc = doc.strip()
    match = PROTOTYPE_REGEX.match(doc)
    if not match:
        return None
    arguments = match.group(1)
    if arguments == "...":
        return None
    defaults = {}
    vararg = None
    varkw = tuple()
    if "[" in arguments:
        arguments, varkw = arguments.split("[", 1)
        arguments = tuple(parseArguments(arguments, defaults))
        varkw = tuple(parseArguments(varkw, defaults))
    else:
        arguments = tuple(parseArguments(arguments, defaults))

    # Argument with default value? => varkw
    move = None
    for index in range(len(arguments) - 1, -1, -1):
        arg = arguments[index]
        if arg not in defaults:
            break
        move = index
    if move is not None:
        varkw = arguments[move:] + varkw
        arguments = arguments[:move]

    if arguments and arguments[-1].startswith("*"):
        vararg = arguments[-1]
        arguments = arguments[:-1]
    return arguments, vararg, varkw, defaults


def parseDocumentation(doc, max_var_arg):
    """
    Arguments:
     - doc: documentation string
     - max_var_arg: maximum number of arguments for variable argument,
       eg. test(*args).
    """
    prototype = parsePrototype(doc)
    if not prototype:
        return None

    args, varargs, varkw, defaults = prototype
    min_arg = len(args)
    max_arg = min_arg + len(varkw)
    if varargs:
        max_arg += max_var_arg
    return min_arg, max_arg


def get_arg_number(func, func_name, min_arg):
    try:
        # Known method of arguments?
        value = METHODS_NB_ARG[func_name]
        if isinstance(value, tuple):
            min_arg, max_arg = value
        else:
            min_arg = max_arg = value
        return min_arg, max_arg
    except KeyError:
        pass

    try:
        argspec = inspect.getfullargspec(func)
        has_self = 1 if "self" in argspec.args or "cls" in argspec.args else 0
        args = (len(argspec.args) - has_self) if argspec.args else 0
        defaults = (len(argspec.defaults) - has_self) if argspec.defaults else 0
        return args - defaults, args
    except TypeError:
        pass

    if PARSE_PROTOTYPE:
        # Try using the documentation
        args = parseDocumentation(func.__doc__, MAX_VAR_ARG)
        if args:
            return args
    return min_arg, MAX_ARG


def class_arg_number(class_name, cls):
    import inspect

    if class_name in CLASS_NB_ARG:
        min_args, max_args = CLASS_NB_ARG[class_name]
        nb_arg = randint(min_args, max_args)
    else:
        try:
            argspec = inspect.getfullargspec(cls.__init__)
            args = len(argspec.args) - 1 if argspec.args else 0
            defaults = len(argspec.defaults) if argspec.defaults else 0
            nb_arg = randint(args - defaults, args)
        except TypeError:
            nb_arg = randint(0, 3)
    return nb_arg
