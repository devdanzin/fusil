"""
Argument Generator for Python Fuzzing

This module provides the ArgumentGenerator class which creates diverse Python values
and expressions for fuzzing function calls. It generates a wide range of argument types
including primitives, collections, edge cases, malformed data, and problematic objects
designed to trigger bugs in Python modules and C extensions.

The generator produces Python source code strings representing arguments. It supports
everything from simple values like integers and strings to complex nested structures,
NumPy arrays, template strings, and specially crafted "tricky" objects that can expose
vulnerabilities through unusual type interactions and boundary conditions.
"""

from __future__ import annotations

from random import choice, randint, sample, random
from textwrap import dedent
from typing import Callable

import fusil.python
from fusil.bytes_generator import BytesGenerator
from fusil.config import FusilConfig
from fusil.python.unicode import escapeUnicode
from fusil.python.values import BUFFER_OBJECTS, INTERESTING, SURROGATES
from fusil.unicode_generator import (
    ASCII8,
    DECIMAL_DIGITS,
    LETTERS,
    UNICODE_65535,
    IntegerGenerator,
    IntegerRangeGenerator,
    UnicodeGenerator,
    UnixPathGenerator,
    UnsignedGenerator,
)

ERRBACK_NAME_CONST = "errback"

try:
    from fusil.python.template_strings import TEMPLATES
except ImportError:
    TEMPLATES = []

try:
    import numpy
except ImportError:
    numpy = None

try:
    import h5py
    import fusil.python.h5py.h5py_tricky_weird
    from fusil.python.h5py.h5py_argument_generator import H5PyArgumentGenerator
except ImportError:
    h5py = None
    H5PyArgumentGenerator = None


class ArgumentGenerator:
    """Handles the generation of diverse argument types for fuzzing."""

    def __init__(
        self,
        options: FusilConfig,
        filenames: list[str],
        use_numpy: bool = False,
        use_templates: bool = True,
        use_h5py: bool = True,
    ):
        """
        Initialize the ArgumentGenerator.

        Args:
            options: Fuzzer configuration options.
            filenames: A list of existing filenames to use for file arguments.
            use_numpy: Whether to use NumPy arrays.
            use_templates: Whether to use template strings (t-strings).
            use_h5py: Whether to use H5Py objects.
        """
        self.options = options
        self.filenames = filenames
        self.errback_name = ERRBACK_NAME_CONST

        self.h5py_argument_generator = H5PyArgumentGenerator(self) if use_h5py and H5PyArgumentGenerator else None

        # Initialize generators for various data types
        self.smallint_generator = IntegerRangeGenerator(-19, 19)
        self.int_generator = IntegerGenerator(20)
        self.bytes_generator = BytesGenerator(0, 20)
        self.unicode_generator = UnicodeGenerator(1, 20, UNICODE_65535)
        self.ascii_generator = UnicodeGenerator(0, 20, ASCII8)
        self.unix_path_generator = UnixPathGenerator(100)
        self.letters_generator = UnicodeGenerator(1, 8, LETTERS | DECIMAL_DIGITS | ASCII8)
        self.float_int_generator = IntegerGenerator(4)
        self.float_float_generator = UnsignedGenerator(4)

        # Define categories of argument generators
        self.hashable_argument_generators: tuple[Callable[[], list[str]], ...] = (
            self.genNone,
            self.genBool,
            self.genSmallUint,
            self.genInt,
            self.genLetterDigit,
            self.genBytes,
            self.genString,
            self.genSurrogates,
            self.genAsciiString,
            self.genUnixPath,
            self.genFloat,
            self.genExistingFilename,
            self.genErrback,
            self.genException,
            self.genRawString,
            self.genWeirdType,
        )
        self.simple_argument_generators: tuple[Callable[[], list[str]], ...] = (
            self.hashable_argument_generators
            + (
                self.genBufferObject,
                self.genInterestingValues,
                self.genWeirdClass,
                self.genWeirdInstance,
                self.genWeirdUnion,
                self.genTrickyObjects,
            )
        )
        if not self.options.no_numpy and use_numpy and H5PyArgumentGenerator:
            self.simple_argument_generators += (self.genTrickyNumpy,) * 50
            assert isinstance(self.h5py_argument_generator, H5PyArgumentGenerator)
            self.simple_argument_generators += (self.h5py_argument_generator.genH5PyObject,) * 50
        self.complex_argument_generators: tuple[Callable[[], list[str]], ...] = (
            self.genList,
            self.genTuple,
            self.genDict,
            self.genTricky,
            self.genInterestingValues,
            self.genWeirdClass,
            self.genWeirdInstance,
            self.genWeirdType,
            self.genWeirdUnion,
            self.genTrickyObjects,
        )

        if not self.options.no_numpy and use_numpy:
            if use_h5py and H5PyArgumentGenerator:
                assert  isinstance(self.h5py_argument_generator, H5PyArgumentGenerator)
                self.simple_argument_generators += (
                    self.h5py_argument_generator.genH5PyObject,
                ) * 50
            self.complex_argument_generators += (self.genTrickyNumpy,) * 50
        if not self.options.no_tstrings and use_templates and TEMPLATES:
            self.complex_argument_generators += (self.genTrickyTemplate,)

    def _create_argument_from_list(
        self, generators: tuple[Callable[[], list[str]], ...]
    ) -> list[str]:
        """Helper to create a single argument using a randomly chosen generator from a list."""
        callback = choice(generators)
        value = callback()
        for item in value:
            if not isinstance(item, str):
                raise ValueError(
                    f"Generator {callback.__name__} returned non-string type {type(item)}"
                )
        return value

    def create_simple_argument(self) -> list[str]:
        """Create a general argument using simple argument generators."""
        return self._create_argument_from_list(self.simple_argument_generators)

    def create_hashable_argument(self) -> list[str]:
        """Create a hashable argument using hashable argument generators."""
        return self._create_argument_from_list(self.hashable_argument_generators)

    def create_complex_argument(self) -> list[str]:
        """Create a potentially complex argument."""
        if randint(1, 10) == 1:  # 10% chance for complex
            generators = self.complex_argument_generators
        else:  # 90% chance for simple
            generators = self.simple_argument_generators
        return self._create_argument_from_list(generators)

    # --- Individual Argument Generation Methods ---
    # These methods return a list of strings, where each string is a line of Python code
    # representing the argument. For multi-line arguments (like dicts), the list will have multiple items.

    def genNone(self) -> list[str]:
        """Generate a 'None' value."""
        return ["None"]

    def genTricky(self) -> list[str]:
        """Generate a 'tricky' or problematic Python object."""
        return [
            choice(
                [
                    "liar1",
                    "liar2",
                    # "lst",
                    "lambda *args, **kwargs: 1/0",
                    "int",
                    "type",
                    "object()",
                    "[[[[[[[[[[[[[[]]]]]]]]]]]]]]",
                    "MagicMock()",
                    "Evil()",
                    "MagicMock",
                    "Evil",
                    "Liar1",
                    "Liar2",
                ]
            )
        ]

    def genBool(self) -> list[str]:
        """Generate a boolean value (True or False)."""
        return [choice(["True", "False"])]

    def genSmallUint(self) -> list[str]:
        """Generate a small unsigned integer string."""
        return [self.smallint_generator.createValue()]

    def genInt(self) -> list[str]:
        """Generate an integer string."""
        return [self.int_generator.createValue()]

    def genBytes(self) -> list[str]:
        """Generate a bytes string literal."""
        bytes_val = self.bytes_generator.createValue()
        text = "".join(f"\\x{byte:02X}" for byte in bytes_val)
        return [f'b"{text}"']

    def genUnixPath(self) -> list[str]:
        """Generate a Unix-like path string."""
        path = self.unix_path_generator.createValue()
        return [f'"{path}"']

    def _gen_unicode_internal(self, generator: UnicodeGenerator) -> list[str]:
        """Helper to generate an escaped Unicode string literal."""
        text = generator.createValue()
        text = escapeUnicode(text)
        return [f'"{text}"']

    def genLetterDigit(self) -> list[str]:
        """Generate a string of letters and digits."""
        return self._gen_unicode_internal(self.letters_generator)

    def genString(self) -> list[str]:
        """Generate a general Unicode string."""
        return self._gen_unicode_internal(self.unicode_generator)

    def genRawString(self) -> list[str]:
        """Generate a raw string, potentially for regex patterns."""
        sequences = (
            [r"\d", r"\D", r"\w", r"\W", r"\s", r"\S", r"\b", r"\B", r"\A", r"\Z"]
            + sorted(LETTERS)
            + ["."] * 10
        )
        special = ["+", "?", "*"]
        result_parts = []
        for _ in range(randint(3, 20)):
            result_parts.append("".join(sample(sequences, randint(1, 3))))
            if randint(0, 9) > 8:  # ~10% chance to add a special char
                result_parts.append(choice(special))
        return [f'r"{"".join(result_parts)}"']

    def genSurrogates(self) -> list[str]:
        """Generate a string containing Unicode surrogate pairs."""
        return [choice(SURROGATES)]

    def genInterestingValues(self) -> list[str]:
        """Generate an 'interesting' predefined value."""
        return [choice(INTERESTING)]

    def genTrickyObjects(self) -> list[str]:
        """Generate a name of a 'tricky' predefined object from tricky_weird."""
        tricky_name = choice(fusil.python.tricky_weird.tricky_objects_names)
        return [tricky_name]

    def genTrickyNumpy(self) -> list[str]:
        """Generate a name of a 'tricky' predefined NumPy object from tricky_weird."""
        tricky_name = choice(fusil.python.tricky_weird.tricky_numpy_names)
        return [tricky_name]

    def genTrickyTemplate(self) -> list[str]:
        """Generate a predefined template string."""
        return [choice(TEMPLATES)]

    def genWeirdClass(self) -> list[str]:
        """Generate a reference to a 'weird' predefined class."""
        weird_class_name = choice(fusil.python.tricky_weird.weird_names)
        return [f"weird_classes['{weird_class_name}']"]

    def genWeirdInstance(self) -> list[str]:
        """Generate a reference to an instance of a 'weird' predefined class."""
        weird_instance_name = choice(fusil.python.tricky_weird.weird_instance_names)
        return [f"weird_instances['{weird_instance_name}']"]

    def genWeirdType(self) -> list[str]:
        """Generate a type hint involving a 'weird' predefined class."""
        weird_class_name = choice(fusil.python.tricky_weird.weird_names)
        type_name = choice(fusil.python.tricky_weird.type_names)
        return [f"{type_name}[weird_classes['{weird_class_name}']]"]

    def genWeirdUnion(self) -> list[str]:
        """Generate a union type hint involving 'weird' predefined classes."""
        weird_class_name1 = choice(fusil.python.tricky_weird.weird_names)
        weird_class_name2 = choice(fusil.python.tricky_weird.weird_names)
        type_name = choice(fusil.python.tricky_weird.type_names)
        return [
            f"{type_name}[weird_classes['{weird_class_name1}']] | weird_classes['{weird_class_name2}'] | big_union"
        ]

    def genBufferObject(self) -> list[str]:
        """Generate a string representing a buffer-like object."""
        return [choice(BUFFER_OBJECTS)]

    def genAsciiString(self) -> list[str]:
        """Generate an ASCII string."""
        return self._gen_unicode_internal(self.ascii_generator)

    def genFloat(self) -> list[str]:
        """Generate a float string."""
        int_part = self.float_int_generator.createValue()
        float_part = self.float_float_generator.createValue()
        return [f"{int_part}.{float_part}"]

    def genExistingFilename(self) -> list[str]:
        """Generate a string of an existing filename."""
        if not self.filenames:
            return ['"NO_FILE_AVAILABLE"']
        filename = choice(self.filenames)
        # Ensure filename is a valid string literal, escaping backslashes and quotes
        return [f"'{filename.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}'"]

    def genErrback(self) -> list[str]:
        """Generate the name of the error callback function."""
        return [self.errback_name]

    def genOpenFile(self) -> list[str]:
        """Generate code to open an existing file."""
        if not self.filenames:
            return ["open('NO_FILE_AVAILABLE')"]  # Fallback
        filename = choice(self.filenames)
        filename_literal = (
            f"'{filename.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}'"
        )
        return [f"open({filename_literal})"]

    def genException(self) -> list[str]:
        """Generate an Exception instance string."""
        return ["Exception('fuzzer_generated_exception')"]

    def _gen_collection_internal(
        self, open_text: str, close_text: str, empty_repr: str, is_dict: bool = False, is_set: bool = False
    ) -> list[str]:
        """Helper to generate code for lists, tuples, or dictionaries."""
        same_type = randint(1, 10) != 1  # 90% same_type
        nb_item = randint(0, 9)

        if not nb_item:
            return [empty_repr]

        items_code_lines: list[list[str]] = []
        if same_type:
            key_generator_func = self.create_hashable_argument if is_dict or is_set else None
            value_generator_func = self.create_simple_argument

            for _ in range(nb_item):
                if is_dict and key_generator_func:
                    current_item_lines = self._create_dict_item_lines(
                        key_generator_func, value_generator_func
                    )
                elif is_set and key_generator_func:
                    current_item_lines = key_generator_func()
                else:
                    current_item_lines = value_generator_func()
                items_code_lines.append(current_item_lines)
        else:  # Mixed types
            for _ in range(nb_item):
                if is_dict:
                    current_item_lines = self._create_dict_item_lines()
                elif is_set:
                    current_item_lines = self.create_hashable_argument()
                else:
                    current_item_lines = self.create_simple_argument()
                items_code_lines.append(current_item_lines)

        if not items_code_lines:
            return [empty_repr]

        final_lines: list[str] = []
        first_item_code = "".join(items_code_lines[0])
        final_lines.append(open_text + first_item_code)

        for item_lines_list in items_code_lines[1:]:
            item_code = "".join(item_lines_list)
            final_lines[-1] += ","
            final_lines.append(" " + item_code)

        if nb_item == 1 and empty_repr == "tuple()":
            final_lines[-1] += ","
        final_lines[-1] += close_text
        return final_lines

    def _create_dict_item_lines(
        self,
        key_generator_func: Callable[[], list[str]] | None = None,
        value_generator_func: Callable[[], list[str]] | None = None,
    ) -> list[str]:
        """Generate a key-value pair for a dictionary literal as a list of code lines."""
        key_lines = key_generator_func() if key_generator_func else self.create_hashable_argument()
        value_lines = (
            value_generator_func() if value_generator_func else self.create_simple_argument()
        )

        key_code = " ".join(key_lines)
        value_code = " ".join(value_lines)
        return [f"{key_code}: {value_code}"]

    def genList(self) -> list[str]:
        """Generate a list literal string."""
        return self._gen_collection_internal("[", "]", "[]")

    def genTuple(self) -> list[str]:
        """Generate a tuple literal string."""
        return self._gen_collection_internal("(", ")", "tuple()")

    def genDict(self) -> list[str]:
        """Generate a dictionary literal string."""
        return self._gen_collection_internal("{", "}", "{}", True)

    def genSet(self) -> list[str]:
        """Generate a set literal string."""
        return self._gen_collection_internal("{", "}", "set()", is_set=True)

    def genSimpleObject(self, var_name: str) -> str:
        class_name = f"C_{var_name}"  # We can use var_name because it will be unique
        setup_code = (dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self.x = 1
                    self.y = 'y'
                    self.value = "value"
                def get_value(self):
                    return self.value
                def __getitem__(self, item):
                    return 5
            {var_name} = {class_name}()
        """))
        return setup_code

    def genLyingEqualityObject(self, var_name: str) -> str:
        """
        Generates a class that lies about equality.
        __eq__ and __ne__ both always return True.
        """
        class_name = f"LyingEquality_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                eq_count = 0
                ne_count = 0
                def __eq__(self, other):
                    self.eq_count += 1
                    if self.eq_count < 70:
                        if not self.eq_count % 20:
                            print("[EVIL] LyingEquality __eq__ called, returning True", file=sys.stderr)
                        return True
                def __ne__(self, other):
                    self.ne_count += 1
                    if self.ne_count < 70:
                        if not self.ne_count % 20:
                            print("[EVIL] LyingEquality __ne__ called, returning True", file=sys.stderr)
                        return True
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulLenObject(self, var_name: str) -> str:
        """
        Generates a class whose __len__ changes on each call.
        """
        class_name = f"StatefulLen_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self.len_count = 0
                def __len__(self):
                    _len = 0 if self.len_count < 70 else 99
                    if not self.len_count % 20:
                        print(f"[EVIL] StatefulLen __len__ called, returning {{_len}}", file=sys.stderr)
                    self.len_count += 1
                    return _len
            {var_name} = {class_name}()
        """)
        return setup_code

    def genUnstableHashObject(self, var_name: str) -> str:
        """
        Generates a class whose __hash__ is different on each call.
        """
        class_name = f"UnstableHash_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                hash_count = 0
                def __hash__(self):
                    # Violates the rule that hash must be constant for the object's lifetime.
                    self.hash_count += 1
                    new_hash = 5 if self.hash_count < 70 else randint(0, 2**64 - 1)
                    if not self.hash_count % 20:
                        print(f"[EVIL] UnstableHash __hash__ called, returning {{new_hash}}", file=sys.stderr)
                    return new_hash
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulStrReprObject(self, var_name: str) -> str:
        """
        Generates a class with stateful __str__ and __repr__ methods.
        __repr__ will eventually return a non-string type to cause a TypeError.
        """
        class_name = f"StatefulStrRepr_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self._str_count = 0
                    self._repr_count = 0
                    self._str_options = ['a', 'b', 'c']
                def __str__(self):
                    val = "a" if self._str_count < 67 else b'a'
                    if not self._str_count % 20:
                        print(f"[EVIL] StatefulStrRepr __str__ called, returning '{{val}}'", file=sys.stderr)
                    self._str_count += 1
                    return val
                def __repr__(self):
                    self._repr_count += 1
                    if self._repr_count > 70:
                        if not self._repr_count % 20:
                            print("[EVIL] StatefulStrRepr __repr__ called, returning NON-STRING type 123", file=sys.stderr)
                        return 123  # Violates contract, should raise TypeError
                    val = f"<StatefulRepr run #{{self._repr_count}}>"
                    if not self._repr_count % 20:
                        print(f"[EVIL] StatefulStrRepr __repr__ called, returning '{{val}}'", file=sys.stderr)
                    return val
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulGetitemObject(self, var_name: str) -> str:
        """
        Generates a class whose __getitem__ returns different types based on call count.
        """
        class_name = f"StatefulGetitem_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self._getitem_count = 0
                def __getitem__(self, key):
                    self._getitem_count += 1
                    if self._getitem_count > 67:
                        if not self._getitem_count % 20:
                            print(f"[EVIL] StatefulGetitem __getitem__ returning float", file=sys.stderr)
                        return 99.9
                    if not self._getitem_count % 20:
                        print(f"[EVIL] StatefulGetitem __getitem__ returning int", file=sys.stderr)
                    return 5
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulGetattrObject(self, var_name: str) -> str:
        """
        Generates a class whose __getattr__ returns different values based on call count.
        """
        class_name = f"StatefulGetattr_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self._getattr_count = 0
                def __getattr__(self, name):
                    self._getattr_count += 1
                    if self._getattr_count > 67:
                        if not self._getattr_count % 20:
                            print(f"[EVIL] StatefulGetattr __getattr__ for '{{name}}' returning 'evil_attribute'", file=sys.stderr)
                        return b'evil_attribute'
                    if not self._getattr_count % 20:
                        print(f"[EVIL] StatefulGetattr __getattr__ for '{{name}}' returning 'normal_attribute'", file=sys.stderr)
                    return 'normal_attribute'
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulBoolObject(self, var_name: str) -> str:
        """
        Generates a class whose __bool__ result flips after a few calls.
        """
        class_name = f"StatefulBool_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self._bool_count = 0
                def __bool__(self):
                    self._bool_count += 1
                    if self._bool_count > 70:
                        if not self._bool_count % 20:
                            print("[EVIL] StatefulBool __bool__ flipping to False", file=sys.stderr)
                        return False
                    if not self._bool_count % 20:
                        print("[EVIL] StatefulBool __bool__ returning True", file=sys.stderr)
                    return True
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulIterObject(self, var_name: str) -> str:
        """
        Generates a class whose __iter__ returns different iterators.
        """
        class_name = f"StatefulIter_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self._iter_count = 0
                    self._iterable = [1, 2, 3]
                def __iter__(self):
                    if not self._iter_count % 20:
                        print(f"[EVIL] StatefulIter __iter__ yielding from {{self._iterable!r}}", file=sys.stderr)
                    self._iter_count += 1
                    if self._iter_count > 67:
                        return iter((None,))
                    return iter(self._iterable)
            {var_name} = {class_name}()
        """)
        return setup_code

    def genStatefulIndexObject(self, var_name: str) -> str:
        """
        Generates a class whose __index__ returns different integer values.
        """
        class_name = f"StatefulIndex_{var_name}"
        setup_code = dedent(f"""
            class {class_name}{self.generate_subclass_str()}:
                def __init__(self):
                    self._index_count = 0
                def __index__(self):
                    self._index_count += 1
                    if self._index_count > 70:
                        if not self._index_count % 20:
                            print("[EVIL] StatefulIndex __index__ returning 99", file=sys.stderr)
                        return 99 # A different, potentially out-of-bounds index
                    if not self._index_count % 20:
                        print("[EVIL] StatefulIndex __index__ returning 0", file=sys.stderr)
                    return 0
            {var_name} = {class_name}()
        """)
        return setup_code

    def generate_subclass_str(self) -> str:
        if random() < 0.1:  # Temporary high chance for testing if it works
            return ""
        bases = ('int', 'float', 'str', 'bytes', 'tuple', 'list', 'dict', 'set')
        if random() > 0.1:
            base = self.genWeirdClass()[0]
        else:
            base = choice(bases)
        return f"({base})"

    def generate_arg_by_type(self, p_type, var_name: str) -> str:
        """
        Generates setup code for a given placeholder type.

        Args:
            p_type: The type hint for the placeholder (e.g., 'int', 'list').
            var_name: The base name for the variable to be created.
        Returns: The setup_code for the variable.
        """
        simple_dispatch_table = {
            'int': self.genInt,
            'float': self.genFloat,
            'str': self.genString,
            'list': self.genList,
            'tuple': self.genTuple,
            'set': self.genSet,
            'dict': self.genDict,
            'small_int': self.genSmallUint,
        }

        custom_dispatch_table = {
            'object': self.genSimpleObject,
            'object_with_method': self.genSimpleObject,
            'object_with_attr': self.genSimpleObject,
            'object_with_getitem': self.genSimpleObject,
            'lying_eq_object': self.genLyingEqualityObject,
            'stateful_len_object': self.genStatefulLenObject,
            'unstable_hash_object': self.genUnstableHashObject,
            'stateful_str_object': self.genStatefulStrReprObject,
            'stateful_getitem_object': self.genStatefulGetitemObject,
            'stateful_getattr_object': self.genStatefulGetattrObject,
            'stateful_bool_object': self.genStatefulBoolObject,
            'stateful_iter_object': self.genStatefulIterObject,
            'stateful_index_object': self.genStatefulIndexObject,
        }

        if p_type == 'any' or (p_type not in simple_dispatch_table and p_type not in custom_dispatch_table):
            # For 'any', we can now also choose one of our new evil objects.
            choices = [
                'int', 'float', 'str', 'list', 'object', 'object_with_method',
                'object_with_attr', 'object_with_getitem',
                'lying_eq_object', 'stateful_len_object', 'unstable_hash_object',
                'stateful_str_object', 'stateful_getitem_object', 'stateful_getattr_object',
                'stateful_bool_object', 'stateful_iter_object', 'stateful_index_object',
            ]
            chosen_type = choice(choices)
            return self.generate_arg_by_type(chosen_type, var_name)
        elif p_type in simple_dispatch_table:
            return f"{var_name} = {'\n'.join(simple_dispatch_table[p_type]())}"
        else:
            return custom_dispatch_table[p_type](var_name)

    def get_random_object_type(self, evil_boost: int = 4) -> str:
        normal = [
            'int', 'float', 'str', 'list', 'object', 'object_with_method',
            'object_with_attr', 'object_with_getitem',
        ]
        evil = [
            'lying_eq_object', 'stateful_len_object', 'unstable_hash_object',
            'stateful_str_object', 'stateful_getitem_object', 'stateful_getattr_object',
            'stateful_bool_object', 'stateful_iter_object', 'stateful_index_object',
        ]
        return choice(normal + evil * evil_boost)
