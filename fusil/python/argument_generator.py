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
try:
    from lafleur.mutator import (
        genLyingEqualityObject,
        genSimpleObject,
        genStatefulBoolObject,
        genStatefulGetattrObject,
        genStatefulGetitemObject,
        genStatefulIndexObject,
        genStatefulIterObject,
        genStatefulLenObject,
        genStatefulStrReprObject,
        genUnstableHashObject,
    )
    HAS_MUTATOR = True
except ImportError:
    genLyingEqualityObject = None
    genSimpleObject = None
    genStatefulBoolObject = None
    genStatefulGetattrObject = None
    genStatefulGetitemObject = None
    genStatefulIndexObject = None
    genStatefulIterObject = None
    genStatefulLenObject = None
    genStatefulStrReprObject = None
    genUnstableHashObject = None
    HAS_MUTATOR = False

ERRBACK_NAME_CONST = "errback"

try:
    from fusil.python.template_strings import TEMPLATES
except ImportError:
    TEMPLATES = []

try:
    from fusil.python import tricky_cereggii
    _HAS_TRICKY_CEREGGII = True
    print("Loaded tricky_cereggii aggregator for ArgumentGenerator.")
except ImportError:
    _HAS_TRICKY_CEREGGII = False
    print("Warning: Could not load tricky_cereggii aggregator for ArgumentGenerator.")
    tricky_cereggii = None # Define for type checking

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
        allow_external_references: bool = True,
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

        is_cereggii_target = (
            self.options.modules == "cereggii" or getattr(self.options, "fuzz_cereggii_scenarios", False)
        )

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

        # Define categories of generators
        safe_hashable_generators = (
            self.genNone, self.genBool, self.genSmallUint, self.genInt,
            self.genLetterDigit, self.genBytes, self.genString, self.genSurrogates,
            self.genAsciiString, self.genUnixPath, self.genFloat,
            self.genExistingFilename, self.genException, self.genRawString,
        )

        safe_simple_generators = safe_hashable_generators + (self.genBufferObject,)

        # These generators produce references to names defined in boilerplate
        external_reference_generators = (
            self.genErrback, self.genWeirdType, self.genWeirdClass,
            self.genWeirdInstance, self.genWeirdUnion, self.genTricky,
            self.genInterestingValues, self.genTrickyObjects,
        )

        self.hashable_argument_generators = safe_hashable_generators
        if allow_external_references:
            # The 'errback' name is hashable but is an external reference
            self.hashable_argument_generators += (self.genErrback,)

        # Build the final lists based on the flag
        self.simple_argument_generators = safe_simple_generators
        if allow_external_references:
            self.simple_argument_generators += external_reference_generators

        self.complex_argument_generators = (
            self.genList, self.genTuple, self.genDict, self.genSet
        )
        if allow_external_references:
            # Add complex generators that rely on external refs
             self.complex_argument_generators += (
                self.genTricky, self.genInterestingValues, self.genWeirdClass,
                self.genWeirdInstance, self.genWeirdType, self.genWeirdUnion,
                self.genTrickyObjects,
            )

        if is_cereggii_target and _HAS_TRICKY_CEREGGII:
            print("Activating cereggii-specific argument generators...")
            # Add hashable cereggii objects
            self.hashable_argument_generators += (
                self.genTrickyAtomicInt64,          # AtomicInt64 is hashable
                self.genTrickyHashableKeyCereggii, # Keys specifically chosen for hashability
            ) * 10 # Weight: make them appear reasonably often

            # Add simple (potentially non-hashable) cereggii objects
            self.simple_argument_generators += (
                self.genTrickyWeirdCereggii,
                self.genTrickyRecursiveCereggii,
                self.genTrickyThreadHandle,
            ) * 10

            # Add complex cereggii objects (AtomicDict itself)
            self.complex_argument_generators += (
                self.genTrickyAtomicDict,
            ) * 10

            # Also add the simple ones to complex, as complex can include simple
            self.complex_argument_generators += (
                self.genTrickyAtomicInt64,
                self.genTrickyHashableKeyCereggii,
                self.genTrickyWeirdCereggii,
                self.genTrickyRecursiveCereggii,
                self.genTrickyThreadHandle,
            ) * 5 # Lower weight here as they are already in simple

        # Handle NumPy, h5py, and t-strings conditionally
        if not self.options.no_numpy and use_numpy and H5PyArgumentGenerator:
            if allow_external_references:
                self.simple_argument_generators += (self.genTrickyNumpy,) * 50
                self.complex_argument_generators += (self.genTrickyNumpy,) * 50
            assert isinstance(self.h5py_argument_generator, H5PyArgumentGenerator)
            self.simple_argument_generators += (self.h5py_argument_generator.genH5PyObject,) * 50

        if not self.options.no_tstrings and use_templates and TEMPLATES and allow_external_references:
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

    def genTrickyAtomicInt64(self) -> list[str]:
        """Generate a reference to a tricky AtomicInt64 instance."""
        # Check if the aggregator and its specific list are available
        if not _HAS_TRICKY_CEREGGII or not tricky_cereggii or not tricky_cereggii.tricky_atomicint64_instance_names:
            # Fallback to creating a simple default instance if tricky ones aren't loaded
            return ["cereggii.AtomicInt64(0)"]
        # Select a random name from the aggregated list
        name = choice(tricky_cereggii.tricky_atomicint64_instance_names)
        # Return the code to access it from the dictionary defined in the boilerplate
        # The name 'tricky_atomic_ints' must match the variable in tricky_atomicint64.py
        return [f"tricky_atomic_ints['{name}']"]

    def genTrickyAtomicDict(self) -> list[str]:
        """Generate a reference to a tricky AtomicDict instance."""
        if not _HAS_TRICKY_CEREGGII or not tricky_cereggii or not tricky_cereggii.tricky_atomicdict_instance_names:
            return ["cereggii.AtomicDict()"]  # Fallback
        name = choice(tricky_cereggii.tricky_atomicdict_instance_names)
        # Assumes 'tricky_atomic_dicts' dict is defined in boilerplate
        return [f"tricky_atomic_dicts['{name}']"]

    def genTrickyWeirdCereggii(self) -> list[str]:
        """Generate a reference to a weird cereggii subclass instance."""
        if not _HAS_TRICKY_CEREGGII or not tricky_cereggii or not tricky_cereggii.tricky_weird_cereggii_instance_names:
            return ["object()"]  # Generic fallback
        name = choice(tricky_cereggii.tricky_weird_cereggii_instance_names)
        # Assumes 'tricky_weird_cereggii_objects' dict is defined in boilerplate
        return [f"tricky_weird_cereggii_objects['{name}']"]

    def genTrickyRecursiveCereggii(self) -> list[str]:
        """Generate a reference to a tricky recursive cereggii object."""
        if not _HAS_TRICKY_CEREGGII or not tricky_cereggii or not tricky_cereggii.tricky_recursive_object_names:
            return ["['recursive_fallback']"]  # Fallback
        name = choice(tricky_cereggii.tricky_recursive_object_names)
        # Assumes 'tricky_recursive_objects' dict is defined in boilerplate
        return [f"tricky_recursive_objects['{name}']"]

    def genTrickyThreadHandle(self) -> list[str]:
        """Generate a reference to a tricky ThreadHandle instance or callable."""
        if not _HAS_TRICKY_CEREGGII or not tricky_cereggii or not tricky_cereggii.tricky_threadhandle_instance_names:
            # Fallback needs a valid object to wrap
            return ["cereggii.ThreadHandle(None)"]
        name = choice(tricky_cereggii.tricky_threadhandle_instance_names)
        # Assumes 'tricky_threadhandle_collection' dict is defined in boilerplate
        return [f"tricky_threadhandle_collection['{name}']"]

    def genTrickyHashableKeyCereggii(self) -> list[str]:
        """Generate a reference to a tricky but hashable object for use as a dict key."""
        # Use the specific list aggregated in tricky_atomicdict.py
        if not _HAS_TRICKY_CEREGGII or not tricky_cereggii or not tricky_cereggii.tricky_hashable_key_names:
            return ["'fallback_key'"]  # Fallback to a simple string
        name = choice(tricky_cereggii.tricky_hashable_key_names)
        # Assumes 'tricky_hashable_keys' dict is defined in boilerplate
        return [f"tricky_hashable_keys['{name}']"]

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

    def generate_subclass_str(self) -> str:
        if random() < 1.1:  # Temporarily no chance
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

        custom_dispatch_table = {}
        if HAS_MUTATOR:
            custom_dispatch_table = {
                'object': genSimpleObject,
                'object_with_method': genSimpleObject,
                'object_with_attr': genSimpleObject,
                'object_with_getitem': genSimpleObject,
                'lying_eq_object': genLyingEqualityObject,
                'stateful_len_object': genStatefulLenObject,
                'unstable_hash_object': genUnstableHashObject,
                'stateful_str_object': genStatefulStrReprObject,
                'stateful_getitem_object': genStatefulGetitemObject,
                'stateful_getattr_object': genStatefulGetattrObject,
                'stateful_bool_object': genStatefulBoolObject,
                'stateful_iter_object': genStatefulIterObject,
                'stateful_index_object': genStatefulIndexObject,
            }

        if p_type == 'any' or (p_type not in simple_dispatch_table and p_type not in custom_dispatch_table):
            # For 'any', we can now also choose one of our new evil objects.
            choices = [
                'int', 'float', 'str', 'list'
            ]
            if HAS_MUTATOR:
                choices += [
                    'object', 'object_with_method', 'object_with_attr', 'object_with_getitem',
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
