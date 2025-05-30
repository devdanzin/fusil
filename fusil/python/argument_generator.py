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

import sys
from random import choice, randint, random, sample, uniform
from typing import Callable
import uuid

import h5py
import numpy

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
    TEMPLATES = None


def _h5_unique_name(base="item"):
    return f"{base}_{uuid.uuid4().hex[:8]}"


class ArgumentGenerator:
    """Handles the generation of diverse argument types for fuzzing."""

    def __init__(
        self,
        options: FusilConfig,
        filenames: list[str],
        use_numpy: bool = False,
        use_templates: bool = True,
    ):
        """
        Initialize the ArgumentGenerator.

        Args:
            options: Fuzzer configuration options.
            filenames: A list of existing filenames to use for file arguments.
            use_numpy: Whether to use NumPy arrays.
            use_templates: Whether to use template strings (t-strings).
        """
        self.options = options
        self.filenames = filenames
        self.errback_name = ERRBACK_NAME_CONST

        # Initialize generators for various data types
        self.smallint_generator = IntegerRangeGenerator(-19, 19)
        self.int_generator = IntegerGenerator(20)
        self.bytes_generator = BytesGenerator(0, 20)
        self.unicode_generator = UnicodeGenerator(1, 20, UNICODE_65535)
        self.ascii_generator = UnicodeGenerator(0, 20, ASCII8)
        self.unix_path_generator = UnixPathGenerator(100)
        self.letters_generator = UnicodeGenerator(
            1, 8, LETTERS | DECIMAL_DIGITS | ASCII8
        )
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
        if not self.options.no_numpy and use_numpy:
            self.simple_argument_generators += (self.genTrickyNumpy,) * 50
            self.simple_argument_generators += (self.genH5PyObject,) * 50
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
            self.simple_argument_generators += (self.genH5PyObject,) * 50
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

    def genH5PyObject(self) -> list[str]:
        """Generate a name of a 'tricky' predefined h5py object from tricky_weird."""
        tricky_name = choice(fusil.python.tricky_weird.tricky_h5py_names)
        return [f"h5py_tricky_objects.get('{tricky_name}')"]

    def genH5PyFileMode(self) -> list[str]:
        modes = ['r', 'r+', 'w', 'w-', 'x', 'a']
        modes += ["rw", "z", "wa"]
        return [f"'{choice(modes)}'"]

    def genH5PyFileDriver(self) -> list[str]:
        drivers = ['core', 'sec2', 'stdio', 'direct', 'split', 'fileobj', None]  # None for default
        # Add invalid driver names too
        drivers += ["mydriver", "\\x00"]
        chosen_driver = choice(drivers)
        return [f"'{chosen_driver}'" if chosen_driver else "None"]

    def genH5PyLibver(self) -> list[str]:
        versions = ['earliest', 'latest', 'v108', 'v110', 'v112', 'v114']  # Valid up to HDF5 1.14.x
        choice_type = randint(0, 2)
        if choice_type == 0:  # Single string
            return [f"'{choice(versions)}'"]
        elif choice_type == 1:  # Tuple
            low = choice(versions)
            high = choice(versions)  # Could ensure low <= high logic if desired
            return [f"('{low}', '{high}')"]
        else:  # None (default)
            return ["None"]

    def genH5PyUserblockSize(self) -> list[str]:
        valid_sizes = [0, 512, 1024, 2048, 4096, 8192]  # 0 means no userblock
        invalid_sizes = [256, 513, 1000]
        chosen_size = choice(valid_sizes + invalid_sizes if random() < 0.3 else valid_sizes)
        return [str(chosen_size)]

    def genH5PyFsStrategyKwargs(self) -> list[str]:
        kwargs = []
        strategy = choice(["page", "fsm", "aggregate", "none", "invalid_strat", None])
        if strategy:
            kwargs.append(f"fs_strategy='{strategy}'")
            if strategy == "page":
                if random() < 0.7: kwargs.append(f"fs_persist={choice([True, False])}")
                if random() < 0.7: kwargs.append(f"fs_threshold={choice([1, 64, 128, 256])}")
                if random() < 0.7: kwargs.append(f"fs_page_size={choice([4096, 16384])}")
                if random() < 0.5:  # Page buffer options
                    pbs = choice([4096, 16384, 32768])
                    kwargs.append(f"page_buf_size={pbs}")
                    # These min_meta_keep/min_raw_keep are percentages 0-100
                    if random() < 0.5: kwargs.append(f"min_meta_keep={randint(0, 100)}")
                    if random() < 0.5: kwargs.append(f"min_raw_keep={randint(0, 100)}")
        return [", ".join(kwargs)] if kwargs else [""]

    def genH5PyLocking(self) -> list[str]:
        options = [True, False, 'best-effort', 'invalid_lock_opt', None]
        chosen = choice(options)
        if isinstance(chosen, str): return [f"'{chosen}'"]
        return [str(chosen)]

    # In ArgumentGenerator
    def genH5PyFileDriver_actualval(self) -> str | None:  # Returns the actual string or None
        drivers = ['core', 'sec2', 'stdio', 'direct', 'split', 'fileobj', None]
        return choice(drivers)

    def genH5PyFileMode_actualval(self) -> str:
        modes = ['r', 'r+', 'w', 'w-', 'x', 'a']
        return choice(modes)

    def gen_h5py_file_name_or_object(self, actual_driver: str | None, actual_mode: str, is_core_backing: bool) -> tuple[
        str, list[str]]:
        setup_lines = []
        if actual_driver == 'fileobj':
            # Ensure io, tempfile are imported in the generated script
            name_expr = f"io.BytesIO()"  # Simpler than TemporaryFile for pure in-memory
        elif actual_driver == 'core' and not is_core_backing:
            name_expr = f"'mem_core_{uuid.uuid4().hex}'"
        else:  # Needs a disk path
            var_name = f"temp_disk_path_{uuid.uuid4().hex[:6]}"
            # This logic creates a filename string. It doesn't create the file on disk yet.
            # That's h5py.File's job for 'w' modes. For 'r'/'r+', the file needs to exist.
            setup_lines.append(f"{var_name}_fd, {var_name} = tempfile.mkstemp(suffix='.h5', prefix='fuzz_')")
            setup_lines.append(f"os.close({var_name}_fd)")
            # Critical: For 'r', 'r+' mode, this temp file is empty. h5py.File will fail.
            # It needs to be a valid (even if empty) HDF5 file, or a specific non-HDF5 file for error testing.
            if actual_mode in ('r', 'r+'):
                # This is where it gets complex for dynamic generation.
                # Easiest is to pre-create a valid HDF5 file and use its path.
                # Or, for error testing, a non-HDF5 file.
                # For now, let's assume if we need to read, we're using a pre-made path
                # from tricky_h5py_code or the fuzzer won't choose r/r+ for random disk paths.
                # A simpler approach for generation: if r/r+ for disk, make it readable by writing first.
                setup_lines.append(f"# Path for {var_name} generated; for 'r'/'r+' ensure it's pre-populated if new.")
                # If we *must* make it valid for 'r'/'r+' here:
                # setup_lines.append(f"with h5py.File({var_name}, 'w') as pre_f: pre_f.create_group('init')")
            name_expr = var_name
            # Track var_name for deletion at end of script if required
        return name_expr, setup_lines

    # genH5PyDriverKwargs should take actual_driver string
    def genH5PyDriverKwargs(self, actual_driver_str_val: str | None) -> list[str]:
        kwargs_parts = []  # e.g., ["backing_store=False", "block_size=1024"]
        if actual_driver_str_val == 'core':
            if random() < 0.8:  # High chance to specify backing_store for core
                bs = choice([True, False])
                kwargs_parts.append(f"backing_store={bs}")
                if not bs and random() < 0.5:  # block_size more relevant if no backing for some HDF5 internal things
                    kwargs_parts.append(f"block_size={choice([512, 4096, 65536])}")
                elif bs and random() < 0.2:  # Less chance if backing_store=True as it might be ignored
                    kwargs_parts.append(f"block_size={choice([512, 4096])}")

        # Add other driver specific kwargs for 'direct', etc.
        # ...
        return ["", ", ".join(kwargs_parts)][
            len(kwargs_parts) > 0]  # Returns empty string or ", kwarg1=val1, kwarg2=val2"

    def genH5PySimpleDtype_expr(self) -> str:
        """Generates a Python expression string for a simple NumPy dtype."""
        # Focusing on basic types for Category B
        simple_dtypes = [
            "'i1'", "'i2'", "'i4'", "'i8'",
            "'u1'", "'u2'", "'u4'", "'u8'",
            "'f2'", "'f4'", "'f8'",
            "'bool'"
        ]
        # Add occasional numpy.dtype() wrapping for variety if desired
        if random() < 0.2:
            return f"numpy.dtype({choice(simple_dtypes)})"
        return choice(simple_dtypes)

    def genH5PyDatasetShape_expr(self) -> str:
        """Generates a Python expression string for a dataset shape."""
        choice = randint(0, 6)
        if choice == 0:
            return "()"  # Scalar
        elif choice == 1:
            return "None"  # Null dataspace (requires dtype)
        elif choice == 2:
            return f"({randint(0, 5)},)"  # 1D, possibly zero-length
        elif choice == 3:
            # 2D, possibly with a zero-length dimension
            d1 = randint(0, 10)
            d2 = randint(0, 3) if d1 > 0 and random() < 0.5 else randint(1, 10)
            return f"({d1}, {d2})"
        elif choice == 4:
            # 3D
            return f"({randint(1, 5)}, {randint(1, 5)}, {randint(1, 5)})"
        elif choice == 5:
            return str(randint(1, 20))  # Integer shape for 1D
        else:  # Higher chance for simple 1D
            return f"({randint(1, 50)},)"

    def genH5PyData_expr(self, shape_expr_str: str, dtype_expr_str: str) -> str:
        """Generates a Python expression for dataset data, or None."""
        choice_int = randint(0, 4)
        if choice_int == 0:
            return "None"  # Let h5py initialize or use fillvalue
        elif choice_int == 1:  # Scalar data (h5py will broadcast if shape allows, or error)
            dt_val = eval(dtype_expr_str)  # Risky, but for simple types here might be okay
            if numpy.issubdtype(dt_val, numpy.integer): return str(randint(0, 100))
            if numpy.issubdtype(dt_val, numpy.floating): return str(round(random() * 100, 2))
            if numpy.issubdtype(dt_val, numpy.bool_): return choice(["True", "False"])
            return "None"  # Fallback for other simple types
        elif choice_int == 2:  # h5py.Empty
            return f"h5py.Empty(dtype={dtype_expr_str})"
        elif choice_int == 3 and shape_expr_str != "None" and shape_expr_str != "()":
            # Attempt to create a compatible numpy array
            # This is complex to make perfectly compatible via string generation.
            # Simplification: small arange if 1D, otherwise zeros.
            try:
                shape_val = eval(shape_expr_str)
                if isinstance(shape_val, int): shape_val = (shape_val,)  # Make tuple
                if isinstance(shape_val, tuple) and len(shape_val) > 0 and all(isinstance(d, int) for d in shape_val):
                    if len(shape_val) == 1 and shape_val[0] < 200 and shape_val[0] >= 0:  # only for small 1D
                        return f"numpy.arange({shape_val[0]}, dtype={dtype_expr_str})"
                    # else: return f"numpy.zeros({shape_expr_str}, dtype={dtype_expr_str})" # For N-D
            except:
                pass  # If shape_expr_str is not eval-able or complex
            return f"numpy.zeros({shape_expr_str}, dtype={dtype_expr_str})" if shape_expr_str != "None" else "None"

        return "None"  # Default

    def genH5PyDatasetChunks_expr(self, shape_expr_str: str) -> str:
        """Generates a Python expression for dataset chunks."""
        choice = randint(0, 4)
        if choice == 0:
            return "True"  # Auto-chunk
        elif choice == 1:
            return "None"  # Contiguous (or error if maxshape set)
        elif choice == 2:  # Explicit chunks
            try:
                # Attempt to make somewhat valid chunks based on shape
                shape_val = eval(shape_expr_str)
                if isinstance(shape_val, int): shape_val = (shape_val,)
                if isinstance(shape_val, tuple) and all(isinstance(d, int) and d > 0 for d in shape_val):
                    chunks = tuple(max(1, d // randint(1, 4)) for d in shape_val)
                    return str(chunks)
                elif isinstance(shape_val, tuple) and any(d == 0 for d in shape_val):  # Has zero dim
                    return "None"  # Cannot chunk if a dim is zero
            except:
                pass  # Fallback if shape_expr is weird
            return f"({randint(1, 10)},)"  # Fallback simple chunk
        elif choice == 3:
            return "False"  # Can cause ValueError if maxshape is also set
        else:  # Invalid chunk tuple (e.g., too many dims, or larger than shape)
            return f"({randint(100, 200)}, {randint(100, 200)})"

    def genH5PyFillvalue_expr(self, dtype_expr_str: str) -> str:
        """Generates a Python expression for a fillvalue compatible with simple dtypes."""
        try:
            # This eval is to determine the kind of dtype for generating a compatible fillvalue
            # It's used locally and doesn't go into the final generated script if it fails.
            dt_val = eval(dtype_expr_str)
            if numpy.issubdtype(dt_val, numpy.integer):
                return str(randint(-100, 100))
            elif numpy.issubdtype(dt_val, numpy.floating):
                return choice([str(round(uniform(-100, 100), 2)), "numpy.nan", "numpy.inf", "-numpy.inf"])
            elif numpy.issubdtype(dt_val, numpy.bool_):
                return choice(["True", "False"])
        except:
            pass  # Fallback if dtype_expr_str is complex or not recognized
        return "None"  # Let h5py use default

    def genH5PyFillTime_expr(self) -> str:
        """Generates a Python expression for dataset fill_time."""
        options = ['ifset', 'never', 'alloc', 'invalid_fill_time_option']
        return f"'{choice(options)}'"

    def genH5PyMaxshape_expr(self, shape_expr_str: str) -> str:
        """Generates a Python expression for dataset maxshape."""
        choice = randint(0, 3)
        if choice == 0:
            return "None"  # Unlimited on all axes implied by current shape

        try:
            # Try to make a maxshape compatible with or larger than shape_expr_str
            shape_val = eval(shape_expr_str)
            if isinstance(shape_val, int): shape_val = (shape_val,)

            if isinstance(shape_val, tuple) and all(isinstance(d, int) for d in shape_val):
                maxs = []
                for dim_size in shape_val:
                    axis_choice = randint(0, 2)
                    if axis_choice == 0:
                        maxs.append("None")
                    elif axis_choice == 1:
                        maxs.append(str(dim_size + randint(0, 10)))
                    else:
                        maxs.append(str(dim_size))  # Same as shape
                return f"({', '.join(maxs)}{',' if len(maxs) == 1 else ''})"  # Ensure tuple format
        except:
            pass  # Fallback if shape_expr_str is weird

        if shape_expr_str != "None" and shape_expr_str != "()":
            # Fallback: make one axis unlimited
            return f"(None, {randint(1, 10)})" if "()," in shape_expr_str or "," in shape_expr_str else "(None,)"
        return "None"

    def genH5PyTrackTimes_expr(self) -> str:
        """Generates a Python expression for dataset track_times."""
        options = [True, False, "'invalid_track_times_val'"]
        return str(choice(options))

    def genH5PyCompressionKwargs_expr(self) -> list[str]:  # Returns list of "kwarg=value" strings
        """Generates Python expressions for compression related kwargs."""
        kwargs_list = []

        # Choose compression algorithm
        if random() < 0.7:  # 70% chance to apply some compression/filter
            comp_choice = randint(0, 5)
            if comp_choice == 0 and 'gzip' in h5py.filters.encode:
                kwargs_list.append("compression='gzip'")
                if random() < 0.5:  # Chance to add opts
                    kwargs_list.append(f"compression_opts={randint(0, 9)}")
            elif comp_choice == 1 and 'lzf' in h5py.filters.encode:
                kwargs_list.append("compression='lzf'")
            # Szip can be problematic if not available, skip for now unless specifically targeted
            # elif comp_choice == 2 and 'szip' in h5py.filters.encode:
            #     kwargs_list.append("compression='szip'")
            #     opts = choice([('ec', 8), ('nn', 16)]) # Example opts
            #     kwargs_list.append(f"compression_opts={opts}")
            elif comp_choice == 3:  # Generic integer filter ID
                kwargs_list.append(
                    f"compression={choice([1, h5py.h5z.FILTER_DEFLATE, 257])}")  # 257 for testing allow_unknown
                if random() < 0.3: kwargs_list.append("allow_unknown_filter=True")
                if "FILTER_DEFLATE" in kwargs_list[-1]:  # if gzip by ID
                    kwargs_list.append(f"compression_opts=({randint(0, 9)},)")

            # Add other filters randomly, these can be combined with compression or used alone
            if random() < 0.4 and 'shuffle' in h5py.filters.encode:
                kwargs_list.append(f"shuffle={choice([True, False])}")

            if random() < 0.3 and 'fletcher32' in h5py.filters.encode:
                kwargs_list.append(f"fletcher32={choice([True, False])}")

            if random() < 0.3 and 'scaleoffset' in h5py.filters.encode:
                # scaleoffset needs chunks. Ensure chunks=True is passed if this is chosen,
                # or that this kwarg is only added if chunks are already enabled.
                # For now, just generate it; caller must ensure chunking if using scaleoffset.
                so_val = choice(
                    [True, randint(0, 16)])  # Bool for auto-int, or nbits for int, or factor for float
                kwargs_list.append(f"scaleoffset={so_val}")

        return kwargs_list

    # In ArgumentGenerator
    def genH5PyVlenDtype_expr(self) -> str:
        base_dtypes = ["numpy.int16", "numpy.float32", "numpy.bool_", "h5py.string_dtype(encoding='ascii')"]
        return f"h5py.vlen_dtype({choice(base_dtypes)})"

    def genH5PyEnumDtype_expr(self) -> str:
        base_types = ["'i1'", "'u2'", "numpy.intc"]
        enum_dict_str = str(
            {f"VAL_{chr(65 + i)}": i for i in range(randint(2, 5))})  # E.g. "{'VAL_A':0, 'VAL_B':1}"
        return f"h5py.enum_dtype({enum_dict_str}, basetype={choice(base_types)})"

    def genH5PyCompoundDtype_expr(self) -> str:
        # This is simplified. A robust version would build more complex structures.
        fields = []
        num_fields = randint(1, 3)
        for i in range(num_fields):
            fname = f"'field_{i}_{uuid.uuid4().hex[:4]}'"
            ftype_choice = randint(0, 3)
            if ftype_choice == 0:
                ftype = self.genH5PySimpleDtype_expr()
            elif ftype_choice == 1:
                ftype = self.genH5PyVlenDtype_expr()  # Can be nested
            elif ftype_choice == 2:
                ftype = f"'{choice(['S', 'U'])}{randint(5, 15)}'"  # Fixed string
            else:
                ftype = "'(2,)i4'"  # Array field
            fields.append(f"({fname}, {ftype})")
        return f"numpy.dtype([{', '.join(fields)}])"

    def genH5PyComplexDtype_expr(self) -> str:  # Top-level chooser
        options = [
            self.genH5PySimpleDtype_expr,
            lambda: f"h5py.string_dtype(encoding='{choice(['ascii', 'utf-8'])}', length={choice([None, 5, 20])})",
            self.genH5PyVlenDtype_expr,
            self.genH5PyEnumDtype_expr,
            self.genH5PyCompoundDtype_expr,
            lambda: f"'({randint(2, 5)},)i2'",  # Simple array dtype
            lambda: "h5py.ref_dtype",
            lambda: "h5py.regionref_dtype"
        ]
        # Add chance to pick from committed types (if names are known to AG)
        # if h5py_tricky_objects_committed_type_names:
        #    options.append(lambda: f"_h5_main_file['{choice(h5py_tricky_objects_committed_type_names)}']")
        return choice(options)()


    def genH5PySliceForDirectIO_expr(self, dataset_rank: int) -> str:
        """Generates a slice expression string for read_direct/write_direct."""
        if random() < 0.2: return "None"
        if random() < 0.2: return "numpy.s_[...]"  # Ellipsis

        slices = []
        for _ in range(int(dataset_rank)):
            choice_int = randint(0, 3)
            if choice_int == 0:
                slices.append(":")  # Full slice for this axis
            elif choice_int == 1:
                slices.append(str(randint(0, 5)))  # Single index
            else:  # start:stop or start:stop:step
                start = randint(0, 10)
                stop = start + randint(1, 10)
                if random() < 0.3:  # chance for step
                    step = choice([1, 2, 3, -1, -2])
                    slices.append(f"{start}:{stop}:{step}")
                else:
                    slices.append(f"{start}:{stop}")
        return f"numpy.s_[{', '.join(slices)}]"

    def genH5PySliceForDirectIO_expr_runtime(self, rank_variable_name_in_script: str) -> str:
        """
        Generates a Python expression string that, when executed, calls a helper
        to create a slice tuple based on the runtime rank.
        Args:
            rank_variable_name_in_script: The string name of the variable in the
                                          generated script that will hold the rank.
        Returns:
            A string like "_fusil_h5_create_dynamic_slice_for_rank(actual_rank_var)"
        """
        # Small chance to return simple generic slices directly, bypassing the helper
        if random() < 0.1:
            return "None"
        if random() < 0.1:
            return "numpy.s_[...]"  # Requires numpy to be imported as numpy in generated script
        if random() < 0.05:
            return "()"

        # Default case: call the runtime helper
        return f"_fusil_h5_create_dynamic_slice_for_rank({rank_variable_name_in_script})"

    def genNumpyArrayForDirectIO_expr(self, array_shape_expr: str, dtype_expr: str,
                                      allow_non_contiguous: bool = True) -> str:
        """Generates a numpy array expression for read_direct (dest) or write_direct (source)."""
        # This needs to create an array that is compatible in size with the selection.
        # For simplicity, assume array_shape_expr is like "(5,5)" or "10"
        # This is a placeholder; a robust version needs to calculate size from selection.
        order_opt = ""
        if allow_non_contiguous and random() < 0.2:
            order_opt = ", order='F'"

        # Try to create a compatible array. This is complex if shape is from a slice.
        # For now, let's generate a small, simple array, assuming compatibility is handled by test case.
        # A better approach would be to get the *actual shape value* from the slice to make a compatible array.
        if random() < 0.5:
            return f"numpy.arange(10, dtype={dtype_expr}).reshape(2,5){order_opt}"  # Example fixed size
        else:
            return f"numpy.full(shape={array_shape_expr if array_shape_expr else '(10,)'}, fill_value={self.genH5PyFillvalue_expr(dtype_expr)}, dtype={dtype_expr}{order_opt})"

    def genH5PyAsTypeDtype_expr(self) -> str:  # Can reuse existing dtype generators
        return self.genH5PyComplexDtype_expr() if random() < 0.5 else self.genH5PySimpleDtype_expr()

    def genH5PyAsStrEncoding_expr(self) -> str:
        encodings = ['ascii', 'utf-8', 'latin-1', 'utf-16', 'cp1252', 'invalid_encoding_fuzz']
        return f"'{choice(encodings)}'"

    def genH5PyAsStrErrors_expr(self) -> str:
        errors = ['strict', 'ignore', 'replace', 'xmlcharrefreplace', 'bogus_error_handler']
        return f"'{choice(errors)}'"

    # In ArgumentGenerator class:

    def genH5PyFieldNameForSlicing_expr(self, dataset_fields_keys_expr_str: str) -> str:
        """
        Generates a field name string or a list of field name strings for slicing,
        given a string expression that evaluates to the dataset's field keys.
        Args:
            dataset_fields_keys_expr_str: Python expression string for dataset.dtype.fields.keys()
                                         e.g., f"list({ctx_p}_dtype_obj.fields.keys())"
        """
        # This code will run in the fuzzer (generator side), but the expression it returns
        # will run in the fuzzed script.
        # It needs to return a Python expression that uses dataset_fields_keys_expr_str.

        # Python code to be embedded in the generated script:
        # This lambda will be defined and called in the generated script.
        # It picks one or more fields from the runtime list of field keys.
        lambda_expr = f"""
(lambda fields_keys:
    (choice(fields_keys) if random() < 0.7 else \
     list(sample(fields_keys, k=min(len(fields_keys), randint(1,3))))) \
    if fields_keys and len(fields_keys) > 0 else \
    choice(["non_existent_field", "another_bad_field"])
)({dataset_fields_keys_expr_str})
"""
        # Cleanup the multiline string for embedding
        return " ".join(lambda_expr.strip().splitlines())

    def genH5PyMultiBlockSlice_expr(self, dataset_1d_len_expr_str: str = "100") -> str:
        """
        Generates a Python expression string that creates an h5py.MultiBlockSlice object.
        Args:
            dataset_1d_len_expr_str: Optional string expression for the length of a 1D dataset,
                                     used to help generate valid parameters.
        """
        # This generates the code to *create* a MultiBlockSlice object in the target script.
        # The parameters will be randomized.
        # The lambda ensures parameters are generated at runtime in the fuzzed script.
        # dataset_1d_len_expr_str is the name of the variable holding the length.
        lambda_expr = f"""
(lambda L: h5py.MultiBlockSlice(
    start=randint(0, max(0, L//2 if L else 10)),
    count=randint(1, max(1, L//4 if L else 5)) if random() < 0.8 else None,
    stride=randint(0, max(1, L//5 if L else 8)) if random() < 0.9 else 1,
    block=randint(1, max(1, L//5 if L else 8)) if random() < 0.8 else 1
))({dataset_1d_len_expr_str} if isinstance({dataset_1d_len_expr_str}, int) else 100)
"""
        # Note: The (L if L else 100) etc. is to handle if length is 0 or None, providing defaults.
        # This lambda will be called with the runtime length of the dataset.
        return " ".join(lambda_expr.strip().splitlines())

    def genH5PyRegionReferenceForSlicing_expr(self, dataset_expr_str: str, dataset_rank_expr_str: str) -> str:
        """
        Generates an expression that creates a RegionReference from a given dataset.
        Args:
            dataset_expr_str: Expression string for the dataset instance.
            dataset_rank_expr_str: Expression string for the dataset's rank.
        """
        # This creates a string that, when run, will access .regionref with a random slice
        # The _fusil_h5_create_dynamic_slice_for_rank helper is ideal here.
        slice_generating_call = f"_fusil_h5_create_dynamic_slice_for_rank({dataset_rank_expr_str})"
        return f"{dataset_expr_str}.regionref[{slice_generating_call}]"

    def genAdvancedSliceArgument_expr(self, dataset_expr_str: str, dataset_rank_expr_str: str,
                                      dataset_fields_keys_expr_str: str) -> str:
        """
        Chooses among generating a basic slice, field name, MultiBlockSlice, or RegionReference.
        """
        choice = random()
        if choice < 0.4:  # Basic slice (using the helper we defined for rank-aware slices)
            return f"_fusil_h5_create_dynamic_slice_for_rank({dataset_rank_expr_str})"
        elif choice < 0.6:  # Field name slice (most effective if dataset_fields_keys_expr_str is valid)
            return self.genH5PyFieldNameForSlicing_expr(dataset_fields_keys_expr_str)
        elif choice < 0.8:  # MultiBlockSlice (using dataset length, simplified to rank for now)
            # For MultiBlockSlice, .indices(length) is key. We'll use dataset_rank_expr_str as a proxy for typical length.
            return self.genH5PyMultiBlockSlice_expr(
                f"({dataset_rank_expr_str} * 10 if isinstance({dataset_rank_expr_str},int) else 100)")
        else:  # RegionReference
            return self.genH5PyRegionReferenceForSlicing_expr(dataset_expr_str, dataset_rank_expr_str)

    def genNumpyValueForComparison_expr(self, dataset_dtype_expr_str: str) -> str:
        # Generate a scalar or small array for comparison
        # This can reuse parts of genH5PyFillvalue_expr or genH5PyData_expr logic
        # to create a compatible value.
        if random() < 0.7:  # Scalar
            return self.genH5PyFillvalue_expr(dataset_dtype_expr_str)  # Good enough for a scalar
        else:  # Small array
            return f"numpy.array([{self.genH5PyFillvalue_expr(dataset_dtype_expr_str)}, {self.genH5PyFillvalue_expr(dataset_dtype_expr_str)}], dtype={dataset_dtype_expr_str})"

        # In ArgumentGenerator class:

    def genH5PyLinkPath_expr(self, current_group_path_expr_str: str = "'/'") -> str:
        """Generates a path string for SoftLink targets."""
        # current_group_path_expr_str is the HDF5 path of the group where the link is being created.
        # This allows generating truly relative paths like '.' or '../sibling'.
        # For simplicity now, mainly absolute or simple relative.
        paths = [
            f"'/{_h5_unique_name('target_abs_')}'",  # Target existing absolute path
            f"'/{_h5_unique_name('dangling_abs_')}'",  # Dangling absolute
            "'.'",  # Link to self (current group)
            "'..'",  # Link to parent
            f"'{_h5_unique_name('sibling_relative')}'",  # Relative path
            f"{current_group_path_expr_str} + '/{_h5_unique_name('child_link_target')}'"
            # Path relative to current group
        ]
        # Add a chance for a truly circular path if current_group_path_expr_str is known
        if current_group_path_expr_str != "'/'" and random() < 0.2:
            paths.append(current_group_path_expr_str)  # Link to the group path itself

        return choice(paths)

    def genH5PyExternalLinkFilename_expr(self, external_target_filename_expr_str: str) -> str:
        """Generates a filename string for ExternalLink targets."""
        # external_target_filename_expr_str is the expression for the valid secondary file.
        if random() < 0.7:  # High chance to use the valid external file
            return external_target_filename_expr_str
        else:  # Chance for a dangling filename
            return f"'{_h5_unique_name('dangling_ext_file_')}.h5'"

    def genH5PyNewLinkName_expr(self) -> str:
        """Generates a new name for a link."""
        # _h5_unique_name should be a helper available in the generated script, or use uuid directly
        # return f"'{_h5_unique_name('link_')}'"
        return f"'link_{uuid.uuid4().hex[:6]}'"

    # def genH5PyExistingObjectPath_expr(self, file_obj_expr_str: str) -> str:
    #     """Generates a string expression for a path to an existing object within file_obj_expr_str."""
    #     # This is tricky without knowing the contents of file_obj_expr_str at generation time.
    #     # Simplification: return a common path or a root-level predefined object.
    #     # This would ideally pick from actual objects in the file.
    #     # For now, assume some known paths or use a runtime helper.
    #     # Example: path to a pre-defined tricky dataset if its name is known globally.
    #     predefined_targets = [
    #         h5py_tricky_objects.get("h5_link_target_dataset").name if h5py_tricky_objects.get(
    #             "h5_link_target_dataset") else None,
    #         h5py_tricky_objects.get("h5_link_target_group").name if h5py_tricky_objects.get(
    #             "h5_link_target_group") else None,
    #     ]
    #     valid_target = choice([p for p in predefined_targets if p])
    #     if valid_target and random() < 0.7:
    #         return f"{file_obj_expr_str}.get('{valid_target}')"  # Get the actual object
    #     return f"{file_obj_expr_str}.get('/')"  # Fallback to root group object

    def genH5PyExistingObjectPath_expr(self, parent_group_expr_str: str) -> str:
        """
        Generates a Python expression string that, when executed in the fuzz script,
        attempts to return an existing h5py object (Dataset or Group) from the
        same file as parent_group_expr_str. This is suitable for creating a hard link.

        Args:
            parent_group_expr_str: Python expression string for the h5py.Group instance
                                   where the hard link will be created (e.g., "_h5_main_file['mygroup']").
        """
        # This lambda will be defined and executed within the generated fuzzer script.
        # It needs access to 'random' and 'h5py' (for isinstance checks).
        # It uses parent_group_expr_str to access the runtime group object.

        # Strategy:
        # 1. Try to pick a random direct child of the parent_group_expr_str.
        # 2. If parent is empty or by chance, try to pick a random child from the file's root.
        # 3. As a final fallback, use the root group of the parent's file.
        # 4. Ensure the picked item is a Group or Dataset (not a link object itself before resolution).

        # We construct a self-contained Python expression string (an IIFE lambda).
        # Note: `h5py_tricky_objects` is available at runtime in the generated script.
        # We can also try to pick from `h5py_tricky_objects` if they are in the same file.

        # Let's make it a bit more robust by trying a sequence of strategies at runtime.
        # This entire block is a string that will be executed in the generated script.
        # The `random` here refers to `random` module in the generated script.

        # We need unique variable names within the lambda if we store intermediate results,
        # or just chain expressions.

        # Expression for selecting a candidate object:
        # This lambda will be embedded as a string, so internal quotes need care.
        # It takes the runtime group object `pg` (parent_group) and the runtime
        # `h5py_tricky_objects` dict.

        # Using a more direct approach: generate a call to a helper function
        # that will be defined in the generated script by WritePythonCode.
        # This keeps the expression returned by ArgumentGenerator simpler.

        helper_call_expr = f"_fusil_h5_get_link_target_in_file({parent_group_expr_str}, h5py_tricky_objects, h5py_runtime_objects)"
        return helper_call_expr

    # In ArgumentGenerator class:
    def genDataForFancyIndexing_expr(self, block_shape_expr_str: str, dtype_expr_str: str) -> str:
        """Generates numpy array expression for RHS of fancy indexing setitem."""
        # block_shape_expr_str is an expression like "tuple(variable_block_shape_list)"
        # dtype_expr_str is like "numpy.uint8"
        return f"numpy.random.randint(0, 255, size=({block_shape_expr_str}), dtype={dtype_expr_str})"

    def genLargePythonInt_expr(self) -> str:
        """Generates a string representation of a large Python integer."""
        return str(choice([
            2 ** 63 - 1, 2 ** 63, 2 ** 63 + 1,
            2 ** 64 - 1, 2 ** 64,
            sys.maxsize, sys.maxsize + 1  # Requires sys import in generated script
        ]))

    def genArrayForArrayDtypeElement_expr(self, element_shape_tuple_expr_str: str, base_dtype_expr_str: str) -> str:
        """
        Generates a Python expression string that, when executed in the fuzz script,
        creates a NumPy array suitable for an element of an array dtype.

        Args:
            element_shape_tuple_expr_str: Python expression string for the shape tuple
                                          of a single element of the array dtype
                                          (e.g., "ctx_p_el_shape_tuple").
            base_dtype_expr_str: Python expression string for the base dtype of the
                                 array elements (e.g., "ctx_p_base_dt_expr" or "'i4'").
        """
        # The generated expression will use numpy.prod on the runtime shape tuple
        # and then reshape. It assumes 'numpy' is imported in the generated script.

        # Ensure base_dtype_expr_str is treated as a dtype object at runtime
        # If it's already a string like "'i4'", it's fine. If it's a variable name,
        # that variable should hold a dtype object or string.

        # Example: if element_shape_tuple_expr_str is " (3,2) " (runtime value)
        # and base_dtype_expr_str is " 'i4' " (runtime value)
        # this will generate:
        # "numpy.arange(numpy.prod((3,2))).astype(numpy.dtype('i4')).reshape((3,2))"

        # We need to ensure that base_dtype_expr_str results in a valid dtype for astype.
        # If ctx_p_base_dt_expr is already a string like "'i4'", it's fine.
        # If it's a variable holding a dtype object, that's also fine.

        # The expression constructs the array at runtime in the generated script
        return (
            f"numpy.arange(int(numpy.prod({element_shape_tuple_expr_str})))"
            f".astype({base_dtype_expr_str})"
            f".reshape({element_shape_tuple_expr_str})"
        )

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
        return [
            f"'{filename.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}'"
        ]

    def genErrback(self) -> list[str]:
        """Generate the name of the error callback function."""
        return [self.errback_name]

    def genOpenFile(self) -> list[str]:
        """Generate code to open an existing file."""
        if not self.filenames:
            return ["open('NO_FILE_AVAILABLE')"]  # Fallback
        filename = choice(self.filenames)
        filename_literal = f"'{filename.replace(chr(92), chr(92) * 2).replace(chr(39), chr(92) + chr(39))}'"
        return [f"open({filename_literal})"]

    def genException(self) -> list[str]:
        """Generate an Exception instance string."""
        return ["Exception('fuzzer_generated_exception')"]

    def _gen_collection_internal(
        self, open_text: str, close_text: str, empty_repr: str, is_dict: bool = False
    ) -> list[str]:
        """Helper to generate code for lists, tuples, or dictionaries."""
        same_type = randint(1, 10) != 1  # 90% same_type
        nb_item = randint(0, 9)

        if not nb_item:
            return [empty_repr]

        items_code_lines: list[list[str]] = []
        if same_type:
            key_generator_func = self.create_hashable_argument if is_dict else None
            value_generator_func = self.create_simple_argument

            for _ in range(nb_item):
                if is_dict and key_generator_func:
                    current_item_lines = self._create_dict_item_lines(
                        key_generator_func, value_generator_func
                    )
                else:
                    current_item_lines = value_generator_func()
                items_code_lines.append(current_item_lines)
        else:  # Mixed types
            for _ in range(nb_item):
                if is_dict:
                    current_item_lines = self._create_dict_item_lines()
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
        key_lines = (
            key_generator_func()
            if key_generator_func
            else self.create_hashable_argument()
        )
        value_lines = (
            value_generator_func()
            if value_generator_func
            else self.create_simple_argument()
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
