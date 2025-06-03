"""
Generates arguments specifically tailored for fuzzing the h5py library.

This module provides the H5PyArgumentGenerator class, which is responsible for
creating a variety of h5py-specific objects and values as Python expression
strings. These are used by the main fuzzing engine to construct calls to
h5py functions and methods.
"""
import sys
import uuid
from random import choice, randint, random, uniform

import h5py
import numpy

import fusil.python.h5py.h5py_tricky_weird


def _h5_unique_name(base="item"):
    """
    Generates a unique name string with a given base and a short UUID.

    Args:
        base: The base string for the name.

    Returns:
        A string combining the base and a unique identifier.
    """
    return f"{base}_{uuid.uuid4().hex[:8]}"


class H5PyArgumentGenerator:
    """
    Generates arguments and expressions specific to the h5py library.

    This class is instantiated by the main ArgumentGenerator and provides
    methods to create h5py file modes, drivers, dataset properties (shape,
    dtype, chunks, fill values), link properties, attribute names/values,
    and references to predefined "tricky" h5py objects.
    """
    def __init__(self, parent):
        """
        Initializes the H5PyArgumentGenerator.

        Args:
            parent: The parent ArgumentGenerator instance, providing access
                    to general argument generation capabilities if needed.
        """
        self.parent = parent

    def genH5PyObject(self) -> list[str]:
        """
        Generates a string expression to retrieve a 'tricky' predefined h5py object.

        The object name is chosen from `tricky_h5py_names` and is expected
        to be available in the `h5py_tricky_objects` dictionary at runtime
        in the generated fuzzing script.

        Returns:
            A list containing a single string, e.g.,
            ["h5py_tricky_objects.get('some_name')"].
        """
        tricky_name = choice(fusil.python.h5py.h5py_tricky_weird.tricky_h5py_names)
        return [f"h5py_tricky_objects.get('{tricky_name}')"]

    def genH5PyFileMode(self) -> list[str]:
        """
        Generates a random h5py file mode string.

        Includes common valid modes and some potentially invalid combinations.

        Returns:
            A list containing a single string representing a file mode, e.g., ["'r+'"].
        """
        modes = ['r', 'r+', 'w', 'w-', 'x', 'a']
        modes += ["rw", "z", "wa"]  # Potentially invalid/problematic modes
        return [f"'{choice(modes)}'"]

    def genH5PyFileDriver(self) -> list[str]:
        """
        Generates a random h5py file driver string or None.

        Includes common valid drivers and some potentially invalid names.

        Returns:
            A list containing a single string representing a file driver or "None".
        """
        drivers = ['core', 'sec2', 'stdio', 'direct', 'split', 'fileobj', None]  # None for default
        drivers += ["mydriver", "\\x00"] # Invalid driver names
        chosen_driver = choice(drivers)
        return [f"'{chosen_driver}'" if chosen_driver else "None"]

    def genH5PyLibver(self) -> list[str]:
        """
        Generates an h5py library version compatibility setting.

        Can be a single version string, a (low, high) tuple, or None.

        Returns:
            A list containing a single string representing the libver setting.
        """
        versions = ['earliest', 'latest', 'v108', 'v110', 'v112', 'v114']
        choice_type = randint(0, 2)
        if choice_type == 0:  # Single string
            return [f"'{choice(versions)}'"]
        elif choice_type == 1:  # Tuple
            low = choice(versions)
            high = choice(versions)
            return [f"('{low}', '{high}')"]
        else:  # None (default)
            return ["None"]

    def genH5PyUserblockSize(self) -> list[str]:
        """
        Generates a user block size for h5py file creation.

        Includes valid powers of two and some invalid sizes.

        Returns:
            A list containing a single string representing the user block size.
        """
        valid_sizes = [0, 512, 1024, 2048, 4096, 8192]  # 0 means no userblock
        invalid_sizes = [256, 513, 1000] # Potentially problematic sizes
        chosen_size = choice(valid_sizes + invalid_sizes if random() < 0.3 else valid_sizes)
        return [str(chosen_size)]

    def genH5PyFsStrategyKwargs(self) -> list[str]:
        """
        Generates keyword arguments related to file space strategy for h5py.File.

        Randomly includes `fs_strategy`, `fs_persist`, `fs_threshold`,
        `fs_page_size`, and page buffering options.

        Returns:
            A list containing a single string of comma-separated keyword arguments,
            or an empty string if no strategy options are chosen.
        """
        kwargs = []
        strategy = choice(["page", "fsm", "aggregate", "none", "invalid_strat", None])
        if strategy:
            kwargs.append(f"fs_strategy='{strategy}'")
            if strategy == "page": # Page strategy specific options
                if random() < 0.7: kwargs.append(f"fs_persist={choice([True, False])}")
                if random() < 0.7: kwargs.append(f"fs_threshold={choice([1, 64, 128, 256])}")
                if random() < 0.7: kwargs.append(f"fs_page_size={choice([4096, 16384])}")
                if random() < 0.5:  # Page buffer options
                    pbs = choice([4096, 16384, 32768])
                    kwargs.append(f"page_buf_size={pbs}")
                    if random() < 0.5: kwargs.append(f"min_meta_keep={randint(0, 100)}")
                    if random() < 0.5: kwargs.append(f"min_raw_keep={randint(0, 100)}")
        return [", ".join(kwargs)] if kwargs else [""]

    def genH5PyLocking(self) -> list[str]:
        """
        Generates a value for the `locking` parameter of `h5py.File`.

        Includes boolean values, 'best-effort', None, and an invalid option.

        Returns:
            A list containing a single string representing the locking option.
        """
        options = [True, False, 'best-effort', 'invalid_lock_opt', None]
        chosen = choice(options)
        if isinstance(chosen, str): return [f"'{chosen}'"]
        return [str(chosen)]

    def genH5PyFileDriver_actualval(self) -> str | None:
        """
        Returns an actual h5py file driver string or None (for default).

        This method is used internally to get a concrete driver value when
        generating file creation code, as opposed to an expression string.

        Returns:
            A string representing a valid h5py driver, or None.
        """
        drivers = ['core', 'sec2', 'stdio', 'direct', 'split', 'fileobj', None]
        return choice(drivers)

    def genH5PyFileMode_actualval(self) -> str:
        """
        Returns an actual h5py file mode string.

        This method is used internally to get a concrete mode value.

        Returns:
            A string representing a valid h5py file mode.
        """
        modes = ['r', 'r+', 'w', 'w-', 'x', 'a']
        return choice(modes)

    def gen_h5py_file_name_or_object(self, actual_driver: str | None, actual_mode: str, is_core_backing: bool) -> tuple[
        str, list[str]]:
        """
        Generates the 'name' argument for h5py.File and any necessary setup code.

        Depending on the driver and mode, this can be a filename string,
        an in-memory object expression (e.g., for 'fileobj' or non-backed 'core'),
        or a variable name referencing a temporary file path.

        Args:
            actual_driver: The actual driver string (e.g., 'core', 'fileobj').
            actual_mode: The actual file mode string (e.g., 'r', 'w').
            is_core_backing: Boolean indicating if a 'core' driver uses backing_store=True.

        Returns:
            A tuple containing:
                - The Python expression string for the 'name' argument.
                - A list of Python code lines for any setup required (e.g., temp file creation).
        """
        setup_lines = []
        if actual_driver == 'fileobj':
            name_expr = f"io.BytesIO()"
        elif actual_driver == 'core' and not is_core_backing:
            name_expr = f"'mem_core_{uuid.uuid4().hex}'" # Unique name for in-memory core file
        else:  # Needs a disk path
            var_name = f"temp_disk_path_{uuid.uuid4().hex[:6]}"
            setup_lines.append(f"{var_name}_fd, {var_name} = tempfile.mkstemp(suffix='.h5', prefix='fuzz_')")
            setup_lines.append(f"os.close({var_name}_fd)")
            if actual_mode in ('r', 'r+'):
                # For read modes, the file needs to exist and ideally be a valid HDF5.
                # This setup just creates an empty temp file.
                # For more robust 'r'/'r+' testing, pre-populating is needed, or use tricky objects.
                setup_lines.append(f"# INFO: Path {var_name} generated for 'r'/'r+'; ensure pre-population if it's a new file.")
            name_expr = var_name
        return name_expr, setup_lines

    def genH5PyDriverKwargs(self, actual_driver_str_val: str | None) -> list[str]:
        """
        Generates driver-specific keyword arguments for h5py.File.

        Currently focuses on 'core' driver options like `backing_store` and `block_size`.

        Args:
            actual_driver_str_val: The actual driver string being used.

        Returns:
            A list containing a single string of comma-separated keyword arguments,
            or an empty string if no specific kwargs are generated for the driver.
        """
        kwargs_parts = []
        if actual_driver_str_val == 'core':
            if random() < 0.8:
                bs = choice([True, False])
                kwargs_parts.append(f"backing_store={bs}")
                if not bs and random() < 0.5:
                    kwargs_parts.append(f"block_size={choice([512, 4096, 65536])}")
                elif bs and random() < 0.2:
                    kwargs_parts.append(f"block_size={choice([512, 4096])}")
        # Add other driver specific kwargs here if needed (e.g., for 'direct')
        return ["", ", ".join(kwargs_parts)][len(kwargs_parts) > 0]

    def genH5PySimpleDtype_expr(self) -> str:
        """
        Generates a Python expression string for a simple NumPy dtype.

        Covers basic integer, float, and boolean types.

        Returns:
            A string representing a NumPy dtype, e.g., "'i4'" or "numpy.dtype('f8')".
        """
        simple_dtypes = [
            "'i1'", "'i2'", "'i4'", "'i8'",
            "'u1'", "'u2'", "'u4'", "'u8'",
            "'f2'", "'f4'", "'f8'",
            "'bool'"
        ]
        if random() < 0.2:
            return f"numpy.dtype({choice(simple_dtypes)})"
        return choice(simple_dtypes)

    def genH5PyDatasetShape_expr(self) -> str:
        """
        Generates a Python expression string for a dataset shape.

        Can produce scalar, null, 1D, 2D, or 3D shapes, including zero-length dimensions.

        Returns:
            A string representing a shape, e.g., "()", "None", "(10,)", "(5,0,3)".
        """
        choice_val = randint(0, 6)
        if choice_val == 0: return "()"  # Scalar
        if choice_val == 1: return "None"  # Null dataspace
        if choice_val == 2: return f"({randint(0, 5)},)"  # 1D
        if choice_val == 3: # 2D
            d1 = randint(0, 10)
            d2 = randint(0, 3) if d1 > 0 and random() < 0.5 else randint(1, 10)
            return f"({d1}, {d2})"
        if choice_val == 4: # 3D
            return f"({randint(1, 5)}, {randint(1, 5)}, {randint(1, 5)})"
        if choice_val == 5: return str(randint(1, 20))  # Integer shape for 1D
        return f"({randint(1, 50)},)" # Default 1D

    def genH5PyData_expr(self, shape_expr_str: str, dtype_expr_str: str) -> str:
        """
        Generates a Python expression for dataset data, or "None".

        Attempts to create scalar data, `h5py.Empty`, or a NumPy array
        compatible with the given shape and dtype expressions.

        Args:
            shape_expr_str: Expression string for the dataset's shape.
            dtype_expr_str: Expression string for the dataset's dtype.

        Returns:
            A string expression for data, or "None".
        """
        choice_int = randint(0, 4)
        if choice_int == 0: return "None"
        if choice_int == 1:  # Scalar data
            try: # Attempt to eval dtype locally to guide scalar generation
                dt_val = eval(dtype_expr_str)
                if numpy.issubdtype(dt_val, numpy.integer): return str(randint(0, 100))
                if numpy.issubdtype(dt_val, numpy.floating): return str(round(random() * 100, 2))
                if numpy.issubdtype(dt_val, numpy.bool_): return choice(["True", "False"])
            except Exception: pass # Fallback if eval fails
            return "None"
        if choice_int == 2: return f"h5py.Empty(dtype={dtype_expr_str})" # h5py.Empty
        if choice_int == 3 and shape_expr_str != "None" and shape_expr_str != "()": # Numpy array
            try: # Attempt to eval shape locally
                shape_val = eval(shape_expr_str)
                if isinstance(shape_val, int): shape_val = (shape_val,)
                if isinstance(shape_val, tuple) and len(shape_val) > 0 and all(isinstance(d, int) for d in shape_val):
                    if len(shape_val) == 1 and 0 <= shape_val[0] < 200:
                        return f"numpy.arange({shape_val[0]}, dtype={dtype_expr_str})"
            except Exception: pass
            return f"numpy.zeros({shape_expr_str}, dtype={dtype_expr_str})"
        return "None"

    def genH5PyDatasetChunks_expr(self, shape_expr_str: str) -> str:
        """
        Generates a Python expression for dataset chunks.

        Can produce True (auto-chunk), None (contiguous), an explicit tuple,
        False (error if maxshape set), or an invalid chunk tuple.

        Args:
            shape_expr_str: Expression string for the dataset's shape.

        Returns:
            A string expression for the chunks parameter.
        """
        choice_val = randint(0, 4)
        if choice_val == 0: return "True"  # Auto-chunk
        if choice_val == 1: return "None"  # Contiguous
        if choice_val == 2:  # Explicit chunks
            try: # Attempt to create valid-ish chunks
                shape_val = eval(shape_expr_str)
                if isinstance(shape_val, int): shape_val = (shape_val,)
                if isinstance(shape_val, tuple) and all(isinstance(d, int) and d > 0 for d in shape_val):
                    return str(tuple(max(1, d // randint(1, 4)) for d in shape_val))
                if isinstance(shape_val, tuple) and any(d == 0 for d in shape_val): return "None"
            except Exception: pass
            return f"({randint(1, 10)},)" # Fallback
        if choice_val == 3: return "False" # Potentially problematic with maxshape
        return f"({randint(100, 200)}, {randint(100, 200)})" # Invalid chunks

    def genH5PyFillvalue_expr(self, dtype_expr_str: str) -> str:
        """
        Generates a Python expression for a fillvalue compatible with simple dtypes.

        Args:
            dtype_expr_str: Expression string for the dataset's dtype.

        Returns:
            A string expression for a fillvalue, or "None".
        """
        try: # Attempt to eval dtype locally
            dt_val = eval(dtype_expr_str)
            if numpy.issubdtype(dt_val, numpy.integer): return str(randint(-100, 100))
            if numpy.issubdtype(dt_val, numpy.floating):
                return choice([str(round(uniform(-100, 100), 2)), "numpy.nan", "numpy.inf", "-numpy.inf"])
            if numpy.issubdtype(dt_val, numpy.bool_): return choice(["True", "False"])
        except Exception: pass
        return "None"

    def genH5PyFillTime_expr(self) -> str:
        """
        Generates a Python expression for dataset fill_time.

        Returns:
            A string representing a fill_time option, e.g., "'ifset'".
        """
        options = ['ifset', 'never', 'alloc', 'invalid_fill_time_option']
        return f"'{choice(options)}'"

    def genH5PyMaxshape_expr(self, shape_expr_str: str) -> str:
        """
        Generates a Python expression for dataset maxshape.

        Attempts to create a maxshape compatible with or larger than the given shape.

        Args:
            shape_expr_str: Expression string for the dataset's current shape.

        Returns:
            A string expression for maxshape, e.g., "(None, 10)", or "None".
        """
        choice_val = randint(0, 3)
        if choice_val == 0: return "None"
        try: # Attempt to create compatible maxshape
            shape_val = eval(shape_expr_str)
            if isinstance(shape_val, int): shape_val = (shape_val,)
            if isinstance(shape_val, tuple) and all(isinstance(d, int) for d in shape_val):
                maxs = [choice(["None", str(d + randint(0, 10)), str(d)]) for d in shape_val]
                return f"({', '.join(maxs)}{',' if len(maxs) == 1 else ''})"
        except Exception: pass
        if shape_expr_str != "None" and shape_expr_str != "()":
            return f"(None, {randint(1, 10)})" if "," in shape_expr_str else "(None,)"
        return "None"

    def genH5PyTrackTimes_expr(self) -> str:
        """
        Generates a Python expression for dataset track_times.

        Returns:
            A string representing a track_times option, e.g., "True".
        """
        options = [True, False, "'invalid_track_times_val'"]
        return str(choice(options))

    def genH5PyCompressionKwargs_expr(self) -> list[str]:
        """
        Generates Python expressions for compression and filter related keyword arguments.

        Randomly selects compression algorithms (gzip, lzf) and other filters
        (shuffle, fletcher32, scaleoffset) along with their options.

        Returns:
            A list of strings, where each string is a "kwarg=value" expression.
        """
        kwargs_list = []
        if random() < 0.7:  # Chance to apply some compression/filter
            comp_choice = randint(0, 5)
            if comp_choice == 0 and 'gzip' in h5py.filters.encode:
                kwargs_list.append("compression='gzip'")
                if random() < 0.5: kwargs_list.append(f"compression_opts={randint(0, 9)}")
            elif comp_choice == 1 and 'lzf' in h5py.filters.encode:
                kwargs_list.append("compression='lzf'")
            elif comp_choice == 3:  # Generic integer filter ID
                filter_id = choice([1, getattr(h5py.h5z, 'FILTER_DEFLATE', 1), 257]) # 257 for unknown
                kwargs_list.append(f"compression={filter_id}")
                if random() < 0.3: kwargs_list.append("allow_unknown_filter=True")
                if filter_id == getattr(h5py.h5z, 'FILTER_DEFLATE', 1): # If gzip by ID
                    kwargs_list.append(f"compression_opts=({randint(0, 9)},)")

            if random() < 0.4 and 'shuffle' in h5py.filters.encode:
                kwargs_list.append(f"shuffle={choice([True, False])}")
            if random() < 0.3 and 'fletcher32' in h5py.filters.encode:
                kwargs_list.append(f"fletcher32={choice([True, False])}")
            if random() < 0.3 and 'scaleoffset' in h5py.filters.encode:
                so_val = choice([True, randint(0, 16)]) # Bool for auto-int, or nbits for int
                kwargs_list.append(f"scaleoffset={so_val}")
        return kwargs_list

    def genH5PyVlenDtype_expr(self) -> str:
        """
        Generates a Python expression for an h5py variable-length (vlen) dtype.

        Returns:
            A string expression, e.g., "h5py.vlen_dtype(numpy.int16)".
        """
        base_dtypes = ["numpy.int16", "numpy.float32", "numpy.bool_", "h5py.string_dtype(encoding='ascii')"]
        return f"h5py.vlen_dtype({choice(base_dtypes)})"

    def genH5PyEnumDtype_expr(self) -> str:
        """
        Generates a Python expression for an h5py enumerated (enum) dtype.

        Returns:
            A string expression, e.g., "h5py.enum_dtype({'A':0, 'B':1}, basetype='i1')".
        """
        base_types = ["'i1'", "'u2'", "numpy.intc"]
        enum_dict_str = str({f"VAL_{chr(65 + i)}": i for i in range(randint(2, 5))})
        return f"h5py.enum_dtype({enum_dict_str}, basetype={choice(base_types)})"

    def genH5PyCompoundDtype_expr(self) -> str:
        """
        Generates a Python expression for a NumPy compound (structured) dtype.

        Creates a dtype with 1 to 3 fields, each with a randomly chosen simple,
        vlen, fixed-string, or array dtype.

        Returns:
            A string expression, e.g., "numpy.dtype([('field_0_abc', 'i4'), ('field_1_def', '(2,)f2')])".
        """
        fields = []
        num_fields = randint(1, 3)
        for i in range(num_fields):
            fname = f"'field_{i}_{uuid.uuid4().hex[:4]}'"
            ftype_choice = randint(0, 3)
            if ftype_choice == 0: ftype = self.genH5PySimpleDtype_expr()
            elif ftype_choice == 1: ftype = self.genH5PyVlenDtype_expr()
            elif ftype_choice == 2: ftype = f"'{choice(['S', 'U'])}{randint(5, 15)}'"  # Fixed string
            else: ftype = "'(2,)i4'"  # Array field
            fields.append(f"({fname}, {ftype})")
        return f"numpy.dtype([{', '.join(fields)}])"

    def genH5PyComplexDtype_expr(self) -> str:
        """
        Generates a Python expression for a potentially complex h5py/NumPy dtype.

        This is a top-level chooser that can select simple dtypes, string dtypes,
        vlen, enum, compound, array dtypes, or reference dtypes.

        Returns:
            A string expression representing a dtype.
        """
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
        return choice(options)()

    def genH5PySliceForDirectIO_expr(self, dataset_rank: int) -> str:
        """
        Generates a slice expression string suitable for `read_direct`/`write_direct`.

        Args:
            dataset_rank: The rank of the dataset the slice will be applied to.

        Returns:
            A string representing a NumPy-style slice, e.g., "numpy.s_[:, 0:5]".
        """
        if random() < 0.2: return "None"
        if random() < 0.2: return "numpy.s_[...]"

        slices = []
        for _ in range(int(dataset_rank)): # Ensure rank is int
            choice_int = randint(0, 3)
            if choice_int == 0: slices.append(":")
            elif choice_int == 1: slices.append(str(randint(0, 5)))
            else:
                start = randint(0, 10)
                stop = start + randint(1, 10)
                if random() < 0.3:
                    step = choice([1, 2, 3, -1, -2])
                    slices.append(f"{start}:{stop}:{step}")
                else:
                    slices.append(f"{start}:{stop}")
        return f"numpy.s_[{', '.join(slices)}]"

    def genH5PySliceForDirectIO_expr_runtime(self, rank_variable_name_in_script: str) -> str:
        """
        Generates an expression to call a runtime helper for creating dynamic slices.

        The helper `_fusil_h5_create_dynamic_slice_for_rank` is expected to be
        defined in the generated script.

        Args:
            rank_variable_name_in_script: The name of the variable in the
                                          generated script that will hold the dataset's rank.
        Returns:
            A string like "_fusil_h5_create_dynamic_slice_for_rank(actual_rank_var)".
        """
        if random() < 0.1: return "None"
        if random() < 0.1: return "numpy.s_[...]"
        if random() < 0.05: return "()"
        return f"_fusil_h5_create_dynamic_slice_for_rank({rank_variable_name_in_script})"

    def genNumpyArrayForDirectIO_expr(self, array_shape_expr: str, dtype_expr: str,
                                      allow_non_contiguous: bool = True) -> str:
        """
        Generates a NumPy array expression for `read_direct` (destination) or
        `write_direct` (source).

        The generated array shape is based on `array_shape_expr`.
        Note: Ensuring perfect compatibility with a preceding slice selection
        solely through string expressions is complex. This method generates
        a plausible array.

        Args:
            array_shape_expr: Python expression string for the desired array shape.
            dtype_expr: Python expression string for the array's dtype.
            allow_non_contiguous: If True, may generate a Fortran-ordered array.

        Returns:
            A string expression for creating a NumPy array.
        """
        order_opt = ""
        if allow_non_contiguous and random() < 0.2:
            order_opt = ", order='F'"
        if random() < 0.5: # Fixed small array for some cases
            return f"numpy.arange(10, dtype={dtype_expr}).reshape(2,5){order_opt}"
        return (f"numpy.full(shape={array_shape_expr if array_shape_expr else '(10,)'}, "
                f"fill_value={self.genH5PyFillvalue_expr(dtype_expr)}, dtype={dtype_expr}{order_opt})")

    def genH5PyAsTypeDtype_expr(self) -> str:
        """
        Generates a dtype expression suitable for the `.astype()` method of an h5py dataset.

        Returns:
            A string expression for a dtype, chosen from complex or simple dtypes.
        """
        return self.genH5PyComplexDtype_expr() if random() < 0.5 else self.genH5PySimpleDtype_expr()

    def genH5PyAsStrEncoding_expr(self) -> str:
        """
        Generates an encoding string for the `.asstr()` method.

        Returns:
            A string like "'utf-8'" or "'invalid_encoding_fuzz'".
        """
        encodings = ['ascii', 'utf-8', 'latin-1', 'utf-16', 'cp1252', 'invalid_encoding_fuzz']
        return f"'{choice(encodings)}'"

    def genH5PyAsStrErrors_expr(self) -> str:
        """
        Generates an error handling string for the `.asstr()` method.

        Returns:
            A string like "'strict'" or "'replace'".
        """
        errors = ['strict', 'ignore', 'replace', 'xmlcharrefreplace', 'bogus_error_handler']
        return f"'{choice(errors)}'"

    def genH5PyFieldNameForSlicing_expr(self, dataset_fields_keys_expr_str: str) -> str:
        """
        Generates a field name (or list of field names) for slicing compound datasets.

        The generated expression, when run in the fuzzed script, will pick
        from the actual field keys of the dataset.

        Args:
            dataset_fields_keys_expr_str: Python expression string that evaluates to
                                          a list of the dataset's field keys at runtime
                                          (e.g., "list(my_dataset.dtype.fields.keys())").
        Returns:
            A Python expression string that selects field name(s).
        """
        lambda_expr = f"""
(lambda fields_keys:
    (choice(fields_keys) if random() < 0.7 else \\
     list(sample(fields_keys, k=min(len(fields_keys), randint(1,3))))) \\
    if fields_keys and len(fields_keys) > 0 else \\
    choice(["non_existent_field", "another_bad_field"])
)({dataset_fields_keys_expr_str})
"""
        return "\n".join(lambda_expr.strip().splitlines())

    def genH5PyMultiBlockSlice_expr(self, dataset_1d_len_expr_str: str = "100") -> str:
        """
        Generates an expression to create an `h5py.MultiBlockSlice` object.

        Args:
            dataset_1d_len_expr_str: Optional expression string for the length of a
                                     1D dataset, used to guide parameter generation.
                                     Defaults to "100".
        Returns:
            A Python expression string that creates an `h5py.MultiBlockSlice`.
        """
        lambda_expr = f"""
(lambda L: h5py.MultiBlockSlice(
    start=randint(0, max(0, L//2 if L else 10)),
    count=randint(1, max(1, L//4 if L else 5)) if random() < 0.8 else None,
    stride=randint(0, max(1, L//5 if L else 8)) if random() < 0.9 else 1,
    block=randint(1, max(1, L//5 if L else 8)) if random() < 0.8 else 1
))({dataset_1d_len_expr_str} if isinstance({dataset_1d_len_expr_str}, int) else 100)
"""
        return "\n".join(lambda_expr.strip().splitlines())

    def genH5PyRegionReferenceForSlicing_expr(self, dataset_expr_str: str, dataset_rank_expr_str: str) -> str:
        """
        Generates an expression that creates an `h5py.RegionReference` from a dataset.

        Args:
            dataset_expr_str: Expression string for the h5py.Dataset instance.
            dataset_rank_expr_str: Expression string for the dataset's rank (an int).

        Returns:
            A Python expression string, e.g., "my_dataset.regionref[some_slice]".
        """
        slice_generating_call = f"_fusil_h5_create_dynamic_slice_for_rank({dataset_rank_expr_str})"
        return f"{dataset_expr_str}.regionref[{slice_generating_call}]"

    def genAdvancedSliceArgument_expr(self, dataset_expr_str: str, dataset_rank_expr_str: str,
                                      dataset_fields_keys_expr_str: str) -> str:
        """
        Chooses and generates an advanced slicing argument.

        This can be a basic slice (dynamically created for rank), a field name
        (for compound types), an `h5py.MultiBlockSlice`, or an `h5py.RegionReference`.

        Args:
            dataset_expr_str: Expression string for the h5py.Dataset instance.
            dataset_rank_expr_str: Expression string for the dataset's rank.
            dataset_fields_keys_expr_str: Expression string for the dataset's field keys.

        Returns:
            A Python expression string representing an advanced slice argument.
        """
        choice_val = random()
        if choice_val < 0.4:
            return f"_fusil_h5_create_dynamic_slice_for_rank({dataset_rank_expr_str})"
        elif choice_val < 0.6:
            return self.genH5PyFieldNameForSlicing_expr(dataset_fields_keys_expr_str)
        elif choice_val < 0.8:
            # Use dataset_rank_expr_str as a proxy for typical length for MultiBlockSlice
            return self.genH5PyMultiBlockSlice_expr(
                f"({dataset_rank_expr_str} * 10 if isinstance({dataset_rank_expr_str},int) else 100)")
        else:
            return self.genH5PyRegionReferenceForSlicing_expr(dataset_expr_str, dataset_rank_expr_str)

    def genNumpyValueForComparison_expr(self, dataset_dtype_expr_str: str) -> str:
        """
        Generates a NumPy scalar or small array suitable for dataset comparisons.

        Args:
            dataset_dtype_expr_str: Expression string for the dataset's dtype.

        Returns:
            A Python expression string for a NumPy value.
        """
        if random() < 0.7:  # Scalar
            return self.genH5PyFillvalue_expr(dataset_dtype_expr_str)
        else:  # Small array
            return (f"numpy.array([{self.genH5PyFillvalue_expr(dataset_dtype_expr_str)}, "
                    f"{self.genH5PyFillvalue_expr(dataset_dtype_expr_str)}], dtype={dataset_dtype_expr_str})")

    def genH5PyLinkPath_expr(self, current_group_path_expr_str: str = "'/'") -> str:
        """
        Generates a path string for `h5py.SoftLink` targets.

        Can be absolute, relative to the current group, or special ('.', '..').

        Args:
            current_group_path_expr_str: Expression string for the HDF5 path of the
                                         group where the link is being created.

        Returns:
            A Python expression string for a link target path.
        """
        paths = [
            f"'/{_h5_unique_name('target_abs_')}'",
            f"'/{_h5_unique_name('dangling_abs_')}'",
            "'.'",
            "'..'",
            f"'{_h5_unique_name('sibling_relative')}'",
            f"{current_group_path_expr_str} + '/{_h5_unique_name('child_link_target')}'"
        ]
        if current_group_path_expr_str != "'/'" and random() < 0.2: # Chance for circular
            paths.append(current_group_path_expr_str)
        return choice(paths)

    def genH5PyExternalLinkFilename_expr(self, external_target_filename_expr_str: str) -> str:
        """
        Generates a filename string for `h5py.ExternalLink` targets.

        Usually returns the provided valid target filename, but can also
        generate a dangling (non-existent) filename.

        Args:
            external_target_filename_expr_str: Expression string for a valid
                                               external target HDF5 filename.
        Returns:
            A Python expression string for an external link filename.
        """
        if random() < 0.7:
            return external_target_filename_expr_str
        return f"'{_h5_unique_name('dangling_ext_file_')}.h5'"

    def genH5PyNewLinkName_expr(self) -> str:
        """
        Generates a new, unique-ish name for creating a link.

        Returns:
            A string expression for a link name, e.g., "'link_abcdef12'".
        """
        return f"'link_{uuid.uuid4().hex[:6]}'"

    def genH5PyExistingObjectPath_expr(self, parent_group_expr_str: str) -> str:
        """
        Generates an expression to get an existing h5py object for hard linking.

        The generated expression calls `_fusil_h5_get_link_target_in_file`
        (expected to be defined in the fuzz script) to find a suitable target
        (Dataset or Group) within the same file as `parent_group_expr_str`.

        Args:
            parent_group_expr_str: Python expression string for the h5py.Group instance
                                   where the hard link will be created.
        Returns:
            A Python expression string that attempts to retrieve an existing object.
        """
        return (f"_fusil_h5_get_link_target_in_file({parent_group_expr_str}, "
                f"h5py_tricky_objects, h5py_runtime_objects)")

    def genDataForFancyIndexing_expr(self, block_shape_expr_str: str, dtype_expr_str: str) -> str:
        """
        Generates a NumPy array expression for the right-hand side of fancy indexing.

        Args:
            block_shape_expr_str: Expression string for the shape of the data block
                                  to be assigned (e.g., "tuple(variable_block_shape_list)").
            dtype_expr_str: Expression string for the dtype of the data.

        Returns:
            A Python expression string to create a NumPy array with random integer data.
        """
        return f"numpy.random.randint(0, 255, size=({block_shape_expr_str}), dtype={dtype_expr_str})"

    def genLargePythonInt_expr(self) -> str:
        """
        Generates a string representation of a large Python integer.

        Includes values around 2**63, 2**64, and `sys.maxsize`.

        Returns:
            A string of a large integer.
        """
        return str(choice([
            2 ** 63 - 1, 2 ** 63, 2 ** 63 + 1,
            2 ** 64 - 1, 2 ** 64,
            sys.maxsize, sys.maxsize + 1
        ]))

    def genArrayForArrayDtypeElement_expr(self, element_shape_tuple_expr_str: str, base_dtype_expr_str: str) -> str:
        """
        Generates an expression to create a NumPy array for an array dtype element.

        The generated expression, when run in the fuzz script, creates an array
        matching the element's shape and base dtype.

        Args:
            element_shape_tuple_expr_str: Expression string for the shape tuple
                                          of a single element (e.g., "ctx_p_el_shape_tuple").
            base_dtype_expr_str: Expression string for the base dtype of array
                                 elements (e.g., "ctx_p_base_dt_expr" or "'i4'").
        Returns:
            A Python expression string like
            "numpy.arange(numpy.prod(shape_tuple)).astype(dtype).reshape(shape_tuple)".
        """
        return (
            f"numpy.arange(int(numpy.prod({element_shape_tuple_expr_str})))"
            f".astype({base_dtype_expr_str})"
            f".reshape({element_shape_tuple_expr_str})"
        )

    def genH5PyAttributeName_expr(self) -> str:
        """
        Generates a string expression for an h5py attribute name.

        Can produce simple alphanumeric names, long names, or names with Unicode.

        Returns:
            A string like "'my_attr_123'" or "'attr_with_unicode_😀'".
        """
        name_len = randint(1, 20)
        name = "".join(choice("abcdefghijklmnopqrstuvwxyz_0123456789") for _ in range(name_len))
        if random() < 0.1: name = "very_long_attribute_name_" + uuid.uuid4().hex[:16]
        if random() < 0.1: name = "attr_with_unicode_😀"
        return f"'{name}'"

    def genH5PyAttributeValue_expr(self) -> str:
        """
        Generates a Python expression for an h5py attribute value.

        Can be a simple scalar (int, float), a string, or a small NumPy array.

        Returns:
            A string expression for an attribute value.
        """
        choice_val = randint(0, 3)
        if choice_val == 0: # Simple scalar int
            return self.parent.genInt()[0] # genInt returns a list
        elif choice_val == 1: # Simple scalar float
            return self.parent.genFloat()[0]
        elif choice_val == 2:  # String
            return self.parent.genString()[0]
        else:  # Small numpy array
            dtype_expr = self.genH5PySimpleDtype_expr()
            return f"numpy.arange({randint(1, 5)}, dtype={dtype_expr})"
