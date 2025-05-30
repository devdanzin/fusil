from __future__ import annotations

import builtins
import inspect
import time
import uuid
from random import choice, randint, random
from textwrap import dedent
from types import BuiltinFunctionType, FunctionType, ModuleType
from typing import TYPE_CHECKING, Any, Callable

import fusil.python.tricky_weird
from fusil.python.arg_numbers import class_arg_number, get_arg_number
from fusil.python.argument_generator import ArgumentGenerator
from fusil.python.blacklists import (
    BLACKLIST,
    METHOD_BLACKLIST,
    OBJECT_BLACKLIST,
)
from fusil.python.mangle import mangle_loop, mangle_obj
from fusil.write_code import WriteCode

if TYPE_CHECKING:
    from fusil.python.python_source import PythonSource

try:
    from fusil.python.template_strings import TEMPLATES

    print("Template strings available.")
    _ARG_GEN_USE_TEMPLATES = True
except ImportError:
    print("Template strings not available.")
    _ARG_GEN_USE_TEMPLATES = False

try:
    import numpy  # type: ignore

    print(f"Numpy {numpy.__version__} is available, using it to build tricky arrays.")
    _ARG_GEN_USE_NUMPY = True
except ImportError:
    print("Numpy is not available.")
    _ARG_GEN_USE_NUMPY = False



time_start = time.time()
USE_MANGLE_FEATURE = False
CALL_REPETITION_COUNT_CONST = 3
ERRBACK_NAME_CONST = "errback"
EXCEPTION_NAMES = {
    cls.__name__
    for cls in builtins.__dict__.values()
    if isinstance(cls, type) and issubclass(cls, Exception)
}


class PythonFuzzerError(Exception):
    """Custom exception raised when fuzzer encounters unrecoverable errors."""


def _h5_unique_name(base="item"):
    return f"{base}_{uuid.uuid4().hex[:8]}"


class WritePythonCode(WriteCode):
    """Generates Python source code with randomized function calls for fuzzing."""

    def __init__(
        self,
        parent_python_source: "PythonSource",
        filename: str,
        module: ModuleType,
        module_name: str,
        threads: bool = True,
        _async: bool = True,
    ):
        """Initialize the Python code writer."""
        super().__init__()  # Initialize base WriteCode
        self.parent_python_source = parent_python_source
        self.options = parent_python_source.options
        self.filenames = parent_python_source.filenames
        self.module = module
        self.module_name = module_name
        self.enable_threads = threads
        self.enable_async = _async
        self.generated_filename = filename

        self.arg_generator = ArgumentGenerator(
            self.options, self.filenames, _ARG_GEN_USE_NUMPY, _ARG_GEN_USE_TEMPLATES
        )

        self.module_functions: list[str]
        self.module_classes: list[str]
        self.module_objects: list[str]
        self.module_functions, self.module_classes, self.module_objects = (
            self._get_module_members()
        )

        if (
            not self.module_functions
            and not self.module_classes
            and not self.module_objects
        ):
            raise PythonFuzzerError(
                f"Module {self.module_name} has no function, no class, and no object to fuzz!"
            )

    def write_print_to_stderr(self, level: int, arguments_str: str) -> None:
        """Write a print statement to stderr at the specified indentation level."""
        code = f"print({arguments_str}, file=stderr)"
        self.write(level, code)

    def _get_module_members(self) -> tuple[list[str], list[str], list[str]]:
        """Extracts fuzzable functions, classes, and objects from the current module."""
        _EXCEPTION_NAMES = EXCEPTION_NAMES

        classes = []
        functions = []
        objects = []
        try:
            module_blacklist = BLACKLIST.get(self.module_name, set())
        except KeyError:
            module_blacklist = set()

        current_blacklist = module_blacklist | METHOD_BLACKLIST

        names = set(dir(self.module))
        names -= {
            "__builtins__",
            "__doc__",
            "__file__",
            "__name__",
            "__package__",
            "__loader__",
            "__spec__",
            "__cached__",
        }
        names -= {"True", "None", "False", "Ellipsis"}

        if not self.options.fuzz_exceptions:
            names -= _EXCEPTION_NAMES

        names -= current_blacklist

        for name in sorted(list(names)):
            if name.startswith("_") and not self.options.test_private:
                if not (name.startswith("__") and name.endswith("__")):
                    continue

            try:
                attr = getattr(self.module, name)
            except AttributeError:
                # Attribute listed in dir() but not actually gettable (e.g., from __all__ but not defined)
                continue
            except Exception as e:
                self.parent_python_source.warning(
                    f"Could not getattr {name} from {self.module_name}: {e}"
                )
                continue

            if isinstance(attr, (FunctionType, BuiltinFunctionType)):
                functions.append(name)
            elif isinstance(attr, type) or inspect.isclass(attr):
                if (
                    not self.options.fuzz_exceptions
                    and isinstance(attr, type)
                    and issubclass(attr, BaseException)
                    and attr.__name__ in _EXCEPTION_NAMES
                ):
                    continue
                classes.append(name)
            else:
                if isinstance(attr, ModuleType):
                    continue
                if (
                    not self.options.fuzz_exceptions
                    and isinstance(attr, BaseException)
                    and attr.__class__.__name__ in _EXCEPTION_NAMES
                ):
                    continue
                objects.append(name)
        return functions, classes, objects

    def _get_object_methods(
        self, obj_instance_or_class: Any, owner_name: str
    ) -> dict[str, Callable[..., Any]]:
        """Extracts callable methods from an object or class, respecting blacklists."""
        methods: dict[str, Callable[..., Any]] = {}
        if type(obj_instance_or_class) in {
            int,
            str,
            float,
            bool,
            bytes,
            tuple,
            list,
            dict,
            set,
            type(None),
        }:
            return methods

        try:
            key = f"{self.module_name}:{owner_name}"
            blacklist = BLACKLIST.get(key, set())
        except KeyError:
            blacklist = set()
        blacklist |= METHOD_BLACKLIST

        is_exception_type_or_instance = (
            isinstance(obj_instance_or_class, type)
            and issubclass(obj_instance_or_class, BaseException)
        ) or isinstance(obj_instance_or_class, BaseException)

        for name in dir(obj_instance_or_class):
            if name in blacklist:
                continue
            if (
                (not self.options.test_private)
                and name.startswith("__")
                and not name.endswith("__")
            ):
                if name not in {
                    "__init__",
                    "__call__",
                    "__getitem__",
                    "__setitem__",
                    "__iter__",
                    "__next__",
                    "__len__",
                    "__contains__",
                    "__eq__",
                    "__lt__",
                    "__gt__",
                    "__le__",
                    "__ge__",
                    "__repr__",
                    "__str__",
                }:
                    continue

            if (
                is_exception_type_or_instance and name == "__init__"
            ):  # Avoid re-initing exceptions
                continue

            try:
                attr = getattr(obj_instance_or_class, name, None)
                if attr is None or not callable(attr):
                    continue
            except Exception as e:  # getattr itself might fail
                self.parent_python_source.warning(
                    f"Could not getattr {name} from {self.module_name}: {e}"
                )
                continue
            methods[name] = attr
        return methods

    def _write_script_header_and_imports(self) -> None:
        """Writes standard imports and initial setup code to the generated script."""
        self.write(
            0,
            dedent(
                """\
                from gc import collect
                from sys import stderr, path as sys_path
                from os.path import dirname
                import inspect
                import io
                import time
                import sys
                from threading import Thread
                from unittest.mock import MagicMock
                import asyncio
                """
            ),
        )
        if not self.options.no_tstrings and _ARG_GEN_USE_TEMPLATES:
            self.write(0, "from string.templatelib import Interpolation, Template")

        self.write_print_to_stderr(0, f'"Importing target module: {self.module_name}"')
        self.write(0, f"import {self.module_name}")
        self.emptyLine()
        # In WritePythonCode, when writing the preamble of the generated script:

        self.write(0, "import random  # For the dynamic slice helper")
        self.write(0, "import numpy   # For numpy.s_ in the dynamic slice helper, if used directly")
        self.emptyLine()
        self.write(0, dedent(
            """\
            def _fusil_h5_create_dynamic_slice_for_rank(rank_value):
                # ""\"Generates a slice tuple suitable for a dataset of given rank_value.""\"
                if rank_value is None: # Could be for null dataspace or if shape fetch failed
                    # Return a generic slice or an ellipsis for such cases
                    return random.choice([numpy.s_[...], slice(None), ()])

                if not isinstance(rank_value, int) or rank_value < 0:
                    # Fallback for unexpected rank_value input
                    return numpy.s_[...] # Default to ellipsis if rank is weird

                if rank_value == 0: # Scalar dataset
                    # Common ways to slice scalars: (), ...
                    return random.choice([(), numpy.s_[...]])

                # For rank > 0, generate a tuple of slice components
                slice_components = []
                # Determine how many components to generate for the slice tuple
                # Usually same as rank, but could be less (e.g., for d[0] on 2D array)
                # or more (h5py might truncate or error). Let's try for same as rank mostly.
                num_dims_to_slice = rank_value
                if random.random() < 0.1: # Small chance to use fewer slice components
                    num_dims_to_slice = random.randint(1, max(1, rank_value))

                for i in range(num_dims_to_slice):
                    choice = random.randint(0, 6)
                    if choice == 0:
                        slice_components.append(slice(None))  # ':'
                    elif choice == 1:
                        # Sensible index: 0, 1, or relative to end if rank_value and current dim size were known
                        # Since we only have rank, let's keep indices small
                        slice_components.append(random.randint(0, 3))
                    elif choice == 2: # start:stop
                        s = random.randint(0, 2)
                        e = s + random.randint(1, 3)
                        slice_components.append(slice(s, e))
                    elif choice == 3: # :stop
                        slice_components.append(slice(None, random.randint(1, 4)))
                    elif choice == 4: # start:
                        slice_components.append(slice(random.randint(0, 2), None))
                    elif choice == 5: # start:stop:step
                        s = random.randint(0, 2)
                        e = s + random.randint(2, 5)
                        st = random.choice([-2, -1, 1, 2, 3])
                        if st == 0: st = 1 # step cannot be 0
                        slice_components.append(slice(s, e, st))
                    else: # Ellipsis (can appear once)
                        if Ellipsis not in slice_components: # Only add one Ellipsis
                            slice_components.append(Ellipsis)
                        else: # fallback if Ellipsis already there
                            slice_components.append(slice(None))

                if not slice_components: # Should not happen if rank > 0
                     return ()

                # h5py can often take a tuple directly for slicing
                # If only one component and it's not Ellipsis, it might not need to be a tuple
                if len(slice_components) == 1 and isinstance(slice_components[0], (int, slice)) and slice_components[0] is not Ellipsis:
                     return slice_components[0]
                return tuple(slice_components)
            """
        ))
        self.emptyLine()

    def _write_tricky_definitions(self) -> None:
        """Writes definitions for 'tricky' classes and objects."""
        self.write(0, fusil.python.tricky_weird.weird_classes)
        self.emptyLine()
        self.write(0, fusil.python.tricky_weird.tricky_typing)
        self.emptyLine()
        self.write(0, fusil.python.tricky_weird.tricky_objects)
        self.emptyLine()
        if not self.options.no_numpy and _ARG_GEN_USE_NUMPY:
            self.write(0, "import numpy")
            self.write(0, fusil.python.tricky_weird.tricky_numpy)
            self.emptyLine()

        if not self.options.no_numpy and _ARG_GEN_USE_NUMPY:
            self.write(0, "# Executing HDF5 tricky object generation code")
            self.write(0, fusil.python.tricky_weird.tricky_h5py_code)
            self.emptyLine()

        self.write(
            0,
            dedent(
                f"""\
                def {ERRBACK_NAME_CONST}(*args, **kw):
                    raise ValueError('errback called')
                """
            ),
        )
        self.emptyLine()

        self.write(
            0,
            dedent(
                f"""\
                class Liar1:
                    def __eq__(self, other):
                        return True
                
                class Liar2:
                    def __eq__(self, other):
                        return False
                
                liar1, liar2 = Liar1(), Liar2()
                
                class Evil:
                    def __eq__(self, other):
                        for attr in dir(other):
                            try: other.__dict__[attr] = {ERRBACK_NAME_CONST}
                            except: pass
                
                evil = Evil()
                
                """
            ),
        )

        if USE_MANGLE_FEATURE:
            self.write(0, mangle_obj)
        self.emptyLine()

    def _write_helper_call_functions(self) -> None:
        """Writes the callMethod and callFunc helper functions into the script."""
        self.write(0, "SENTINEL_VALUE = object()")
        self.emptyLine()
        self.write(0, "def callMethod(prefix, obj_to_call, method_name, *arguments):")
        current_level = self.addLevel(1)
        self.write(
            0,
            f'func_display_name = f"{self.module_name}.{{method_name}}()" if obj_to_call is {self.module_name} else f"{{obj_to_call.__class__.__name__}}.{{method_name}}()"',
        )
        self.write(0, 'message = f"[{prefix}] {func_display_name}"')
        self.write_print_to_stderr(0, "message")
        self.write(0, "result = SENTINEL_VALUE")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, "func_to_run = getattr(obj_to_call, method_name)")
        self.write(0, f"for _ in range(int({CALL_REPETITION_COUNT_CONST})):")
        self.write(1, "result = func_to_run(*arguments)")
        self.restoreLevel(current_level + 1)
        self.write(0, "except (Exception, SystemExit, KeyboardInterrupt) as err:")
        self.addLevel(1)
        self.write(0, "try:")
        self.write(1, "errmsg = repr(err)")
        self.write(0, "except Exception as e_repr:")
        self.write(1, "errmsg = f'Error during repr: {e_repr.__class__.__name__}'")
        self.write(0, "errmsg = errmsg.encode('ASCII', 'replace').decode('ASCII')")
        self.write_print_to_stderr(
            0,
            'f"[{prefix}] {func_display_name} => EXCEPTION: {err.__class__.__name__}: {errmsg}"',
        )
        self.write(0, "result = SENTINEL_VALUE")
        self.restoreLevel(current_level + 1)

        self.write_print_to_stderr(0, 'f"[{prefix}] -explicit garbage collection-"')
        self.write(0, "collect()")

        if self.enable_threads:
            self.write(0, "if result is not SENTINEL_VALUE:")
            self.write(
                1,
                "fuzzer_threads_alive.append(Thread(target=func_to_run, args=arguments, name=message))",
            )
        self.write(0, "return result")
        self.restoreLevel(current_level)
        self.emptyLine()

        self.write(0, "def callFunc(prefix, func_name_str, *arguments):")
        self.write(
            1,
            f"return callMethod(prefix, {self.module_name}, func_name_str, *arguments)",
        )
        self.emptyLine()

    def _write_main_fuzzing_logic(self) -> None:
        """Writes the core fuzzing loops for functions, classes, and objects."""
        self.write(0, f"fuzz_target_module = {self.module_name}")
        self.emptyLine()

        if self.enable_threads:
            self.write(0, "fuzzer_threads_alive = []")
        if self.enable_async:
            self.write(0, "fuzzer_async_tasks = []")
        self.emptyLine()

        if self.module_functions:
            self.write_print_to_stderr(
                0,
                f'"--- Fuzzing {len(self.module_functions)} functions in {self.module_name} ---"',
            )
            for i in range(self.options.functions_number):
                func_name = choice(self.module_functions)
                try:
                    func_obj = getattr(self.module, func_name)
                except AttributeError:
                    continue  # Should not happen if _get_module_members is correct

                prefix = f"f{i + 1}"
                self._generate_and_write_call(
                    prefix=prefix,
                    callable_name=func_name,
                    callable_obj=func_obj,
                    min_arg_count=1,
                    target_obj_expr="fuzz_target_module",
                    is_method_call=False,
                )
        self.emptyLine()

        # Fuzz classes (instantiate and call methods)
        if self.module_classes:
            self.write_print_to_stderr(
                0,
                f'"--- Fuzzing {len(self.module_classes)} classes in {self.module_name} ---"',
            )
            for i in range(self.options.classes_number):
                if not self.module_classes:
                    break
                class_name = choice(self.module_classes)
                try:
                    class_obj = getattr(self.module, class_name)
                except AttributeError:
                    continue

                self._fuzz_one_class(
                    class_idx=i, class_name_str=class_name, class_type=class_obj
                )
        self.emptyLine()

        if self.module_objects:
            self.write_print_to_stderr(
                0,
                f'"--- Fuzzing {len(self.module_objects)} objects in {self.module_name} ---"',
            )
            for i in range(self.options.objects_number):
                if not self.module_objects:
                    break
                obj_name = choice(self.module_objects)
                if obj_name in OBJECT_BLACKLIST:
                    continue
                try:
                    obj_instance = getattr(self.module, obj_name)
                except AttributeError:
                    continue
                if isinstance(obj_instance, ModuleType):
                    continue

                self._fuzz_one_module_object(
                    obj_idx=i, obj_name_str=obj_name, obj_instance=obj_instance
                )

        self.emptyLine()

    def _fuzz_one_class(
        self, class_idx: int, class_name_str: str, class_type: type
    ) -> None:
        """Generates code to instantiate a class and fuzz its methods."""
        prefix = f"c{class_idx + 1}"
        self.write_print_to_stderr(
            0, f'"[{prefix}] Attempting to instantiate class: {class_name_str}"'
        )

        is_h5py_type = hasattr(class_type, "__module__") and \
                       class_type.__module__ and \
                       class_type.__module__.startswith("h5py")
        is_h5py_file = is_h5py_type and class_name_str == "File" # Or issubclass(class_type, h5py.File)
        is_h5py_dataset = is_h5py_type and class_name_str == "Dataset" # Or issubclass(class_type, h5py.Dataset)

        instance_var_name = f"instance_c{class_idx}_{class_name_str.lower()}"  # Make unique and descriptive

        if is_h5py_file:
            # Your existing logic for calling _write_h5py_file_creation_call()
            # Ensure it defines a variable like 'new_file_obj' that you can then assign
            # to instance_var_name or use directly.
            # From your diff, it seems _write_h5py_file() defines 'new_file_obj'
            self._write_h5py_file()  # This was your name from the diff, assuming it sets 'new_file_obj'
            self.write(0, f"{instance_var_name} = new_file_obj")  # Assign to the common instance_var_name
            self.emptyLine()

        elif is_h5py_dataset:
            # For Dataset, we need a parent (File or Group).
            # Simplest: use _h5_main_file (must be defined in generated script's global scope by tricky_h5py_code)
            # Or, pick a random existing File/Group from h5py_tricky_objects or h5py_runtime_objects.

            # For now, using _h5_main_file for simplicity. A more advanced picker could be added.
            parent_obj_expr_str = "_h5_main_file"
            dataset_name_expr_str = f"{_h5_unique_name('runtime_ds_c')}"  # Ensure _h5_unique_name is available or use uuid

            self.write(0, f"# Conditionally creating h5py.Dataset {dataset_name_expr_str} on {parent_obj_expr_str}")
            self.write(0, f"if {parent_obj_expr_str} and hasattr({parent_obj_expr_str}, 'create_dataset'):")
            self.addLevel(1)
            self.write(0, f"{instance_var_name} = None # Initialize before try")
            self._write_h5py_dataset_creation_call(parent_obj_expr_str, dataset_name_expr_str, instance_var_name)
            self.restoreLevel(self.base_level - 1)  # Exit if
            self.write(0, "else:")
            self.addLevel(1)
            self.write_print_to_stderr(0,
                                       f'"Skipping dynamic Dataset creation for {instance_var_name} as parent HDF5 file/group ({parent_obj_expr_str}) is not available/valid."')
            self.write(0, f"{instance_var_name} = None")
            self.restoreLevel(self.base_level - 1)  # Exit else
            self.emptyLine()

        else:  # Original logic for other classes (from your diff, slightly adapted for clarity)
            num_constructor_args = class_arg_number(class_name_str, class_type)
            self.write(0, f"{instance_var_name} = None # Initialize instance variable")
            self.write(0, "try:")
            self.addLevel(1)
            self.write(0,
                       f"{instance_var_name} = callFunc('{prefix}_init', '{class_name_str}',")  # prefix was from original _fuzz_one_class
            self._write_arguments_for_call_lines(num_constructor_args, 1)  # Indent args by 1
            self.write(0, "  )")  # Close callFunc
            if USE_MANGLE_FEATURE:  # Assuming USE_MANGLE_FEATURE is defined
                self.write(0, mangle_loop % num_constructor_args)  # Assuming mangle_loop defined
            self.restoreLevel(self.base_level - 1)  # Exit try's indentation (level 1)
            self.write(0, "except Exception as e_instantiate:")
            self.addLevel(1)  # Indent for except block contents
            self.write_print_to_stderr(
                0,  # This 0 is relative to current base_level (which is parent's level + 1)
                f'"[{prefix}] Failed to instantiate {class_name_str}: {{e_instantiate.__class__.__name__}} {{e_instantiate}}"',
            )
            # instance_var_name remains None if already set, or if callFunc returned None
            # If callFunc might not set instance_var_name on error, set it explicitly:
            self.write(0, f"{instance_var_name} = None")
            self.restoreLevel(self.base_level - 1)  # Exit except's indentation
            self.emptyLine()

        # Common logic: if instance_var_name was successfully created, fuzz its methods
        # Inside _fuzz_one_class, after instance_var_name is potentially defined:
        self.write(0, f"if {instance_var_name} is not None and {instance_var_name} is not SENTINEL_VALUE:")
        current_level = self.addLevel(1)
        # class_type is the type object of the class that was "instantiated"
        self._fuzz_methods_on_object_or_specific_types(
            current_prefix=f"{prefix}m",  # prefix from _fuzz_one_class context, e.g., "o1m", "c1m"
            target_obj_expr_str=instance_var_name,
            target_obj_class_name=class_name_str,  # Original class name string
            target_obj_actual_type_obj=class_type,  # The actual type object
            num_method_calls_to_make=self.options.methods_number
        )
        self.restoreLevel(self.base_level - 1)
        self.write(0, f"del {instance_var_name} # Cleanup instance")
        self.write_print_to_stderr(
            0, f'"[{prefix}] -explicit garbage collection for class instance-"'
        )
        self.write(0, "collect()")
        self.restoreLevel(current_level)
        self.emptyLine()

    def _fuzz_one_dataset_instance(self, dset_expr_str: str, dset_name_for_log: str, prefix: str):
        """
        Generates code to perform a variety of operations on a given dataset instance.
        Args:
            dset_expr_str: Python expression string for the dataset instance.
            dset_name_for_log: Clean name for logging.
            prefix: Logging prefix.
        """
        self.write_print_to_stderr(0,
                                   f'f"--- Fuzzing Dataset Instance: {dset_name_for_log} (var: {dset_expr_str}, prefix: {prefix}) ---"')
        self.emptyLine()

        # --- Preamble: Get dataset context at runtime in generated script ---
        # These variables will hold the actual properties of the dataset when the fuzzed code runs.
        ctx_p = f"ctx_{prefix}"  # Context prefix to make variables unique per call

        self.write(0, f"{ctx_p}_target_dset = {dset_expr_str}")  # Assign to a short-lived var
        self.write(0, f"if {ctx_p}_target_dset is not None:")
        self.addLevel(1)  # Enter if target_dset is not None

        self.write(0, f"{ctx_p}_shape = None")
        self.write(0, f"{ctx_p}_dtype_str = None")
        self.write(0, f"{ctx_p}_dtype_obj = None")
        self.write(0, f"{ctx_p}_is_compound = False")
        self.write(0, f"{ctx_p}_is_string_like = False")
        self.write(0, f"{ctx_p}_is_chunked = False")
        self.write(0, f"{ctx_p}_is_scalar = False")
        self.write(0, f"{ctx_p}_rank = 0")
        self.write(0, f"{ctx_p}_is_empty_dataspace = False")

        self.write(0, f"try:")
        self.addLevel(1)
        self.write(0, f"{ctx_p}_shape = {ctx_p}_target_dset.shape")
        self.write(0, f"{ctx_p}_dtype_obj = {ctx_p}_target_dset.dtype")
        self.write(0, f"{ctx_p}_dtype_str = str({ctx_p}_dtype_obj)")
        self.write(0, f"{ctx_p}_is_compound = {ctx_p}_dtype_obj.fields is not None")
        self.write(0, f"{ctx_p}_is_string_like = 'S' in {ctx_p}_dtype_str or 'U' in {ctx_p}_dtype_str or \\")
        self.write(1,
                   f"'string' in {ctx_p}_dtype_str or ('vlen' in {ctx_p}_dtype_str and ('str' in {ctx_p}_dtype_str or 'bytes' in {ctx_p}_dtype_str))")
        self.write(0, f"{ctx_p}_is_chunked = {ctx_p}_target_dset.chunks is not None")
        self.write(0, f"{ctx_p}_is_scalar = ({ctx_p}_shape == () )")
        self.write(0, f"{ctx_p}_rank = len({ctx_p}_shape) if {ctx_p}_shape is not None else 0")
        self.write(0, f"{ctx_p}_is_empty_dataspace = h5py._hl.base.is_empty_dataspace({ctx_p}_target_dset.id)")
        self.write_print_to_stderr(0,
                                   f"f'''DS_OP_CTX ({dset_name_for_log}): Shape={{ {ctx_p}_shape }}, Dtype={{ {ctx_p}_dtype_str }}, Chunked={{ {ctx_p}_is_chunked }}, Scalar={{ {ctx_p}_is_scalar }}'''")
        self.restoreLevel(self.base_level - 1)  # Exit try
        self.write(0,
                   f"except Exception as e_op_ctx: print(f'''DS_OP_CTX_ERR ({dset_name_for_log}): {{e_op_ctx}}''', file=sys.stderr)")
        self.emptyLine()

        # --- Operations (within the 'if target_dset is not None:' block) ---

        # Access common properties
        properties_to_access = ["name", "shape", "dtype", "size", "chunks", "compression",
                                "compression_opts", "fillvalue", "shuffle", "fletcher32",
                                "scaleoffset", "maxshape", "file", "parent"]
        for prop_name in properties_to_access:
            self.write(0,
                       f"try: print(f'''DS_PROP ({dset_name_for_log}): .{prop_name} = {{repr(getattr({ctx_p}_target_dset, '{prop_name}'))}}''', file=sys.stderr)")
            self.write(0,
                       f"except Exception as e_prop: print(f'''DS_PROP_ERR ({dset_name_for_log}) .{prop_name}: {{e_prop}}''', file=sys.stderr)")
        self.emptyLine()

        # Call len()
        self.write(0,
                   f"try: print(f'''DS_LEN ({dset_name_for_log}): len = {{len({ctx_p}_target_dset)}}''', file=sys.stderr)")
        self.write(0,
                   f"except Exception as e_len: print(f'''DS_LEN_ERR ({dset_name_for_log}): {{e_len}}''', file=sys.stderr)")
        self.emptyLine()

        # Call repr()
        self.write(0,
                   f"try: print(f'''DS_REPR ({dset_name_for_log}): repr = {{repr({ctx_p}_target_dset)}}''', file=sys.stderr)")
        self.write(0,
                   f"except Exception as e_repr_op: print(f'''DS_REPR_ERR ({dset_name_for_log}): {{e_repr_op}}''', file=sys.stderr)")
        self.emptyLine()

        # Call .astype()
        if random() < 0.4:  # Chance to try astype
            astype_dtype_expr = self.arg_generator.genH5PyAsTypeDtype_expr()
            self.write(0,
                       f"if {ctx_p}_shape is not None and not {ctx_p}_is_empty_dataspace:")  # Astype on empty might be problematic or less interesting for now
            self.addLevel(1)
            self.write(0, f"try:")
            self.addLevel(1)
            self.write(0, f"{ctx_p}_astype_view = {ctx_p}_target_dset.astype({astype_dtype_expr})")
            self.write_print_to_stderr(0,
                                       f"f'''DS_ASTYPE ({dset_name_for_log}): view created with dtype {astype_dtype_expr}. View repr: {{repr({ctx_p}_astype_view)}}'''")
            self.write(0,
                       f"if not {ctx_p}_is_scalar and {ctx_p}_shape and product({ctx_p}_shape) > 0 :")  # product from h5py._hl.base
            self.addLevel(1)
            self.write_print_to_stderr(0,
                                       f"f'''DS_ASTYPE ({dset_name_for_log}): first elem = {{repr({ctx_p}_astype_view[tuple(0 for _ in range({ctx_p}_rank))])}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit if not scalar
            self.write(0,
                       f"{ctx_p}_arr_from_astype = numpy.array({ctx_p}_astype_view)")  # Try converting to numpy array
            self.write_print_to_stderr(0,
                                       f"f'''DS_ASTYPE ({dset_name_for_log}): converted to numpy array with shape {{ {ctx_p}_arr_from_astype.shape }}'''")
            self.restoreLevel(self.base_level - 1)  # Exit try for astype
            self.write(0,
                       f"except Exception as e_astype: print(f'''DS_ASTYPE_ERR ({dset_name_for_log}) with dtype {astype_dtype_expr}: {{e_astype}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if shape is not None
        self.emptyLine()

        # Call .asstr() (conditionally)
        if random() < 0.4:
            self.write(0,
                       f"if {ctx_p}_is_string_like and {ctx_p}_shape is not None and not {ctx_p}_is_empty_dataspace:")
            self.addLevel(1)
            asstr_enc_expr = self.arg_generator.genH5PyAsStrEncoding_expr()
            asstr_err_expr = self.arg_generator.genH5PyAsStrErrors_expr()
            self.write(0, f"try:")
            self.addLevel(1)
            self.write(0,
                       f"{ctx_p}_asstr_view = {ctx_p}_target_dset.asstr(encoding={asstr_enc_expr}, errors={asstr_err_expr})")
            self.write_print_to_stderr(0,
                                       f"f'''DS_ASSTR ({dset_name_for_log}): view created with enc {asstr_enc_expr}, err {asstr_err_expr}. View repr: {{repr({ctx_p}_asstr_view)}}'''")
            self.write(0, f"if not {ctx_p}_is_scalar and {ctx_p}_shape and product({ctx_p}_shape) > 0:")
            self.addLevel(1)
            self.write_print_to_stderr(0,
                                       f"f'''DS_ASSTR ({dset_name_for_log}): first elem = {{repr({ctx_p}_asstr_view[tuple(0 for _ in range({ctx_p}_rank))])}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit if not scalar
            self.write(0, f"{ctx_p}_arr_from_asstr = numpy.array({ctx_p}_asstr_view)")
            self.write_print_to_stderr(0,
                                       f"f'''DS_ASSTR ({dset_name_for_log}): converted to numpy array with shape {{ {ctx_p}_arr_from_asstr.shape }}'''")
            self.restoreLevel(self.base_level - 1)  # Exit try for asstr
            self.write(0,
                       f"except Exception as e_asstr: print(f'''DS_ASSTR_ERR ({dset_name_for_log}) with enc {asstr_enc_expr}: {{e_asstr}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if is_string_like
        self.emptyLine()

        # Call .fields() (conditionally)
        if random() < 0.3:
            self.write(0,
                       f"if {ctx_p}_is_compound and {ctx_p}_dtype_obj is not None and {ctx_p}_dtype_obj.fields:")  # Check if fields exist
            self.addLevel(1)
            self.write(0, f"try:")
            self.addLevel(1)
            self.write(0, f"field_names_tuple = tuple({ctx_p}_dtype_obj.fields.keys())")  # Get actual field names
            self.write(0, f"if field_names_tuple:")  # If there are fields
            self.addLevel(1)
            self.write(0, f"field_to_access = choice(field_names_tuple)")
            self.write(0,
                       f"if random() < 0.5: field_to_access = list(sample(field_names_tuple, k=min(len(field_names_tuple), randint(1,2))))")  # List of fields
            self.write(0, f"{ctx_p}_fields_view = {ctx_p}_target_dset.fields(field_to_access)")
            self.write_print_to_stderr(0,
                                       f"f'''DS_FIELDS ({dset_name_for_log}): view for {{field_to_access}}. View repr: {{repr({ctx_p}_fields_view)}}'''")
            self.write(0, f"if not {ctx_p}_is_scalar and {ctx_p}_shape and product({ctx_p}_shape) > 0:")
            self.addLevel(1)
            self.write_print_to_stderr(0,
                                       f"f'''DS_FIELDS ({dset_name_for_log}): first elem = {{repr({ctx_p}_fields_view[tuple(0 for _ in range({ctx_p}_rank))])}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit if not scalar
            self.restoreLevel(self.base_level - 1)  # Exit if field_names_tuple
            self.restoreLevel(self.base_level - 1)  # Exit try for fields
            self.write(0,
                       f"except Exception as e_fields: print(f'''DS_FIELDS_ERR ({dset_name_for_log}): {{e_fields}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if is_compound
        self.emptyLine()

        # Call .iter_chunks() (conditionally)
        if random() < 0.3:  # Your original chance
            self.write(0,
                       f"if {ctx_p}_is_chunked and not {ctx_p}_is_empty_dataspace and {ctx_p}_rank is not None:")  # Added rank check
            self.addLevel(1)
            # Use the new AG method, passing the name of the runtime rank variable
            sel_expr_iter = self.arg_generator.genH5PySliceForDirectIO_expr_runtime(f"{ctx_p}_rank")

            self.write(0, f"try:")
            self.addLevel(1)
            self.write(0, f"{ctx_p}_selection_for_iter_chunks = {sel_expr_iter}")  # Evaluate the slice expression
            self.write(0, f"{ctx_p}_chunk_count = 0")
            # Use the evaluated selection for iter_chunks
            self.write(0,
                       f"for {ctx_p}_chunk_slice in {ctx_p}_target_dset.iter_chunks({ctx_p}_selection_for_iter_chunks if {ctx_p}_selection_for_iter_chunks is not None else None):")
            self.addLevel(1)
            self.write(0, f"{ctx_p}_chunk_count += 1")
            self.write(0,
                       f"if {ctx_p}_chunk_count % 10 == 0: print(f'''DS_ITER_CHUNKS ({dset_name_for_log}): processed {{ {ctx_p}_chunk_count }} chunks...''', file=sys.stderr)")
            self.write(0, f"if {ctx_p}_chunk_count > {randint(5, 20)}: break")
            self.restoreLevel(self.base_level - 1)  # Exit for loop
            self.write_print_to_stderr(0,
                                       f"f'''DS_ITER_CHUNKS ({dset_name_for_log}): iterated {{ {ctx_p}_chunk_count }} chunks for selection {{{ctx_p}_selection_for_iter_chunks!r}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit try
            self.write(0,
                       f"except Exception as e_iterchunks: print(f'''DS_ITER_CHUNKS_ERR ({dset_name_for_log}): {{e_iterchunks}} for selection {{{ctx_p}_selection_for_iter_chunks!r}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if is_chunked
        self.emptyLine()

        # Call read_direct() / write_direct()
        if random() < 0.5 and not ctx_p + "_is_empty_dataspace" and f"{ctx_p}_rank is not None":
            # ...
            source_sel_expr = self.arg_generator.genH5PySliceForDirectIO_expr_runtime(f"{ctx_p}_rank")
            dest_sel_expr = self.arg_generator.genH5PySliceForDirectIO_expr_runtime(
                f"{ctx_p}_rank")  # Or rank of dest array

            self.write(0,
                       f"if {ctx_p}_shape is not None and product({ctx_p}_shape) > 0 and product({ctx_p}_shape) < 1000: # Only for reasonably small datasets")
            self.addLevel(1)

            self.write(0, f"try:")  # Outer try for this whole block
            self.addLevel(1)
            self.write(0, f"{ctx_p}_source_sel = {source_sel_expr}")
            self.write(0, f"{ctx_p}_dest_sel = {dest_sel_expr}")

            # Create compatible numpy array for read_direct destination or write_direct source
            # This is still complex: the shape of np_arr_for_rd needs to match dest_sel applied to some array,
            # or be the full shape if dest_sel is None or Ellipsis.
            # And shape of np_arr_for_wd needs to match source_sel applied to it.
            # For now, a simplified approach: create a NumPy array of the *same shape as the dataset*
            # if selections are simple (like None or Ellipsis). If selections are complex, this becomes harder.

            self.write(0, f"# For read_direct, np_arr_for_rd is destination")
            self.write(0, f"try:")  # Try creating dest array
            self.addLevel(1)
            # A more robust way to get shape for dest array if selection is complex is hard here.
            # For full copy or simple slice, using dataset's shape is okay.
            self.write(0, f"{ctx_p}_np_arr_for_rd = numpy.empty(shape={ctx_p}_shape, dtype={ctx_p}_dtype_obj)")
            self.write(0,
                       f"{ctx_p}_target_dset.read_direct({ctx_p}_np_arr_for_rd, source_sel={ctx_p}_source_sel, dest_sel={ctx_p}_dest_sel)")
            self.write_print_to_stderr(0,
                                       f"f'''DS_READ_DIRECT ({dset_name_for_log}): success with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit inner try for read_direct
            self.write(0,
                       f"except Exception as e_readdirect: print(f'''DS_READ_DIRECT_ERR ({dset_name_for_log}): {{e_readdirect}} with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}}''', file=sys.stderr)")

            self.write(0, f"# For write_direct, np_arr_for_wd is source")
            self.write(0, f"try:")  # Try creating source array
            self.addLevel(1)
            self.write(0,
                       f"{ctx_p}_np_arr_for_wd = numpy.zeros(shape={ctx_p}_shape, dtype={ctx_p}_dtype_obj)")  # Or arange, random etc.
            # This source array should ideally match the shape implied by source_sel
            self.write(0,
                       f"# Note: {ctx_p}_np_arr_for_wd shape should ideally match source_sel's effect on itself.")
            self.write(0,
                       f"{ctx_p}_target_dset.write_direct({ctx_p}_np_arr_for_wd, source_sel={ctx_p}_source_sel, dest_sel={ctx_p}_dest_sel)")
            self.write_print_to_stderr(0,
                                       f"f'''DS_WRITE_DIRECT ({dset_name_for_log}): success with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit inner try for write_direct
            self.write(0,
                       f"except Exception as e_writedirect: print(f'''DS_WRITE_DIRECT_ERR ({dset_name_for_log}): {{e_writedirect}} with src_sel {{{ctx_p}_source_sel!r}} dst_sel {{{ctx_p}_dest_sel!r}}''', file=sys.stderr)")

            self.restoreLevel(self.base_level - 1)  # Exit outer try
            self.write(0,
                       f"except Exception as e_direct_io_setup: print(f'''DS_DIRECT_IO_SETUP_ERR ({dset_name_for_log}): {{e_direct_io_setup}}''', file=sys.stderr)")

            self.restoreLevel(self.base_level - 1)  # Exit if shape is small
        self.emptyLine()

        # __setitem__ with Fancy Indexing (more targeted if possible)
        if random() < 0.15:
            self.write(0,
                       f"if {ctx_p}_rank >= 2 and {ctx_p}_shape and {ctx_p}_shape[0] > 0 and {ctx_p}_shape[1] > 2:")  # Condition for this specific fancy index
            self.addLevel(1)
            self.write(0, "try:")
            self.addLevel(1)
            self.write(0,
                       f"{ctx_p}_fancy_indices = sorted(sample(range({ctx_p}_shape[1]), k=min({ctx_p}_shape[1], randint(1,3))))")
            # Shape of block_data needs to match dataset[:, fancy_indices, ...].shape
            self.write(0, f"{ctx_p}_block_shape = list({ctx_p}_shape)")
            self.write(0, f"{ctx_p}_block_shape[1] = len({ctx_p}_fancy_indices)")
            self.write(0,
                       f"{ctx_p}_block_data = numpy.zeros(tuple({ctx_p}_block_shape), dtype={ctx_p}_dtype_obj)")  # Or random data
            self.write(0, f"{ctx_p}_target_dset[:, {ctx_p}_fancy_indices, ...] = {ctx_p}_block_data")
            self.write_print_to_stderr(0,
                                       f"f'''DS_FANCY_SETITEM ({dset_name_for_log}): success with indices {{{ctx_p}_fancy_indices}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit try
            self.write(0,
                       f"except Exception as e_fancyitem: print(f'''DS_FANCY_SETITEM_ERR ({dset_name_for_log}): {{e_fancyitem}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if rank >=2
        self.emptyLine()

        # Iteration
        if random() < 0.3:
            self.write(0,
                       f"if not {ctx_p}_is_scalar and {ctx_p}_shape and {ctx_p}_shape[0] > 0 and not {ctx_p}_is_empty_dataspace:")  # Can iterate if not scalar and first dim > 0
            self.addLevel(1)
            self.write(0, "try:")
            self.addLevel(1)
            self.write(0, f"{ctx_p}_iter_count = 0")
            self.write(0, f"for {ctx_p}_row in {ctx_p}_target_dset:")
            self.addLevel(1)
            self.write(0, f"{ctx_p}_iter_count += 1")
            self.write(0, f"if {ctx_p}_iter_count > {randint(3, 7)}: break")
            self.restoreLevel(self.base_level - 1)  # Exit for
            self.write_print_to_stderr(0, f"f'''DS_ITER ({dset_name_for_log}): iterated {{{ctx_p}_iter_count}} rows'''")
            self.restoreLevel(self.base_level - 1)  # Exit try
            self.write(0,
                       f"except Exception as e_iter: print(f'''DS_ITER_ERR ({dset_name_for_log}): {{e_iter}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if not scalar
        self.emptyLine()

        # Comparisons
        if random() < 0.3:
            comp_val_expr = self.arg_generator.genNumpyValueForComparison_expr(f"{ctx_p}_dtype_str")
            self.write(0, f"if {ctx_p}_dtype_str is not None:")  # Only if dtype context was obtained
            self.addLevel(1)
            self.write(0, "try:")
            self.addLevel(1)
            self.write(0, f"{ctx_p}_comp_val = {comp_val_expr}")
            self.write(0, f"{ctx_p}_is_equal = ({ctx_p}_target_dset == {ctx_p}_comp_val)")
            self.write(0, f"{ctx_p}_is_not_equal = ({ctx_p}_target_dset != {ctx_p}_comp_val)")
            self.write_print_to_stderr(0,
                                       f"f'''DS_COMPARE ({dset_name_for_log}): == type {{type({ctx_p}_is_equal).__name__}}, != type {{type({ctx_p}_is_not_equal).__name__}}'''")
            self.restoreLevel(self.base_level - 1)  # Exit try
            self.write(0,
                       f"except Exception as e_compare: print(f'''DS_COMPARE_ERR ({dset_name_for_log}): {{e_compare}}''', file=sys.stderr)")
            self.restoreLevel(self.base_level - 1)  # Exit if dtype_str
        self.emptyLine()

        # Access some .id properties
        if random() < 0.2:
            id_props_to_get = ["get_type()", "get_create_plist()", "get_access_plist()",
                               "get_offset()", "get_storage_size()"]
            for id_prop_call in id_props_to_get:
                self.write(0,
                           f"try: print(f'''DS_ID_PROP ({dset_name_for_log}): .id.{id_prop_call} result = {{repr({ctx_p}_target_dset.id.{id_prop_call})}}''', file=sys.stderr)")
                self.write(0,
                           f"except Exception as e_id_prop: print(f'''DS_ID_PROP_ERR ({dset_name_for_log}) .id.{id_prop_call}: {{e_id_prop}}''', file=sys.stderr)")
            self.emptyLine()

        self.restoreLevel(self.base_level - 1)  # Exit 'if target_dset is not None:'
        self.write(0, "else:")
        self.addLevel(1)
        self.write_print_to_stderr(0,
                                   f'f"Skipping dataset operations for {dset_name_for_log} as target_dset is None."')
        self.restoreLevel(self.base_level - 1)  # Exit else
        self.emptyLine()

    def _write_h5py_file(self):
        # In WritePythonCode._write_h5py_file(self):

        # 1. Get actual driver and mode strings first
        actual_driver = self.arg_generator.genH5PyFileDriver_actualval()  # New AG method
        actual_mode = self.arg_generator.genH5PyFileMode_actualval()  # New AG method

        driver_expr = f"'{actual_driver}'" if actual_driver else "None"
        mode_expr = f"'{actual_mode}'"

        # 2. Determine if backing store is True for core driver (affects path generation)
        #    This info should come from genH5PyDriverKwargs based on actual_driver
        #    Let's assume driver_kwargs_str_list and driver_kwargs_expr are generated here.
        #    For simplicity, assume a helper:
        #    is_core_backing = (actual_driver == 'core' and self.arg_generator.is_core_backing_store_enabled_in_kwargs(...))
        is_core_backing = False  # Placeholder, needs logic based on generated driver_kwargs
        driver_kwargs_expr = None
        if actual_driver == 'core':
            # A simplified way to decide: if driver_kwargs mentions backing_store=True
            # This is still a bit messy; genH5PyDriverKwargs ideally should not produce
            # incompatible options with driver='core', backing_store=False if path is just an ID.
            # The generation of driver_kwargs needs to be smarter.
            # For now, let's assume it's generated:
            driver_kwargs_str_list = self.arg_generator.genH5PyDriverKwargs(actual_driver)
            driver_kwargs_expr = "".join(driver_kwargs_str_list)
            if "backing_store=True" in driver_kwargs_expr:
                is_core_backing = True

        # 3. Generate the file name or object expression
        #    This is a crucial change. gen_h5py_file_name_or_object needs to be implemented in AG.
        #    It might return a variable name like 'temp_file_path_xyz' if it means a disk file.
        name_arg_expression, setup_code_lines = self.arg_generator.gen_h5py_file_name_or_object(
            actual_driver, actual_mode, is_core_backing
        )

        for line in setup_code_lines:  # If gen_... needs to emit setup code (e.g. creating tempfile path variable)
            self.write(0, line)

        # 4. Generate other kwargs
        libver_expr = "".join(self.arg_generator.genH5PyLibver())
        userblock_val_str = "".join(self.arg_generator.genH5PyUserblockSize())  # e.g., "512"
        locking_expr = "".join(self.arg_generator.genH5PyLocking())
        fs_kwargs_expr = ""  # Default to empty

        all_kwargs = []
        if actual_driver: all_kwargs.append(f"driver={driver_expr}")
        if driver_kwargs_expr: all_kwargs.append(driver_kwargs_expr)  # This should be just the kwargs string
        if libver_expr != "None": all_kwargs.append(f"libver={libver_expr}")
        if locking_expr != "None": all_kwargs.append(f"locking={locking_expr}")

        # Conditional creation-only parameters
        if actual_mode in ('w', 'w-', 'x'):  # Only for pure creation modes
            if userblock_val_str != "0":
                all_kwargs.append(f"userblock_size={userblock_val_str}")

            # Your fs_strategy tweak - apply only for creation modes
            if randint(0, 9) > 1:  # Reduced chance further from your "> 8" if still too many errors
                fs_kwargs_str_list_temp = self.arg_generator.genH5PyFsStrategyKwargs()
                fs_kwargs_expr_temp = "".join(fs_kwargs_str_list_temp)
                if fs_kwargs_expr_temp:  # Only add if it generated something
                    all_kwargs.append(fs_kwargs_expr_temp)
                    fs_kwargs_expr = fs_kwargs_expr_temp  # Store it for logging

        kwargs_final_str = ", ".join(filter(None, all_kwargs))

        # 5. Write the h5py.File call
        self.write(0, f"new_file_obj = None # Initialize before try block")  # Good practice
        self.write(0, f"try:")
        self.addLevel(1)
        self.write(0, f"new_file_obj = h5py.File({name_arg_expression}, mode={mode_expr}, {kwargs_final_str})")
        self.write(0, f"if new_file_obj: # Check if successfully created")
        self.addLevel(1)
        self.write(0, f"h5py_tricky_objects['runtime_file_{uuid.uuid4().hex[:4]}'] = new_file_obj")
        self.write(0, f"_h5_internal_files_to_keep_open_.append(new_file_obj)")
        self.restoreLevel(self.base_level - 1)  # Exit if
        self.restoreLevel(self.base_level - 1)  # Exit try

        self.write(0, f"except Exception as e_file_create:")
        # The original had new_file_obj = None inside except, but it's already None if exception occurs
        self.addLevel(1)
        # Using triple quotes for the f-string in print to handle potential quotes in expressions
        self.write(0,
                   f"print(f'''FUZZ_RUNTIME_WARN: Failed to create h5py.File({name_arg_expression}, {mode_expr}, {kwargs_final_str}): {{e_file_create.__class__.__name__}} {{e_file_create}}''', file=sys.stderr)")
        self.restoreLevel(self.base_level - 1)  # Exit except
        self.emptyLine()

    def _write_h5py_dataset_creation_call(
            self, parent_obj_expr: str, dataset_name_expr: str, instance_var_name: str
    ):
        """
        Generates and writes a call to parent_obj_expr.create_dataset()
        with fuzzed parameters. The result (or None on failure) is assigned
        to instance_var_name.
        """
        self.write(0, f"# Dynamically creating dataset: {dataset_name_expr} on {parent_obj_expr}")

        # Generate parameters using ArgumentGenerator
        # For Category B, we primarily use simple dtypes.
        # Data generation is tricky to make always compatible with shape/dtype via string expr.
        # It's often safer to create dataset first, then write data.
        # Or, create with shape and dtype, and let h5py handle/error on data.

        shape_expr = self.arg_generator.genH5PyDatasetShape_expr()
        if random() < 0.4:  # 40% chance to try a complex dtype
            dtype_expr = self.arg_generator.genH5PyComplexDtype_expr()
            # Data generation for complex dtypes is hard; often best to omit data or use h5py.Empty
            if random() < 0.8 or "vlen" in dtype_expr or "enum" in dtype_expr:  # Higher chance to omit data for these
                data_expr = "None"
            else:  # For simpler compound or array dtypes, might try to generate some zeros
                data_expr = f"numpy.zeros({shape_expr}, dtype={dtype_expr})" if shape_expr != "None" and shape_expr != "()" else "None"

            # Special case for h5py.Empty which needs a dtype but not shape/data
            if shape_expr == "None" and data_expr == "None":
                data_expr = f"h5py.Empty(dtype={dtype_expr})"
                # Shape should remain None if data is h5py.Empty
        else:
            dtype_expr = self.arg_generator.genH5PySimpleDtype_expr()
            data_expr = self.arg_generator.genH5PyData_expr(shape_expr, dtype_expr)  # Existing logic

        # Most other parameters are kwargs
        kwargs_list = []
        if data_expr != "None":
            kwargs_list.append(f"data={data_expr}")

        # Chunks: scaleoffset needs chunks. Some compression benefits from chunks.
        # maxshape always implies chunks (auto-created if not specified).
        chunks_expr = self.arg_generator.genH5PyDatasetChunks_expr(shape_expr)
        if chunks_expr != "None":  # Only add if not default contiguous
            kwargs_list.append(f"chunks={chunks_expr}")
            # If chunks are being set, it's safer to also set maxshape if we want resizability
            if random() < 0.5:  # Chance to add maxshape if chunked
                kwargs_list.append(f"maxshape={self.arg_generator.genH5PyMaxshape_expr(shape_expr)}")

        # Fillvalue and FillTime
        # fillvalue needs to be compatible with dtype.
        # genH5PyFillvalue_expr tries to do this for simple dtypes.
        if random() < 0.7:  # 70% chance to specify fillvalue
            fv_expr = self.arg_generator.genH5PyFillvalue_expr(dtype_expr)
            if fv_expr != "None":  # if generator provided something specific
                kwargs_list.append(f"fillvalue={fv_expr}")

        if random() < 0.5:  # 50% chance to specify fill_time
            kwargs_list.append(f"fill_time={self.arg_generator.genH5PyFillTime_expr()}")

        # Compression and other filters
        compression_kwargs = self.arg_generator.genH5PyCompressionKwargs_expr()  # This returns a list of "kw=val"
        kwargs_list.extend(compression_kwargs)

        # Track times
        if random() < 0.5:
            kwargs_list.append(f"track_times={self.arg_generator.genH5PyTrackTimes_expr()}")

        # Assemble the create_dataset call string
        # Base parameters are shape and dtype, others are kwargs
        # Handle cases: shape only, dtype only (for null dataspace), shape+dtype, or data only

        kwds_for_create = {}  # Use a dict then format
        if shape_expr != "None": kwds_for_create['shape'] = shape_expr
        if dtype_expr != "None": kwds_for_create['dtype'] = dtype_expr  # Always good to have dtype
        if data_expr != "None": kwds_for_create['data'] = data_expr

        # Add other kwargs from kwargs_list (which are already "key=value" strings)
        # This needs refinement. Let's make kwargs_list a list of (key_str, value_expr_str) tuples
        # from ArgumentGenerator, then format them here.

        # Simplified:
        # Assume genH5PyCompressionKwargs_expr returns a list of "kw=val" strings
        # All generated parameters should be in kwargs_list as "key=value" strings.

        # Let's redefine how kwargs are collected:
        all_kwargs_dict = {}
        if shape_expr != "None": all_kwargs_dict["shape"] = shape_expr
        all_kwargs_dict["dtype"] = dtype_expr  # dtype is good to provide generally, or from data
        if data_expr != "None": all_kwargs_dict["data"] = data_expr

        if chunks_expr != "None": all_kwargs_dict["chunks"] = chunks_expr
        if random() < 0.5 and "chunks" in all_kwargs_dict:  # maxshape often with chunks
            all_kwargs_dict["maxshape"] = self.arg_generator.genH5PyMaxshape_expr(shape_expr)

        if random() < 0.7:
            fv_expr = self.arg_generator.genH5PyFillvalue_expr(dtype_expr)
            if fv_expr != "None": all_kwargs_dict["fillvalue"] = fv_expr
        if random() < 0.5:
            all_kwargs_dict["fill_time"] = self.arg_generator.genH5PyFillTime_expr()

        compression_kwargs_strings = self.arg_generator.genH5PyCompressionKwargs_expr()  # list of "key=val"
        for comp_kw_str in compression_kwargs_strings:
            key, val = comp_kw_str.split('=', 1)
            all_kwargs_dict[key] = val  # Assumes val is already a valid expression string

        if random() < 0.5:
            all_kwargs_dict["track_times"] = self.arg_generator.genH5PyTrackTimes_expr()

        final_kwargs_str = ", ".join(f"{k}={v}" for k, v in all_kwargs_dict.items() if v is not None)

        self.write(0, f"try:")
        self.addLevel(1)
        self.write(0,
                   f"{instance_var_name} = {parent_obj_expr}.create_dataset('{dataset_name_expr}', {final_kwargs_str})")
        self.write(0, f"if {instance_var_name}:")
        self.addLevel(1)
        # Using a different dict key for runtime created datasets for clarity
        self.write(0, f"h5py_runtime_objects['{dataset_name_expr.strip(chr(39))}'] = {instance_var_name}")
        self.restoreLevel(self.base_level - 1)  # Exit if
        self.restoreLevel(self.base_level - 1)  # Exit try
        self.write(0, f"except Exception as e_dset_create:")
        self.addLevel(1)
        # instance_var_name should already be None if try block failed before assignment or if create_dataset returned None
        self.write(0, f"{instance_var_name} = None")  # Ensure it's None on error
        # Using triple quotes for the f-string in print
        self.write(0, f"try:")
        self.write_print_to_stderr(
            1,
            f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {dataset_name_expr} on {{ {parent_obj_expr} }} "
            f"with args {{ repr(dict({final_kwargs_str})) }}: "  # Log evaluated args if possible, or raw string
            f"{{e_dset_create.__class__.__name__}} {{e_dset_create}}'''"
        )
        self.write(0, f"except Exception as e_dset_print_error:")
        self.write(1, f"f'''FUZZ_RUNTIME_WARN: Failed to create dataset {dataset_name_expr} on {{ {parent_obj_expr} }} "
            f"with args ERROR_PRINTING_ARGS: "
            f"{{e_dset_create.__class__.__name__}} {{e_dset_create}}'''")
        self.restoreLevel(self.base_level - 1)  # Exit except
        self.emptyLine()

    def _fuzz_methods_on_object_or_specific_types(
            self,
            current_prefix: str,  # e.g., "o1m", "c1_instm"
            target_obj_expr_str: str,  # e.g., "instance_c0_dataset", "h5py_tricky_objects.get('some_key')"
            target_obj_class_name: str,  # e.g., "Dataset", "File", "MyClass" (for logging/heuristics)
            target_obj_actual_type_obj: Any,  # The actual type object if available to WritePythonCode, else None
            num_method_calls_to_make: int
    ):
        self.write_print_to_stderr(0,
                                   f'f"--- Fuzzing instance: {target_obj_expr_str} (type hint: {target_obj_class_name}, prefix: {current_prefix}) ---"')

        # Check if it's an h5py.Dataset and call specialized fuzzing for it
        # We need h5py imported in the generated script for isinstance
        self.write(0, f"if isinstance({target_obj_expr_str}, h5py.Dataset):")
        self.addLevel(1)
        # Use a clean name for logging, e.g., derived from target_obj_expr_str or its HDF5 name
        dset_log_name = target_obj_expr_str.split('.')[-1].strip("')\"")  # Basic heuristic for name
        self._fuzz_one_dataset_instance(target_obj_expr_str, dset_log_name, current_prefix)
        self.restoreLevel(self.base_level - 1)
        # Optionally, after specific fuzzing, still do some random method calls or reduce num_method_calls_to_make
        # For now, let's assume _fuzz_one_dataset_instance is comprehensive enough for datasets for this pass.

        # elif isinstance({target_obj_expr_str}, h5py.File):
        # self._fuzz_one_file_instance(target_obj_expr_str, ..., current_prefix) # Similarly for files
        # elif isinstance({target_obj_expr_str}, h5py.Group):
        # self._fuzz_one_group_instance(target_obj_expr_str, ..., current_prefix)

        # else: # General method fuzzing for other types
        self.write(0, f"# General method fuzzing for {target_obj_expr_str}")
        methods_dict = {}
        if target_obj_actual_type_obj:  # If WritePythonCode has the type
            methods_dict = self._get_object_methods(target_obj_actual_type_obj, target_obj_class_name)
        else:  # Try to get methods at runtime in generated script (less ideal for setup)
            self.write(0,
                       f"try: runtime_methods_{current_prefix} = {{name: getattr({target_obj_expr_str}, name) for name in dir({target_obj_expr_str}) if callable(getattr({target_obj_expr_str}, name, None))}}")
            # This ^ is complex for generated code. Simpler to rely on type info if available.
            # For now, we'll assume methods_dict comes from _get_object_methods based on type info.
            pass  # Fallback or skip if no type info

        # The original callFunction/writeCode loop for random methods would go here,
        # using methods_dict. This part is from your existing fuzzer logic.
        # For example:
        if methods_dict:
            method_names_list = sorted(list(methods_dict.keys()))
            if method_names_list:
                for m_idx in range(num_method_calls_to_make):
                    chosen_method_name = choice(method_names_list)
                    chosen_method_obj = methods_dict[chosen_method_name] # Actual method callable
                    self._generate_and_write_call( # Your generic method call writer
                        prefix=f"{current_prefix}{m_idx+1}",
                        callable_name=chosen_method_name,
                        callable_obj=chosen_method_obj,
                        min_arg_count=0, # Heuristic for methods
                        target_obj_expr=target_obj_expr_str,
                        is_method_call=True
                    )
        self.write_print_to_stderr(0, f'f"--- Finished fuzzing instance: {target_obj_expr_str} ---"')
        self.emptyLine()

    def _fuzz_one_module_object(
        self, obj_idx: int, obj_name_str: str, obj_instance: Any
    ) -> None:
        """Generates code to fuzz methods of a given module-level object."""
        prefix = f"obj{obj_idx + 1}"
        obj_expr_in_script = f"fuzz_target_module.{obj_name_str}"

        self._fuzz_methods_on_object_or_specific_types(
            current_prefix=f"obj{obj_idx}m",  # Prefix for this object
            target_obj_expr_str=obj_expr_in_script,
            target_obj_class_name=obj_instance.__class__.__name__,  # Get class name from instance
            target_obj_actual_type_obj=type(obj_instance),  # Get type from instance
            num_method_calls_to_make=self.options.methods_number
        )
        self.write_print_to_stderr(
            0, f'"[{prefix}] -explicit garbage collection for module object bindings-"'
        )
        self.write(0, "collect()")
        self.emptyLine()

    def _write_arguments_for_call_lines(
        self, num_args: int, base_indent_level: int
    ) -> None:
        """Generates and writes argument lines for a function/method call."""
        for i in range(num_args):
            arg_lines = self.arg_generator.create_complex_argument()
            last_char = "," if i < num_args - 1 else ""

            if not arg_lines:
                self.write(base_indent_level, f"None{last_char} # Empty arg generated")
                continue

            self.write(
                base_indent_level,
                arg_lines[0] + (last_char if len(arg_lines) == 1 else ""),
            )
            for arg_line_part in arg_lines[1:]:
                self.write(
                    base_indent_level,
                    arg_line_part
                    + (last_char if arg_line_part == arg_lines[-1] else ""),
                )

    def _generate_and_write_call(
        self,
        prefix: str,
        callable_name: str,
        callable_obj: Callable[..., Any],
        min_arg_count: int,
        target_obj_expr: str,  # e.g., "fuzz_target_module" or "instance_var"
        is_method_call: bool,
    ) -> None:
        """Generates code for a single function or method call, including async/thread wrappers."""

        if callable_name.lower() in {
            "abort",
            "systemerror",
            "fatal",
            "critical",
            "assert",
        }:
            return

        min_arg, max_arg = get_arg_number(callable_obj, callable_name, min_arg_count)

        rand_choice = randint(0, 19)
        if rand_choice < 1:  # 0 (5%)
            num_args = 0
        elif rand_choice < 2:  # 1 (5%)
            num_args = 1
        elif rand_choice < 3:  # max_arg + 1 (5%)
            num_args = max_arg + 1
        elif min_arg == max_arg:
            num_args = min_arg
        else:  # (remaining 85%)
            num_args = randint(min_arg, max_arg)

        call_prefix = (
            f'callMethod("{prefix}", {target_obj_expr}, "{callable_name}"'
            if is_method_call
            else f'callFunc("{prefix}", "{callable_name}"'
        )

        self.write(0, f"res_{prefix} = {call_prefix},")
        self._write_arguments_for_call_lines(num_args, 1)
        self.write(0, ")")
        self.emptyLine()

        if self.enable_threads or self.enable_async:
            self.write(0, "target_func = None")
            self.write(0, "try:")
            self.write(
                1, f"target_func = getattr({target_obj_expr}, '{callable_name}')"
            )
            self.write(0, "except Exception as e_get_target_func:")
            self.write_print_to_stderr(
                1,
                f'f"[{prefix}] Failed to get attribute {callable_name} from {target_obj_expr}: '
                f'{{e_get_target_func.__class__.__name__}} {{e_get_target_func}}"',
            )
        self.emptyLine()

        if self.enable_threads:
            self.write(0, "if target_func is not None:")
            self.addLevel(1)
            self.write(0, "try:")
            self.addLevel(1)
            arg_expr_list = []
            for _ in range(num_args):
                arg_lines = self.arg_generator.create_simple_argument()
                arg_expr_list.append(" ".join(arg_lines))

            args_tuple_str = f"({', '.join(arg_expr_list)}{',' if len(arg_expr_list) == 1 and num_args == 1 else ''})"

            self.write(
                0,
                f"thread_obj = Thread(target=target_func, args={args_tuple_str}, name='{prefix}_{callable_name}')",
            )
            self.write(0, "fuzzer_threads_alive.append(thread_obj)")
            self.restoreLevel(self.base_level - 1)
            self.write(0, "except Exception as e_thread_create:")
            self.write_print_to_stderr(
                1,
                f'f"[{prefix}] Failed to create thread for {callable_name}: {{e_thread_create.__class__.__name__}}"',
            )
            self.addLevel(-1)
            self.emptyLine()

        if self.enable_async:
            async_func_name = f"async_call_{prefix}_{callable_name}"
            self.write(0, "if target_func is not None:")
            self.addLevel(1)
            self.write(0, f"def {async_func_name}(target_func=target_func):")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"Starting async task: {async_func_name}"')
            self.write(0, f"time.sleep({random() / 1000:.6f}) # Small delay")
            self.write(0, "try:")
            self.addLevel(1)
            arg_expr_list_async = []
            for _ in range(num_args):
                arg_lines = self.arg_generator.create_simple_argument()
                arg_expr_list_async.append(" ".join(arg_lines))

            args_str_async = ", ".join(arg_expr_list_async)

            self.write(
                0, f"target_func({args_str_async})"
            )
            self.addLevel(-1)
            self.write(0, "except Exception as e_async_call:")
            self.write_print_to_stderr(
                1,
                f'f"[{prefix}] Exception in async task {async_func_name}: {{e_async_call.__class__.__name__}} {{e_async_call}}"',
            )
            self.write_print_to_stderr(0, f'"Ending async task: {async_func_name}"')
            self.addLevel(-1)  # Exit def
            self.write(0, f"fuzzer_async_tasks.append({async_func_name})")
            self.addLevel(-1)
            self.emptyLine()

    def _write_concurrency_finalization(self) -> None:
        """Writes code to start/join threads and run asyncio tasks."""
        if self.enable_threads:
            self.write_print_to_stderr(
                0, '"--- Starting and Joining Fuzzer Threads ---"'
            )
            self.write(0, "for t_obj in fuzzer_threads_alive:")
            self.write(1, "try:")
            self.write_print_to_stderr(2, 'f"Starting thread: {t_obj.name}"')
            self.write(2, "t_obj.start()")
            self.write(1, "except Exception as e_thread_start:")
            self.write_print_to_stderr(
                2,
                'f"Failed to start thread {t_obj.name}: {e_thread_start.__class__.__name__}"',
            )
            self.write(0, "for t_obj in fuzzer_threads_alive:")
            self.write(1, "try:")
            self.write_print_to_stderr(2, 'f"Joining thread: {t_obj.name}"')
            self.write(2, "t_obj.join(timeout=1.0) # Add timeout to join")
            self.write(1, "except Exception as e_thread_join:")
            self.write_print_to_stderr(
                2,
                'f"Failed to join thread {t_obj.name}: {e_thread_join.__class__.__name__}"',
            )
            self.emptyLine()

        if self.enable_async:
            self.write_print_to_stderr(0, '"--- Running Fuzzer Async Tasks ---"')
            self.write(0, "async def main_async_fuzzer_tasks():")
            self.write(1, "if not fuzzer_async_tasks: return")
            self.write(
                1,
                "task_objects = [asyncio.to_thread(func) for func in fuzzer_async_tasks]",
            )
            self.write(1, "await asyncio.gather(*task_objects, return_exceptions=True)")
            self.emptyLine()
            # self.write(0, "asyncio.run(main_async_fuzzer_tasks())") # Python 3.7+
            self.write(0, "runner = asyncio.Runner()")
            self.write(0, "try:")
            self.write(1, "runner.run(main_async_fuzzer_tasks())")
            self.write(0, "except Exception as e_async_runner_run:")
            self.write(1, "print(f'Exception in async runner: {e_async_runner_run.__class__.__name__} {e_async_runner_run}')")
            self.write(0, "finally:")
            self.write(1, "runner.close()")
            self.emptyLine()

    def generate_fuzzing_script(self) -> None:
        """Creates and writes the entire fuzzing script to the specified file."""
        self.createFile(self.generated_filename)

        self._write_script_header_and_imports()
        self._write_tricky_definitions()
        self._write_helper_call_functions()
        self._write_main_fuzzing_logic()
        self._write_concurrency_finalization()

        self.parent_python_source.warning(
            f'--- Fuzzing script generation for {self.module_name} complete ---'
        )
        self.close()
