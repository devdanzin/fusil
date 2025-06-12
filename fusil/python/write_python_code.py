from __future__ import annotations

import builtins
import inspect
import time
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
from fusil.python.mangle_object import mangle_loop, mangle_obj
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

_ARG_GEN_USE_H5PY = False
if _ARG_GEN_USE_NUMPY:
    try:
        import h5py
        print(f"h5py is available.")
        _ARG_GEN_USE_H5PY = True
        from fusil.python.h5py.write_h5py_code import WriteH5PyCode
        import fusil.python.h5py.h5py_tricky_weird
    except ImportError:
        print("h5py is not available.")
        _ARG_GEN_USE_H5PY = False

time_start = time.time()
USE_MANGLE_FEATURE = False
CALL_REPETITION_COUNT_CONST = 3
ERRBACK_NAME_CONST = "errback"
EXCEPTION_NAMES = {
    cls.__name__
    for cls in builtins.__dict__.values()
    if isinstance(cls, type) and issubclass(cls, Exception)
}
TRIVIAL_TYPES = {
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
}
TRIVIAL_TYPES_STR = "{int, str, float, bool, bytes, tuple, list, dict, set, type(None),}"


class PythonFuzzerError(Exception):
    """Custom exception raised when fuzzer encounters unrecoverable errors."""


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
        use_h5py: bool = False,
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
        self.jit_warmed_targets = []
        self.h5py_writer = WriteH5PyCode(self) if use_h5py and _ARG_GEN_USE_H5PY else None

        self.arg_generator = ArgumentGenerator(
            self.options, self.filenames, _ARG_GEN_USE_NUMPY, _ARG_GEN_USE_TEMPLATES, _ARG_GEN_USE_H5PY
        )

        self.module_functions: list[str]
        self.module_classes: list[str]
        self.module_objects: list[str]
        self.module_functions, self.module_classes, self.module_objects = self._get_module_members()

        if not self.module_functions and not self.module_classes and not self.module_objects:
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
                    # and attr.__name__ in _EXCEPTION_NAMES
                ):
                    continue
                classes.append(name)
            else:
                if isinstance(attr, ModuleType) or type(attr) in TRIVIAL_TYPES:
                    continue
                if (
                    not self.options.fuzz_exceptions
                    and isinstance(attr, BaseException)
                    # and attr.__class__.__name__ in _EXCEPTION_NAMES
                ):
                    continue
                objects.append(name)
        return functions, classes, objects

    def _get_object_methods(
        self, obj_instance_or_class: Any, owner_name: str
    ) -> dict[str, Callable[..., Any]]:
        """Extracts callable methods from an object or class, respecting blacklists."""
        methods: dict[str, Callable[..., Any]] = {}
        if type(obj_instance_or_class) in TRIVIAL_TYPES:
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
                (not self.options.test_private) and name.startswith("_")
                # and not name.endswith("__")
            ):
                # if name not in {
                #     "__init__",
                #     "__call__",
                #     "__getitem__",
                #     "__setitem__",
                #     "__iter__",
                #     "__next__",
                #     "__len__",
                #     "__contains__",
                #     "__eq__",
                #     "__lt__",
                #     "__gt__",
                #     "__le__",
                #     "__ge__",
                #     "__repr__",
                #     "__str__",
                # }:
                continue

            if is_exception_type_or_instance and name == "__init__":  # Avoid re-initing exceptions
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
                from random import choice, randint, random
                from sys import stderr, path as sys_path
                from os.path import dirname
                import ast
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

        if self.h5py_writer:
            self.h5py_writer._write_h5py_script_header_and_imports()

        self.write(
            0,
            dedent(f"""\
        TRIVIAL_TYPES = {TRIVIAL_TYPES_STR}
        def skip_trivial_type(obj_instance_or_class):
            if type(obj_instance_or_class) in TRIVIAL_TYPES:
                return True
            return False
        """),
        )
        self.emptyLine()

    def _write_tricky_definitions(self) -> None:
        """Writes definitions for 'tricky' classes and objects."""
        self.write(0, fusil.python.tricky_weird.weird_classes)
        self.emptyLine()
        self.write(0, fusil.python.tricky_weird.tricky_typing)
        self.emptyLine()
        self.write(0, fusil.python.tricky_weird.tricky_objects)
        self.emptyLine()
        if not self.options.no_numpy and _ARG_GEN_USE_NUMPY and _ARG_GEN_USE_H5PY:
            self.write(0, "import numpy")
            self.write(0, fusil.python.tricky_weird.tricky_numpy)
            self.emptyLine()

        if not self.options.no_numpy and _ARG_GEN_USE_NUMPY and _ARG_GEN_USE_H5PY:
            self.write(0, "# Executing HDF5 tricky object generation code")
            self.write(0, fusil.python.h5py.h5py_tricky_weird.tricky_h5py_code)
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
                prefix = f"f{i + 1}"

                # JIT Mode Logic
                level = self.options.jit_fuzz_level

                # At the highest level, try to generate a mixed scenario
                if level >= 3 and random() < self.options.jit_hostile_prob:
                    mixed_scenario_generators = [
                        self._generate_mixed_many_vars_scenario,
                        self._generate_del_invalidation_scenario,
                    ]
                    chosen_generator = choice(mixed_scenario_generators)
                    chosen_generator(prefix)
                    continue

                # At level 2, try to generate an isolated hostile scenario
                if level >= 2 and random() < self.options.jit_hostile_prob:
                    # Randomly pick one of the simple hostile scenarios
                    # For now, we only have the deleter, but you would add others here
                    self._generate_deleter_scenario(prefix)  # The one we made before
                    continue

                if self.options.jit_fuzz and random() < self.options.jit_pattern_mix_prob:
                    # Decide randomly between a pattern block or a polymorphic call
                    if random() < 0.5:
                        self._generate_jit_pattern_block(prefix)
                    else:
                        self._generate_polymorphic_call_block(prefix)
                    continue

                func_name = choice(self.module_functions)
                try:
                    func_obj = getattr(self.module, func_name)
                except AttributeError:
                    continue  # Should not happen if _get_module_members is correct

                self._generate_and_write_call(
                    prefix=prefix,
                    callable_name=func_name,
                    callable_obj=func_obj,
                    min_arg_count=1,
                    target_obj_expr="fuzz_target_module",
                    is_method_call=False,
                    generation_depth=0,
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

                self._fuzz_one_class(class_idx=i, class_name_str=class_name, class_type=class_obj)
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

    def _fuzz_one_class(self, class_idx: int, class_name_str: str, class_type: type) -> None:
        """Generates code to instantiate a class and fuzz its methods."""
        prefix = f"c{class_idx + 1}"
        self.write_print_to_stderr(
            0, f'"[{prefix}] Attempting to instantiate class: {class_name_str}"'
        )

        instance_var_name = (
            f"instance_{prefix}_{class_name_str.lower().replace('.', '_')}"  # Unique name
        )

        num_constructor_args = class_arg_number(class_name_str, class_type)
        self.write(0, f"{instance_var_name} = None # Initialize instance variable")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(
            0, f"{instance_var_name} = callFunc('{prefix}_init', '{class_name_str}',"
        )  # prefix was from original _fuzz_one_class
        self._write_arguments_for_call_lines(num_constructor_args, 1)  # Indent args by 1
        self.write(0, "  )")  # Close callFunc
        if USE_MANGLE_FEATURE:  # Assuming USE_MANGLE_FEATURE is defined
            self.write(0, mangle_loop % num_constructor_args)  # Assuming mangle_loop defined
        self.restoreLevel(self.base_level - 1)  # Exit try's indentation (level 1)
        self.write(0, "except Exception as e_instantiate:")
        self.addLevel(1)  # Indent for except block contents
        self.write(0, f"{instance_var_name} = None")
        self.write_print_to_stderr(
            0,  # This 0 is relative to current base_level (which is parent's level + 1)
            f'"[{prefix}] Failed to instantiate {class_name_str}: {{e_instantiate.__class__.__name__}} {{e_instantiate}}"',
        )
        # instance_var_name remains None if already set, or if callFunc returned None
        # If callFunc might not set instance_var_name on error, set it explicitly:
        self.write(0, f"{instance_var_name} = None")
        self.restoreLevel(self.base_level - 1)  # Exit except's indentation
        self.emptyLine()

        if self.options.jit_fuzz:
            # --- JIT MODE: Fuzz one stateful object in a loop ---
            self.write_print_to_stderr(
                0, f'"[{prefix}] JIT MODE: Stateful fuzzing for class: {class_name_str}"'
            )

            self.write(
                0, f"if {instance_var_name} is not None and {instance_var_name} is not SENTINEL_VALUE:"
            )
            self.addLevel(1)
            self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
            self.addLevel(1)
            self.write(0, f"'INDENTED BLOCK'")


            # Get a list of methods once
            methods_dict = self._get_object_methods(class_type, class_name_str)
            if methods_dict:
                # Inside the loop, pick a random method and call it
                chosen_method_name = choice(list(methods_dict.keys()))
                chosen_method_obj = methods_dict[chosen_method_name]
                self._generate_and_write_call(  # This is the original call generator
                    prefix=f"{prefix}_{chosen_method_name}",
                    callable_name=chosen_method_name,
                    callable_obj=chosen_method_obj,
                    min_arg_count=0,
                    target_obj_expr=instance_var_name,
                    is_method_call=True,
                    generation_depth=0,
                )
            self.restoreLevel(self.base_level - 2)  # Exit both for loop and if
            # self.write(0, f"del {instance_var_name} # Cleanup instance")
            self.emptyLine()

        else: # self.h5py_writer and not self.h5py_writer.fuzz_one_h5py_class(
            # class_name_str, class_type, instance_var_name, prefix
        # ):
            # Now, dispatch fuzzing on the created instance_var_name
            self._dispatch_fuzz_on_instance(
                current_prefix=f"{prefix}_{class_name_str.lower()}_ops",  # e.g., "c0_file_ops", "c1_dataset_ops"
                target_obj_expr_str=instance_var_name,
                class_name_hint=class_name_str,
                generation_depth=0,
            )

        # Cleanup for the instance variable created in this scope (if it wasn't None already)
        # Note: _dispatch_fuzz_on_instance does not delete the object it's passed.
        # self.write(0, f"if '{instance_var_name}' in locals() and {instance_var_name} is not None:")
        # self.addLevel(1)
        # self.write(0, f"try: del {instance_var_name}")
        # self.write(0, f"except NameError: pass")  # Should not happen with check above but defensive
        # self.restoreLevel(self.base_level - 1)
        # self.write_print_to_stderr(0, f'"GC after _fuzz_one_class for {class_name_str}"')
        # self.write(0, "collect()")
        # self.emptyLine()

        # Common logic: if instance_var_name was successfully created, fuzz its methods
        # Inside _fuzz_one_class, after instance_var_name is potentially defined:
        self.write(
            0, f"if {instance_var_name} is not None and {instance_var_name} is not SENTINEL_VALUE:"
        )
        current_level = self.addLevel(1)
        # class_type is the type object of the class that was "instantiated"
        self._fuzz_methods_on_object_or_specific_types(
            current_prefix=f"{prefix}m",  # prefix from _fuzz_one_class context, e.g., "o1m", "c1m"
            target_obj_expr_str=instance_var_name,
            target_obj_class_name=class_name_str,  # Original class name string
            target_obj_actual_type_obj=class_type,  # The actual type object
            num_method_calls_to_make=self.options.methods_number,
        )
        # self.restoreLevel(self.base_level - 1)
        self.write(0, f"del {instance_var_name} # Cleanup instance")
        self.write_print_to_stderr(
            0, f'"[{prefix}] -explicit garbage collection for class instance-"'
        )
        self.write(0, "collect()")
        self.restoreLevel(current_level)
        self.emptyLine()

    MAX_FUZZ_GENERATION_DEPTH = 2  # Adjust as needed; 3-5 is usually a good start

    def _dispatch_fuzz_on_instance(
        self,
        current_prefix: str,
        target_obj_expr_str: str,
        class_name_hint: str,  # Can be a runtime type string like "type(obj).__name__"
        generation_depth: int,
    ):
        """Dispatches fuzzing operations for a given object instance."""
        if generation_depth > self.MAX_FUZZ_GENERATION_DEPTH:
            self.write(0, f"try:")
            self.write_print_to_stderr(
                1,
                f"f'Max fuzz code generation depth ({self.MAX_FUZZ_GENERATION_DEPTH}) reached for {{ {target_obj_expr_str}!r }}, not generating deeper fuzzing.'",
            )
            self.write(0, f"except Exception:")
            self.write_print_to_stderr(
                1,
                f"f'Max fuzz code generation depth ({self.MAX_FUZZ_GENERATION_DEPTH}) reached for {class_name_hint}, not generating deeper fuzzing.'",
            )

            return
        self.write(0, f"try:")
        self.write_print_to_stderr(
            1,
            f'f"--- (Depth {generation_depth}) Dispatching Fuzz for: {{ {target_obj_expr_str}!r }} (hint: {class_name_hint}, prefix: {current_prefix}) ---"',
        )
        self.write(0, f"except Exception as e:")
        self.write_print_to_stderr(
            1,
            f'f"--- (Depth {generation_depth}) Error calling repr() prefix: {current_prefix}) ---"',
        )
        self.write(0, f"# {self.base_level=}")
        self.write(0, f"if {target_obj_expr_str} is not None:")
        # ---- BLOCK: Main if target_obj_expr_str not None ----
        L_main_if_target_not_none = self.addLevel(1)
        self.write(0, f"# {self.base_level=}")
        self.write(0, f"# {L_main_if_target_not_none=}")
        try:
            self.write(0, f"if skip_trivial_type({target_obj_expr_str}):")
            skiplevel = self.addLevel(1)
            self.write_print_to_stderr(
                0,
                f"f'Skipping deep diving on {target_obj_expr_str} {{type({target_obj_expr_str})}}'",
            )
            self.restoreLevel(skiplevel)
            if self.h5py_writer:
                L_else_generic = self.h5py_writer._dispatch_fuzz_on_h5py_instance(
                    class_name_hint, current_prefix, generation_depth, target_obj_expr_str
                )
            try:
                self.write(0, f"try:")
                self.write_print_to_stderr(
                    1,
                    f"f'Instance {{ {target_obj_expr_str}!r }} (actual type {{type({target_obj_expr_str}).__name__}}) has no specific fuzzer type, doing generic calls.'",
                )
                self.write(0, f"except Exception as e:")
                self.write_print_to_stderr(
                    1,
                    f"f'Error printing instance repr() {{ e }} (actual type {{type({target_obj_expr_str}).__name__}}) has no specific fuzzer type, doing generic calls.'",
                )

                self._fuzz_generic_object_methods(
                    f"{current_prefix}_generic",
                    target_obj_expr_str,
                    # class_name_hint, # Not directly used by _fuzz_generic_object_methods as it uses dir()
                    self.options.methods_number,  # Generic number of calls
                )
            finally:
                if self.h5py_writer:
                    self.restoreLevel(L_else_generic)
        finally:
            self.restoreLevel(L_main_if_target_not_none)
        # ---- END BLOCK: Main if target_obj_expr_str not None ----

    def _fuzz_generic_object_methods(
        self, current_prefix: str, target_obj_expr_str: str, num_calls: int
    ):
        """
        Generates code for fuzzing methods of a generic object.
        (This is the generic part previously in _dispatch_fuzz_on_instance's else block)
        """
        # ... (Code from previous _dispatch_fuzz_on_instance's "else" block for generic method fuzzing)
        # ... (It gets methods using dir() and then calls _generate_and_write_call)
        # Important: If _generate_and_write_call itself captures results and calls
        # _dispatch_fuzz_on_instance, that's another way deep diving happens generically.
        # self.write_print_to_stderr(0, f"f'Generic method fuzzing for {{ {target_obj_expr_str}!r }} with prefix {current_prefix}'")
        # For brevity, this is a placeholder. Your actual generic fuzzing logic would go here.
        # This part usually involves:
        # 1. Getting a list of callable attributes (methods).
        # 2. Looping `num_calls` times.
        # 3. In each iteration, choosing a random method.
        # 4. Calling `self._generate_and_write_call` for that method.
        # The deep dive part comes if _generate_and_write_call is enhanced.
        self.write(0, f"if skip_trivial_type({target_obj_expr_str}):")
        skiplevel = self.addLevel(1)
        self.write_print_to_stderr(
            0, f"f'Skipping deep diving on {target_obj_expr_str} {{type({target_obj_expr_str})}}'"
        )
        self.restoreLevel(skiplevel)
        self.write(0, "else:")
        elselevel = self.addLevel(1)
        self.write_print_to_stderr(
            0,
            f"f'Instance {target_obj_expr_str} (type {{type({target_obj_expr_str}).__name__}}) has no specific fuzzer, doing generic calls.'",
        )
        # --- Generic Method Fuzzing Logic ---
        # This is where you'd put your existing loop that gets methods via dir() or _get_object_methods
        # and calls them randomly using _generate_and_write_call.
        # For this to work, you need the actual methods of the object.
        # This requires getting methods at runtime in the generated script or having class_type available
        # in WritePythonCode if the object's type is known at generation time.

        # Example of generic method fuzzing (conceptual, adapt from your existing code):
        self.write(0, f"{current_prefix}_methods = []")
        self.write(0, f"try:")
        self.addLevel(1)
        self.write(0, f"for {current_prefix}_attr_name in dir({target_obj_expr_str}):")
        self.addLevel(1)
        self.write(
            0, f"if {current_prefix}_attr_name.startswith('_'): continue"
        )  # Skip private/dunder for simplicity
        self.write(0, f"try:")  # Inner try for getattr
        self.addLevel(1)
        self.write(
            0,
            f"{current_prefix}_attr_val = getattr({target_obj_expr_str}, {current_prefix}_attr_name)",
        )
        self.write(
            0,
            f"if callable({current_prefix}_attr_val): {current_prefix}_methods.append(({current_prefix}_attr_name, {current_prefix}_attr_val))",
        )
        self.restoreLevel(self.base_level - 1)  # Exit inner try
        self.write(0, f"except Exception: pass")
        self.restoreLevel(self.base_level - 1)  # Exit for loop
        self.restoreLevel(self.base_level - 1)  # Exit outer try
        self.write(0, f"except Exception: {current_prefix}_methods = [] # Failed to get methods")

        self.write(0, f"if {current_prefix}_methods:")
        self.addLevel(1)
        self.write_print_to_stderr(
            0,
            f"f'Found {{len({current_prefix}_methods)}} callable methods for generic fuzzing of {target_obj_expr_str}'",
        )
        self.write(
            0,
            f"for _i_{current_prefix} in range(min(len({current_prefix}_methods), {self.options.methods_number})):",
        )  # Use configured num calls
        self.addLevel(1)
        self.write(
            0,
            f"{current_prefix}_method_name_to_call, {current_prefix}_method_obj_to_call = choice({current_prefix}_methods)",
        )
        # Now call _generate_and_write_call using {current_prefix}_method_name_to_call (string)
        # and {current_prefix}_method_obj_to_call (the callable).
        # _generate_and_write_call needs adaptation if method_obj is a runtime variable.
        # For simplicity here, let's assume _generate_and_write_call can take the method *name*
        # and the target object expression.
        self.write(0, f"# Conceptual call to generic method fuzzer")
        self.write(
            0,
            f"callMethod(f'{current_prefix}_gen{{_i_{current_prefix}}}', {target_obj_expr_str}, {current_prefix}_method_name_to_call)",
        )  # Example simplified call
        self.restoreLevel(self.base_level - 1)  # Exit for loop
        self.restoreLevel(self.base_level - 1)  # Exit if methods
        self.restoreLevel(elselevel)  # Exit else
        self.emptyLine()

    def _fuzz_methods_on_object_or_specific_types(
        self,
        current_prefix: str,  # e.g., "o1m", "c1_instm"
        target_obj_expr_str: str,  # e.g., "instance_c0_dataset", "h5py_tricky_objects.get('some_key')"
        target_obj_class_name: str,  # e.g., "Dataset", "File", "MyClass" (for logging/heuristics)
        target_obj_actual_type_obj: Any,  # The actual type object if available to WritePythonCode, else None
        num_method_calls_to_make: int,
    ):
        """Fuzzes methods of a given object, with special handling for specific types."""
        self.write_print_to_stderr(
            0,
            f'f"--- Fuzzing instance: {target_obj_expr_str} (type hint: {target_obj_class_name}, prefix: {current_prefix}) ---"',
        )

        self.write(0, f"if skip_trivial_type({target_obj_expr_str}):")
        skiplevel = self.addLevel(1)
        self.write_print_to_stderr(
            0, f"f'Skipping deep diving on {target_obj_expr_str} {{type({target_obj_expr_str})}}'"
        )
        self.restoreLevel(skiplevel)

        if self.h5py_writer:
            self.h5py_writer._fuzz_methods_on_h5py_object_or_specific_types(
                current_prefix, target_obj_expr_str
            )

        # else: # General method fuzzing for other types
        self.write(0, f"# General method fuzzing for {target_obj_expr_str}")
        methods_dict = {}
        if target_obj_actual_type_obj:  # If WritePythonCode has the type
            methods_dict = self._get_object_methods(
                target_obj_actual_type_obj, target_obj_class_name
            )
        else:  # Try to get methods at runtime in generated script (less ideal for setup)
            # self.write(0,
            #            f"try: runtime_methods_{current_prefix} = {{name: getattr({target_obj_expr_str}, name) for name in dir({target_obj_expr_str}) if callable(getattr({target_obj_expr_str}, name, None))}}")
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
                    chosen_method_obj = methods_dict[chosen_method_name]  # Actual method callable
                    self._generate_and_write_call(  # Your generic method call writer
                        prefix=f"{current_prefix}{m_idx + 1}",
                        callable_name=chosen_method_name,
                        callable_obj=chosen_method_obj,
                        min_arg_count=0,  # Heuristic for methods
                        target_obj_expr=target_obj_expr_str,
                        is_method_call=True,
                        generation_depth=0,
                    )
        self.write_print_to_stderr(
            0, f'f"--- Finished fuzzing instance: {target_obj_expr_str} ---"'
        )
        self.emptyLine()

    def _fuzz_one_module_object(self, obj_idx: int, obj_name_str: str, obj_instance: Any) -> None:
        """Generates code to fuzz methods of a given module-level object."""
        prefix = f"obj{obj_idx + 1}"
        obj_expr_in_script = f"fuzz_target_module.{obj_name_str}"

        self._fuzz_methods_on_object_or_specific_types(
            current_prefix=f"obj{obj_idx}m",  # Prefix for this object
            target_obj_expr_str=obj_expr_in_script,
            target_obj_class_name=obj_instance.__class__.__name__,  # Get class name from instance
            target_obj_actual_type_obj=type(obj_instance),  # Get type from instance
            num_method_calls_to_make=self.options.methods_number,
        )
        self.write_print_to_stderr(
            0, f'"[{prefix}] -explicit garbage collection for module object bindings-"'
        )
        self.write(0, "collect()")
        self.emptyLine()

    def _write_arguments_for_call_lines(self, num_args: int, base_indent_level: int) -> None:
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
                    arg_line_part + (last_char if arg_line_part == arg_lines[-1] else ""),
                )

    def _generate_and_write_call(
        self,
        prefix: str,
        callable_name: str,
        callable_obj: Callable[..., Any],
        min_arg_count: int,
        target_obj_expr: str,  # e.g., "fuzz_target_module" or "instance_var"
        is_method_call: bool,
        generation_depth: int,
        in_jit_loop: bool = False,
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
        if self.options.jit_fuzz and is_method_call and in_jit_loop:
            self.write(0, f"if res_{prefix} is SENTINEL_VALUE:")
            self.write_print_to_stderr(
                1,
                f"f'Method {callable_name} raised an exception, breaking JIT loop.'",
            )
            self.write(1, "break")
            self.emptyLine()
            return

        self.write(0, f"# Deep dive on result of {callable_name}")
        self.write(
            0,
            f"if 'res_{prefix}' in locals() and res_{prefix} is not None and res_{prefix} is not SENTINEL_VALUE:",
        )
        # We need to ensure SENTINEL_VALUE is defined if callMethod uses it.
        # Let's assume res_{prefix} is the actual return value.
        L_deep_dive_res = self.addLevel(1)
        try:
            self.write(0, f"{prefix}_res_type_name = type(res_{prefix}).__name__")
            self.write(0, f"try:")
            L_before_repr = self.addLevel(1)
            self.write_print_to_stderr(
                0,
                f"f'CALL_RESULT ({prefix}): Method {callable_name} returned {{res_{prefix}!r}} of type {{{prefix}_res_type_name}}. Attempting deep dive.'",
            )
            self.restoreLevel(L_before_repr)
            self.write(0, f"except Exception as e:")
            L_after_repr = self.addLevel(1)
            self.write_print_to_stderr(
                0,
                f"f'EXCEPTION printing CALL_RESULT: {{ e }}'",
            )
            self.restoreLevel(L_after_repr)
            self._dispatch_fuzz_on_instance(
                current_prefix=f"{prefix}_res_dive",
                target_obj_expr_str=f"res_{prefix}",  # The variable holding the result
                class_name_hint=f"{prefix}_res_type_name",  # Runtime type name
                generation_depth=generation_depth + 1,  # Incremented depth
            )
        finally:
            self.restoreLevel(L_deep_dive_res)

        if self.enable_threads or self.enable_async:
            self.write(0, "target_func = None")
            self.write(0, "try:")
            self.write(1, f"target_func = getattr({target_obj_expr}, '{callable_name}')")
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

            self.write(0, f"target_func({args_str_async})")
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

    def _generate_jit_pattern_block(self, prefix: str) -> None:
        """Generates a block of code with patterns designed to stress the JIT."""
        self.write_print_to_stderr(
            0, f'"[{prefix}] Generating JIT-optimized pattern block."'
        )

        # 1. Initialize some variables for the block to use
        self.write(0, f"var_int_a = {self.arg_generator.genInt()[0]}")
        self.write(0, f"var_int_b = {self.arg_generator.genSmallUint()[0]}")
        self.write(0, f'var_str_c = "fusil_jit_fuzzing_string"')
        self.write(0, f"var_list_d = [10, 20, 30, 40, 50]")
        self.write(0, f"var_tuple_e = (100, 200, 300)")
        self.write(0, f"temp_val = 0")
        self.emptyLine()

        # 2. Create the hot loop
        loop_iterations = self.options.jit_loop_iterations
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)

        # 3. Weave in the JIT-friendly patterns inside the loop
        # Math, Truth Tests, Subscripts, and Calls
        self.write(0, f"if i_{prefix} > var_int_b:")
        self.write(1, f"temp_val = var_int_a + i_{prefix}")
        self.write(1, f"char = var_str_c[i_{prefix} % len(var_str_c)]")

        # Containment check and Unpacking
        self.write(0, "if 20 in var_list_d:")
        self.write(1, f"x_{prefix}, y_{prefix} = (i_{prefix}, temp_val)")

        # Attribute loading on a common object
        self.write(0, f"var_list_d.append(i_{prefix})")

        self.restoreLevel(self.base_level - 1)
        self.emptyLine()

    def _generate_polymorphic_call_block(self, prefix: str) -> None:
        """Generates a hot loop with calls to one function using args of different types."""
        if not self.module_functions:
            return

        func_name = choice(self.module_functions)
        self.write_print_to_stderr(
            0, f'"[{prefix}] Generating polymorphic call block for: {func_name}"'
        )

        # Select a few argument generators to cycle through
        poly_gens = [
            self.arg_generator.genInt,
            self.arg_generator.genString,
            self.arg_generator.genList,
            self.arg_generator.genBytes,
            self.arg_generator.genBool,
            self.arg_generator.genFloat,
        ]

        # Get N diverse generators
        num_types = self.options.jit_polymorphic_degree
        gens_to_use = [choice(poly_gens) for _ in range(num_types)]

        # Write the hot loop
        loop_iterations = self.options.jit_loop_iterations // num_types
        self.write(0, f"for _ in range({loop_iterations}):")
        self.addLevel(1)
        self.write(0, f"'INDENTED BLOCK'")


        # Inside the loop, call the same function with different typed args
        for gen_func in gens_to_use:
            arg_str = " ".join(gen_func())
            self.write(0, f"callFunc('{prefix}', '{func_name}', {arg_str})")

        self.restoreLevel(self.base_level - 1)
        self.emptyLine()

    def _generate_phase1_warmup(self, prefix: str) -> dict | None:
        if not self.module_classes:
            return None

        class_name = choice(self.module_classes)
        class_obj = getattr(self.module, class_name)
        methods = self._get_object_methods(class_obj, class_name)
        if not methods:
            return None

        method_name = choice(list(methods.keys()))
        method_obj = methods[method_name]
        instance_var = f"instance_{prefix}"

        self.write_print_to_stderr(0, f'"[{prefix}] PHASE 1: Warming up {class_name}.{method_name}"')

        # Generate instantiation code
        # (This reuses logic from your existing _fuzz_one_class)
        self.write(0, f"{instance_var} = callFunc('{prefix}_init', '{class_name}')")

        # Generate the hot loop
        self.write(0, f"if {instance_var} is not None and {instance_var} is not SENTINEL_VALUE:")
        self.addLevel(1)
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)

        # Generate the repeated call inside the loop
        self._generate_and_write_call(
            prefix=f"{prefix}_warmup",
            callable_name=method_name,
            callable_obj=method_obj,
            min_arg_count=0,
            target_obj_expr=instance_var,
            is_method_call=True,
            generation_depth=0,
            in_jit_loop=True,
        )

        self.restoreLevel(self.base_level - 2)  # Exit loop and if

        # Store context for the next phases
        target_info = {
            'type': 'method_call',
            'class_name': class_name,
            'instance_var': instance_var,
            'method_name': method_name,
        }
        self.jit_warmed_targets.append(target_info)
        return target_info

    def _generate_phase2_invalidate(self, prefix: str, target_info: dict) -> None:
        self.write_print_to_stderr(0, f'"[{prefix}] PHASE 2: Invalidating dependency for {target_info["class_name"]}"')

        class_name = target_info['class_name']
        method_name = target_info['method_name']

        # Invalidate by replacing the method on the class with a lambda
        # This is inspired by test_guard_type_version_executor_invalidated from test_opt.py
        self.write(0, "# Maliciously replacing the method on the class to invalidate JIT cache")
        self.write(0, "try:")
        self.write(1,
                   f"setattr({self.module_name}.{class_name}, '{method_name}', lambda *a, **kw: 'invalidation payload')")
        self.write(1, "collect() # Encourage cleanup")
        self.write(0, "except Exception as e:")
        self.write_print_to_stderr(1, f'f"[{prefix}] PHASE 2: Exception invalidating {target_info["class_name"]}: {{ e }}"')


        self.emptyLine()

    def _generate_phase3_reexecute(self, prefix: str, target_info: dict) -> None:
        self.write_print_to_stderr(0,
                                   f'"[{prefix}] PHASE 3: Re-executing {target_info["method_name"]} to check for crash"')

        instance_var = target_info['instance_var']
        method_name = target_info['method_name']

        self.write(0, f"if {instance_var} is not None and {instance_var} is not SENTINEL_VALUE:")
        self.addLevel(1)
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        self.write(0, "try:")
        self.addLevel(1)

        # Re-execute the original call. We don't need the full _generate_and_write_call,
        # just a simple call to the now-potentially-broken method.
        self.write(0, f"getattr({instance_var}, '{method_name}')()")

        self.restoreLevel(self.base_level - 1)
        self.write(0, "except Exception as e:")
        self.addLevel(1)
        # Log expected exceptions, a crash is the real prize.
        self.write_print_to_stderr(0, f'"[{prefix}] Caught expected exception: {{e.__class__.__name__}}"')
        self.write(0, "break")


        self.restoreLevel(self.base_level - 3)  # Exit try, loop, and if
        self.emptyLine()

    def _generate_invalidation_scenario(self, prefix: str) -> None:
        """
        Orchestrates the generation of a three-phase JIT invalidation scenario.

        This method calls helper methods to generate code for each phase:
        1. Warm-up: JIT-compile a target method.
        2. Invalidate: Change a dependency of the compiled code.
        3. Re-execute: Call the target method again to check for crashes.
        """
        self.write(0, f"# --- JIT Invalidation Scenario: {prefix} ---")
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting JIT Invalidation Scenario <<<"'
        )
        self.emptyLine()

        # --- Phase 1: Warm-up and JIT Compilation ---
        # This call generates the code to get a method JIT-compiled and returns
        # information about that target for the subsequent phases.
        target_info = self._generate_phase1_warmup(prefix)

        # --- Check if a suitable target was found ---
        if target_info:
            # If warmup was successful, proceed to the next phases.
            self.emptyLine()

            # --- Phase 2: Invalidate Dependency ---
            # This call uses the info from phase 1 to generate code that
            # maliciously alters a dependency of the JIT-compiled code.
            self._generate_phase2_invalidate(prefix, target_info)
            self.emptyLine()

            # --- Phase 3: Re-execute and Check for Crash ---
            # This call generates code to run the original target again. If the
            # JIT cache was not correctly invalidated, this is where a crash
            # or incorrect behavior would occur.
            self._generate_phase3_reexecute(prefix, target_info)

        else:
            # If no suitable target was found in Phase 1, log it and abort this scenario.
            self.write_print_to_stderr(
                0, f'"[{prefix}] Could not find a suitable target for an invalidation scenario. Skipping."'
            )

        self.emptyLine()
        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished JIT Invalidation Scenario >>>"'
        )
        self.write(0, f"# --- End Scenario: {prefix} ---")
        self.emptyLine()

    def _generate_deleter_scenario(self, prefix: str) -> None:
        """
        Generates a sophisticated scenario that uses a __del__ side effect
        to induce type confusion for local, instance, and class variables.
        The side effect is triggered only once, near the end of the hot loop.
        """
        self.write_print_to_stderr(0, f'"[{prefix}] >>> Starting Advanced __del__ Side Effect Scenario <<<"')

        # --- 1. SETUP OUTSIDE THE LOOP ---
        # Define unique names for all our variables using the prefix.
        target_var = f"target_{prefix}"
        fm_target_var = f"fm_{target_var}"
        dummy_class_name = f"Dummy_{prefix}"
        dummy_instance_name = f"dummy_instance_{prefix}"
        fm_dummy_class_attr = f"fm_{dummy_instance_name}_a"
        fm_dummy_instance_attr = f"fm_{dummy_instance_name}_b"
        loop_iterations = self.options.jit_loop_iterations

        # Create the local variable and its FrameModifier.
        self.write(0, f"# A. Create a local variable and its FrameModifier")
        self.write(0, f"{target_var} = 100")
        self.write(0, f"{fm_target_var} = FrameModifier('{target_var}', 'local-string')")
        self.emptyLine()

        # Create the class, instance, and their FrameModifiers.
        self.write(0, f"# B. Create a class with instance/class attributes and their FrameModifiers")
        self.write(0, f"class {dummy_class_name}:")
        self.write(1, "a = 200  # Class attribute")
        self.write(1, "def __init__(self):")
        self.write(2, "self.b = 300  # Instance attribute")
        self.write(0, f"{dummy_instance_name} = {dummy_class_name}()")
        # Note: The target strings now include the instance name, e.g., 'dummy_instance_f1.a'
        self.write(0, f"{fm_dummy_class_attr} = FrameModifier('{dummy_instance_name}.a', 'class-attr-string')")
        self.write(0, f"{fm_dummy_instance_attr} = FrameModifier('{dummy_instance_name}.b', 'instance-attr-string')")
        self.emptyLine()

        # --- 2. HOT LOOP ---
        self.write(0, f"for i_{prefix} in range({loop_iterations}):")
        self.addLevel(1)

        # --- 2A. WARM-UP PHASE (inside loop) ---
        self.write(0, f"# Use all variables to warm up the JIT with their initial types")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"x = {target_var} + i_{prefix}")
        self.write(0, f"y = {dummy_instance_name}.a + i_{prefix}")
        self.write(0, f"z = {dummy_instance_name}.b + i_{prefix}")
        self.restoreLevel(self.base_level - 1)
        self.write(0, "except TypeError: pass")
        self.emptyLine()

        # --- 2B. TRIGGER PHASE (inside loop) ---
        # Trigger the deletion on the penultimate iteration to ensure the loop
        # runs one more time with the corrupted state.
        self.write(0, f"# On the penultimate loop, delete the FrameModifiers to trigger __del__")
        self.write(0, f"if i_{prefix} == {loop_iterations - 2}:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] DELETING FRAME MODIFIERS..."')
        self.write(0, f"del {fm_target_var}")
        self.write(0, f"del {fm_dummy_class_attr}")
        self.write(0, f"del {fm_dummy_instance_attr}")
        self.write(0, "collect()")
        self.restoreLevel(self.base_level - 1)
        self.emptyLine()

        # --- 2C. RE-EXECUTE PHASE (inside loop) ---
        self.write(0, f"# Use the variables again, which may hit a corrupted JIT state after deletion")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"res_local = {target_var} + i_{prefix}")
        self.write(0, f"res_cls_attr = {dummy_instance_name}.a + i_{prefix}")
        self.write(0, f"res_inst_attr = {dummy_instance_name}.b + i_{prefix}")
        self.restoreLevel(self.base_level - 1)
        self.write(0, "except TypeError as e:")
        self.write(1, "pass # This TypeError is expected if the side effect worked")
        self.restoreLevel(self.base_level - 1)  # Exit for loop

        self.write_print_to_stderr(0, f'"[{prefix}] <<< Finished Advanced __del__ Side Effect Scenario >>>"')
        self.emptyLine()

    def _generate_many_vars_scenario(self, prefix: str) -> None:
        """
        Generates a function with >256 local variables to stress the JIT's
        bytecode parser, specifically its handling of the EXTENDED_ARG opcode.
        """
        func_name = f"many_vars_func_{prefix}"
        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Many Vars" Resource Limit Scenario <<<"""')
        self.write(0, f"# Define a function with an unusually large number of local variables.")
        self.write(0, f"def {func_name}():")
        self.addLevel(1)

        # 1. Generate over 256 local variable assignments.
        num_vars = 260  # A value safely over the 256 threshold
        for i in range(num_vars):
            self.write(0, f"var_{i} = {i}")

        # 2. Add a hot loop that uses some of these variables to make the function
        #    a candidate for JIT compilation.
        self.write(0, f"# Hot loop to trigger JIT compilation of this large function.")
        self.write(0, "total = 0")
        self.write(0, f"for i in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        # Use the first, middle, and last variables to ensure they aren't optimized away.
        self.write(0, f"total += var_0 + var_{num_vars // 2} + var_{num_vars - 1}")
        self.restoreLevel(self.base_level - 1)  # Exit for loop
        self.write(0, "return total")
        self.restoreLevel(self.base_level - 1)  # Exit def
        self.emptyLine()

        # 3. Call the newly defined function.
        self.write(0, f"# Execute the function with many variables.")
        self.write(0, f"{func_name}()")
        self.write_print_to_stderr(0, f'"""[{prefix}] <<< Finished "Many Vars" Scenario >>>"""')
        self.emptyLine()

    def _generate_deep_calls_scenario(self, prefix: str) -> None:
        """
        Generates a deep chain of function calls to stress the JIT's
        stack analysis and trace stack limits.
        """
        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Deep Calls" Resource Limit Scenario <<<"""')

        # 1. Define the base case for the call chain.
        depth = 20  # A reasonably deep call chain
        self.write(0, f"# Define a deep chain of {depth} nested function calls.")
        self.write(0, f"def f_0_{prefix}(): return 1")

        # 2. Generate the chain of functions, each calling the previous one.
        for i in range(1, depth):
            self.write(0, f"def f_{i}_{prefix}(): return 1 + f_{i - 1}_{prefix}()")

        top_level_func = f"f_{depth - 1}_{prefix}"
        self.emptyLine()

        # 3. Call the top-level function inside a hot loop to trigger the JIT.
        #    Wrap it in a try...except RecursionError since this is a possible outcome.
        self.write(0, f"# Execute the top-level function of the chain in a hot loop.")
        self.write(0, f"for _ in range({self.options.jit_loop_iterations}):")
        self.addLevel(1)
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"{top_level_func}()")
        self.restoreLevel(self.base_level - 1)
        self.write(0, "except RecursionError:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[{prefix}] Caught expected RecursionError."')
        self.write(0, "break # Exit loop if recursion limit is hit")
        self.restoreLevel(self.base_level - 2)  # Exit except and for loop

        self.write_print_to_stderr(0, f'"""[{prefix}] <<< Finished "Deep Calls" Scenario >>>"""')
        self.emptyLine()

    def _define_frame_modifier_instances(self, prefix: str, targets_and_payloads: dict) -> list[str]:
        """
        Generates the 'fm_... = FrameModifier(...)' lines for a set of targets.

        Args:
            prefix: The unique prefix for this scenario.
            targets_and_payloads: A dictionary mapping target variable paths
                                  (e.g., 'var_250') to their malicious payload.

        Returns:
            A list of the variable names created for the FrameModifier instances.
        """
        fm_vars = []
        self.write(0, "# Define FrameModifier instances to arm the __del__ side effects.")
        for i, (target_path, payload) in enumerate(targets_and_payloads.items()):
            fm_var_name = f"fm_{prefix}_{i}"
            self.write(0, f"{fm_var_name} = FrameModifier('{target_path}', {payload})")
            fm_vars.append(fm_var_name)
        self.emptyLine()
        return fm_vars

    def _generate_del_trigger(self, loop_var: str, loop_iterations: int, fm_vars_to_del: list[str]) -> None:
        """
        Generates the 'if ...: del ...' block to trigger the __del__ methods
        on the penultimate iteration of a loop.
        """
        self.write(0, f"# Trigger the __del__ side effect on the penultimate iteration.")
        self.write(0, f"if {loop_var} == {loop_iterations - 2}:")
        self.addLevel(1)
        self.write_print_to_stderr(0, f'"[+] Deleting FrameModifiers to trigger side effects..."')
        for fm_var in fm_vars_to_del:
            self.write(0, f"del {fm_var}")
        self.write(0, "collect()")
        self.restoreLevel(self.base_level - 1)

    def _generate_mixed_many_vars_scenario(self, prefix: str) -> None:
        """
        MIXED SCENARIO 1: Combines "Many Vars", `__del__` side effects, and
        JIT-friendly math/logic patterns into one hostile function.
        """
        func_name = f"mixed_many_vars_func_{prefix}"
        loop_var = f"i_{prefix}"
        num_vars = 260
        loop_iterations = self.options.jit_loop_iterations

        self.write_print_to_stderr(0, f'"""[{prefix}] >>> Starting "Mixed Many Vars" Hostile Scenario <<<"""')
        self.write(0, f"def {func_name}():")
        self.addLevel(1)

        # 1. Define 260+ local variables to stress EXTENDED_ARG.
        self.write(0, f"# Define {num_vars} local variables.")
        for i in range(num_vars):
            self.write(0, f"var_{i} = {i}")
        self.emptyLine()

        # 2. Arm the __del__ side effect using our new helper.
        #    We will target a high-index variable that is used in the hot loop.
        target_variable_path = f'var_{num_vars - 1}'
        fm_vars = self._define_frame_modifier_instances(
            prefix, {target_variable_path: "'corrupted-by-del'"}
        )

        # 3. Add a hot loop.
        self.write(0, f"for {loop_var} in range({loop_iterations}):")
        self.addLevel(1)

        # 4. Inside the loop, generate JIT-friendly patterns that use the variables.
        self.write(0, "# Use variables in JIT-friendly patterns.")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, f"res = var_0 + {loop_var}")
        self.write(0, f"res += var_{num_vars - 1} # This is the variable we will corrupt.")
        self.restoreLevel(self.base_level - 1)
        self.write(0, "except TypeError: pass")
        self.emptyLine()

        # 5. Inside the loop, plant the time bomb using our new helper.
        self._generate_del_trigger(loop_var, loop_iterations, fm_vars)

        self.restoreLevel(self.base_level - 1)  # Exit for loop
        self.restoreLevel(self.base_level - 1)  # Exit def
        self.emptyLine()

        # 6. Call the master function we just created.
        self.write(0, f"# Execute the composed hostile function.")
        self.write(0, f"{func_name}()")
        self.write_print_to_stderr(0, f'"""[{prefix}] <<< Finished "Mixed Many Vars" Scenario >>>"""')
        self.emptyLine()

    def _generate_del_invalidation_scenario(self, prefix: str) -> None:
        """
        MIXED SCENARIO 2: An invalidation scenario where the invalidation
        is performed indirectly via a __del__ side effect.
        """
        self.write_print_to_stderr(
            0, f'"[{prefix}] >>> Starting __del__ Invalidation Scenario <<<"'
        )
        self.emptyLine()

        # --- Phase 1: Warm-up ---
        target_info = self._generate_phase1_warmup(prefix)

        if not target_info:
            self.write_print_to_stderr(
                0, f'"[{prefix}] Could not find a suitable target. Aborting scenario."'
            )
            self.emptyLine()
            return

        self.emptyLine()

        # --- Phase 2: Invalidate via __del__ ---
        self.write_print_to_stderr(
            0, f'"[{prefix}] PHASE 2: Arming FrameModifier to invalidate via __del__."'
        )

        # The target path is the method on the class, e.g., 'MyTargetClass.target_method'
        target_path = f'{self.module_name}.{target_info["class_name"]}.{target_info["method_name"]}'

        fm_vars = self._define_frame_modifier_instances(
            prefix, {target_path: "lambda *a, **kw: 'invalidated by __del__'"}
        )

        # Immediately delete the instance to trigger the __del__ method.
        self.write(0, "# Immediately delete the FrameModifier to trigger the side effect.")
        for fm_var in fm_vars:
            self.write(0, f"del {fm_var}")
        self.write(0, "collect()")
        self.emptyLine()

        # --- Phase 3: Re-execute ---
        self._generate_phase3_reexecute(prefix, target_info)

        self.write_print_to_stderr(
            0, f'"[{prefix}] <<< Finished __del__ Invalidation Scenario >>>"'
        )
        self.emptyLine()

    def _write_concurrency_finalization(self) -> None:
        """Writes code to start/join threads and run asyncio tasks."""
        if self.enable_threads:
            self.write_print_to_stderr(0, '"--- Starting and Joining Fuzzer Threads ---"')
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
            self.write(
                1,
                "print(f'Exception in async runner: {e_async_runner_run.__class__.__name__} {e_async_runner_run}')",
            )
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
            f"--- Fuzzing script generation for {self.module_name} complete ---"
        )
        self.close()
