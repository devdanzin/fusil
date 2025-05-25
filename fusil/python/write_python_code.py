from __future__ import annotations

import builtins
import inspect
import random
import time
from random import choice, randint
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
CALL_REPETITION_COUNT_CONST = 65
ERRBACK_NAME_CONST = "errback"
EXCEPTION_NAMES = {
    cls.__name__
    for cls in builtins.__dict__.values()
    if isinstance(cls, type) and issubclass(cls, Exception)
}


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
        self.write(0, "def callMethod(prefix, obj_to_call, method_name, *arguments):")
        current_level = self.addLevel(1)
        self.write(
            0,
            f'func_display_name = f"{self.module_name}.{{method_name}}()" if obj_to_call is {self.module_name} else f"{{obj_to_call.__class__.__name__}}.{{method_name}}()"',
        )
        self.write(0, 'message = f"[{prefix}] {func_display_name}"')
        self.write(0, "SENTINEL_VALUE = object()")
        self.write_print_to_stderr(0, "message")
        self.write(0, "result = SENTINEL_VALUE")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(0, "func_to_run = getattr(obj_to_call, method_name)")
        self.write(0, f"for _ in range({CALL_REPETITION_COUNT_CONST}):")
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
        instance_var_name = f"instance_{prefix}"
        self.write_print_to_stderr(
            0, f'"[{prefix}] Attempting to instantiate class: {class_name_str}"'
        )

        num_constructor_args = class_arg_number(class_name_str, class_type)

        self.write(0, f"{instance_var_name} = None # Initialize instance variable")
        self.write(0, "try:")
        self.addLevel(1)
        self.write(
            0, f"{instance_var_name} = callFunc('{prefix}_init', '{class_name_str}',"
        )
        self._write_arguments_for_call_lines(num_constructor_args, 1)
        self.write(0, ")")
        if USE_MANGLE_FEATURE:
            self.write(0, mangle_loop % num_constructor_args)
        self.restoreLevel(self.base_level - 1)  # Exit try
        self.write(0, "except Exception as e_instantiate:")
        self.write_print_to_stderr(
            1,
            f'"[{prefix}] Failed to instantiate {class_name_str}: {{e_instantiate.__class__.__name__}}"',
        )
        self.emptyLine()

        self.write(0, f"if {instance_var_name} is not None:")
        current_level = self.addLevel(1)
        methods = self._get_object_methods(class_type, class_name_str)

        if methods:
            self.write_print_to_stderr(
                0,
                f'"[{prefix}] Fuzzing {len(methods)} methods on instance of {class_name_str}"',
            )
            for m_idx in range(self.options.methods_number):
                method_name = choice(list(methods.keys()))
                method_obj = methods[method_name]

                self._generate_and_write_call(
                    prefix=f"{prefix}m{m_idx + 1}",
                    callable_name=method_name,
                    callable_obj=method_obj,
                    min_arg_count=0,
                    target_obj_expr=instance_var_name,
                    is_method_call=True,
                )
        self.write(0, f"del {instance_var_name} # Cleanup instance")
        self.write_print_to_stderr(
            0, f'"[{prefix}] -explicit garbage collection for class instance-"'
        )
        self.write(0, "collect()")
        self.restoreLevel(current_level)
        self.emptyLine()

    def _fuzz_one_module_object(
        self, obj_idx: int, obj_name_str: str, obj_instance: Any
    ) -> None:
        """Generates code to fuzz methods of a given module-level object."""
        prefix = f"obj{obj_idx + 1}"
        obj_expr_in_script = f"fuzz_target_module.{obj_name_str}"

        self.write_print_to_stderr(
            0,
            f'"[{prefix}] Fuzzing methods on module object: {obj_name_str} ({type(obj_instance).__name__})"',
        )

        methods = self._get_object_methods(obj_instance, obj_name_str)
        if methods:
            self.write_print_to_stderr(
                0, f'"[{prefix}] Found {len(methods)} methods for {obj_name_str}"'
            )
            for m_idx in range(self.options.methods_number):
                method_name = choice(list(methods.keys()))
                method_obj = methods[method_name]

                self._generate_and_write_call(
                    prefix=f"{prefix}m{m_idx + 1}",
                    callable_name=method_name,
                    callable_obj=method_obj,
                    min_arg_count=0,
                    target_obj_expr=obj_expr_in_script,
                    is_method_call=True,
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
            self.write(
                0, f"target_func = getattr({target_obj_expr}, '{callable_name}')"
            )
        self.emptyLine()

        if self.enable_threads:
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
            self.emptyLine()

        if self.enable_async:
            async_func_name = f"async_call_{prefix}_{callable_name}"
            self.write(0, f"def {async_func_name}():")
            self.addLevel(1)
            self.write_print_to_stderr(0, f'"Starting async task: {async_func_name}"')
            self.write(0, f"time.sleep({random.random() / 1000:.6f}) # Small delay")
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
            f'"--- Fuzzing script generation for {self.module_name} complete ---"'
        )
        self.close()
