from __future__ import annotations

import builtins
import inspect
import logging
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
from fusil.write_code import WriteCode

if TYPE_CHECKING:
    from fusil.python.python_source import PythonSource

# Module logger for the optional-feature detection below. These run at import time (before
# the ApplicationLogger configures the root logger), so they no longer print unconditionally
# to stdout (which the crash detector scrapes); they surface in fusil.log / under -v instead.
logger = logging.getLogger(__name__)

try:
    from fusil.python.template_strings import TEMPLATES  # noqa: F401  (availability probe)

    logger.info("Template strings available.")
    _ARG_GEN_USE_TEMPLATES = True
except ImportError:
    logger.info("Template strings not available.")
    _ARG_GEN_USE_TEMPLATES = False

try:
    import numpy  # type: ignore

    logger.info("Numpy %s is available, using it to build tricky arrays.", numpy.__version__)
    _ARG_GEN_USE_NUMPY = True
except ImportError:
    logger.info("Numpy is not available.")
    _ARG_GEN_USE_NUMPY = False

time_start = time.time()
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
        plugin_manager=None,
    ):
        """Initialize the Python code writer."""
        super().__init__()  # Initialize base WriteCode
        self.parent_python_source = parent_python_source
        self.plugin_manager = plugin_manager
        self.options = parent_python_source.options
        self.filenames = parent_python_source.filenames
        self.module = module
        self.module_name = module_name
        self.enable_threads = threads
        self.enable_async = _async
        self.generated_filename = filename

        self.arg_generator = ArgumentGenerator(
            self.options,
            self.filenames,
            _ARG_GEN_USE_NUMPY,
            _ARG_GEN_USE_TEMPLATES,
            allow_external_references=self.options.external_references,
            plugin_manager=self.plugin_manager,
        )

        self.module_functions: list[str]
        self.module_classes: list[str]
        self.module_objects: list[str]
        self.module_functions, self.module_classes, self.module_objects = self._get_module_members()

        if not self.module_functions and not self.module_classes and not self.module_objects:
            raise PythonFuzzerError(
                f"Module {self.module_name} has no function, no class, and no object to fuzz!"
            )

    def write_print_to_stderr(
        self, level: int, arguments_str: str, return_str: bool = False
    ) -> str:
        """
        Writes a print statement to stderr and now also returns the
        statement as a string.
        """
        code = f"print({arguments_str}, file=stderr)"
        if return_str:
            return code
        else:
            self.write(level, code)
        return ""

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
            except (AttributeError, Exception) as e:
                self.parent_python_source.warning(
                    f"Could not getattr {name} from {self.module_name}: {e}"
                )
                continue

            pm = self.plugin_manager
            if isinstance(attr, (FunctionType, BuiltinFunctionType)):
                if pm and pm.is_blacklisted("function", name):
                    continue
                functions.append(name)
            elif isinstance(attr, type) or inspect.isclass(attr):
                if (
                    not self.options.fuzz_exceptions
                    and isinstance(attr, type)
                    and issubclass(attr, BaseException)
                    # and attr.__name__ in _EXCEPTION_NAMES
                ):
                    continue
                if pm and pm.is_blacklisted("class", name):
                    continue
                classes.append(name)
            else:
                if isinstance(attr, ModuleType) or type(attr) in TRIVIAL_TYPES:
                    continue
                if (
                    not self.options.fuzz_exceptions and isinstance(attr, BaseException)
                    # and attr.__class__.__name__ in _EXCEPTION_NAMES
                ):
                    continue
                if pm and pm.is_blacklisted("object", name):
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

        pm = self.plugin_manager
        for name in dir(obj_instance_or_class):
            if name in blacklist:
                continue
            if pm and pm.is_blacklisted("method", name):
                continue
            if (
                (not self.options.test_private)
                and name.startswith("_")
                # a plugin may whitelist a normally-skipped method (e.g. '__del__')
                and not (pm and pm.is_whitelisted("method", name))
                # and not name.endswith("__")
            ):
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
                f"""\
                # FUSIL_BOILERPLATE_START

                from gc import collect
                from random import choice, randint, random, sample, seed
                from sys import stderr, path as sys_path
                from os.path import dirname
                import ast
                import inspect
                import io
                import math
                import operator
                import time
                import sys
                from threading import Thread
                from unittest.mock import MagicMock
                import asyncio
                seed({randint(0, 2**30)})
                """
            ),
        )
        if not self.options.no_tstrings and _ARG_GEN_USE_TEMPLATES:
            self.write(0, "from string.templatelib import Interpolation, Template")

        self.write_print_to_stderr(0, f'"Importing target module: {self.module_name}"')
        # The parent discovers importable modules in ITS interpreter; the target interpreter
        # may not have them (e.g. pexpect/ptyprocess are importable in the parent env but absent
        # in the target build). A missing target module is an environment mismatch, not a crash,
        # so exit cleanly (0) -- otherwise the bare import raises ModuleNotFoundError, the script
        # dies with a non-zero code, and --exitcode-score scores it as a spurious finding.
        self.write(0, "try:")
        with self.indented():
            self.write(0, f"import {self.module_name}")
        self.write(0, "except ImportError as _fusil_import_error:")
        with self.indented():
            self.write_print_to_stderr(
                0,
                f'"FUSIL: target module {self.module_name} not importable (skipping):",'
                " repr(_fusil_import_error)",
            )
            self.write(0, "raise SystemExit(0)")
        self.emptyLine()

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

        if self.options.oom_fuzz and self.options.oom_foreign:
            # Foreign-allocator OOM: arm the LD_PRELOAD malloc shim (via ctypes) instead of
            # _testcapi.set_nomemory. `fusil_malloc_arm(start, stop)` is a drop-in for
            # set_nomemory, so oom_call/oom_run below use `_set_nomemory` unchanged. The shim
            # is static LD_PRELOAD interposition -- no allocator swap -- so the one-time
            # install dance the _testcapi path needs does not apply here.
            self.write_block(
                0,
                """
                import faulthandler
                faulthandler.enable()
                import ctypes
                try:
                    _set_nomemory = ctypes.CDLL(None).fusil_malloc_arm
                    _set_nomemory.argtypes = (ctypes.c_long, ctypes.c_long)
                    _OOM_AVAILABLE = True
                except (OSError, AttributeError):
                    _OOM_AVAILABLE = False
                    print("--oom-foreign requested but fusil_malloc_shim not preloaded (LD_PRELOAD); running without injection", file=stderr)
                _OOM_DISABLE = 2_000_000_000
                if _OOM_AVAILABLE:
                    _set_nomemory(_OOM_DISABLE, 0)
            """,
            )
            self.emptyLine()
        elif self.options.oom_fuzz:
            self.write_block(
                0,
                """
                import faulthandler
                faulthandler.enable()
                try:
                    from _testcapi import set_nomemory as _set_nomemory
                    _OOM_AVAILABLE = True
                except ImportError:
                    _OOM_AVAILABLE = False
                    print("OOM mode requested but _testcapi.set_nomemory unavailable; running without injection", file=stderr)
                # set_nomemory()/remove_mem_hooks() install/restore the allocation-failure hook by
                # swapping the process-global allocator via PyMem_SetAllocator(), which is NOT
                # thread-safe. Performing that swap inside the per-call/per-sequence OOM loops races
                # any worker threads the fuzzed code spawned and corrupts the heap -- false-positive
                # "crashes" (mimalloc asserts, _PyMem_DebugRawFree bad-ID, segvs). So install the hook
                # EXACTLY ONCE here, before any fuzzed code runs, in a disarmed state, and thereafter
                # only re-arm/disarm the failure WINDOW with set_nomemory() (which never swaps the
                # allocator). _OOM_DISABLE is a start count no real run reaches, so every allocation
                # passes through (injection effectively off).
                _OOM_DISABLE = 2_000_000_000
                if _OOM_AVAILABLE:
                    _set_nomemory(_OOM_DISABLE, 0)
            """,
            )
            self.emptyLine()

        if self.options.gc_aggressive:
            # gc.set_threshold(1, 1, 1) forces a gen-0 collection on ~every tracked allocation,
            # turning rare "GC fires while an object is tracked but half-initialised"
            # races (tp_traverse reading a NULL field) into deterministic crashes. A cheap
            # global coercion like the OOM hook; composes with the bombs + class fuzzing.
            self.write_block(
                0,
                """
                import gc
                gc.set_threshold(1, 1, 1)
                """,
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
        self.write(0, fusil.python.tricky_weird.bomb_objects)
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

        self.write(0, "# Define a custom exception to distinguish our check from others.")
        self.write(0, "class JITCorrectnessError(AssertionError): pass")
        self.emptyLine()

        # Add plugin-provided definitions
        if self.plugin_manager:
            plugin_defs = self.plugin_manager.get_definitions(self.options, self.module_name)
            for definition_code in plugin_defs:
                self.write(0, "# --- Plugin-provided definitions ---")
                self.write(0, definition_code)
                self.emptyLine()

    def _write_helper_call_functions(self) -> None:
        """Writes helper functions for calling code, comparing results, etc."""
        # Fixed-shape helper: emit it as one block rather than line-by-line self.write calls.
        self.write_block(
            0,
            """
            # Helper for correctness testing that handles NaN, lambdas, and complex numbers.
            import math
            import types
            def compare_results(a, b):
                if isinstance(a, types.FunctionType) and a.__name__ == '<lambda>' and \\
                   isinstance(b, types.FunctionType) and b.__name__ == '<lambda>':
                    return True # Treat two lambdas as equal for our purposes
                if isinstance(a, complex) and isinstance(b, complex):
                    a_real_nan = math.isnan(a.real)
                    b_real_nan = math.isnan(b.real)
                    a_imag_nan = math.isnan(a.imag)
                    b_imag_nan = math.isnan(b.imag)
                    real_match = (a.real == b.real) or (a_real_nan and b_real_nan)
                    imag_match = (a.imag == b.imag) or (a_imag_nan and b_imag_nan)
                    return real_match and imag_match
                if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
                    return True
                if isinstance(a, object) and isinstance(b, object):
                    return True
                if isinstance(a, tuple) and isinstance(b, tuple) and len(a) == len(b):
                    return all(compare_results(x, y) for x, y in zip(a, b))
                return a == b
            """,
        )
        self.emptyLine()

        self.write(0, "SENTINEL_VALUE = object()")
        self.emptyLine()
        self.write(0, "def callMethod(prefix, obj_to_call, method_name, *arguments, verbose=True):")
        with self.indented():
            self.write(
                0,
                f'func_display_name = f"{self.module_name}.{{method_name}}()" if obj_to_call is {self.module_name} else f"{{obj_to_call.__class__.__name__}}.{{method_name}}()"',
            )
            self.write(0, 'message = f"[{prefix}] {func_display_name}"')
            self.write(0, "if verbose:")
            self.write_print_to_stderr(1, "message")
            self.write(0, "result = SENTINEL_VALUE")
            self.write(0, "try:")
            with self.indented():
                self.write(0, "func_to_run = getattr(obj_to_call, method_name)")
                self.write(0, f"for _ in range(int({CALL_REPETITION_COUNT_CONST})):")
                self.write(1, "result = func_to_run(*arguments)")
            self.write(0, "except (Exception, SystemExit, KeyboardInterrupt) as err:")
            with self.indented():
                self.write(0, "try:")
                self.write(1, "errmsg = repr(err)")
                self.write(0, "except Exception as e_repr:")
                self.write(1, "errmsg = f'Error during repr: {e_repr.__class__.__name__}'")
                self.write(0, "errmsg = errmsg.encode('ASCII', 'replace').decode('ASCII')")
                self.write(0, "if verbose:")
                self.write_print_to_stderr(
                    1,
                    'f"[{prefix}] {func_display_name} => EXCEPTION: {err.__class__.__name__}: {errmsg}"',
                )
                self.write(0, "result = SENTINEL_VALUE")

            self.write(0, "if verbose:")
            self.write_print_to_stderr(1, 'f"[{prefix}] -explicit garbage collection-"')
            self.write(0, "collect()")

            if self.enable_threads:
                self.write(0, "if result is not SENTINEL_VALUE:")
                self.write(
                    1,
                    "fuzzer_threads_alive.append(Thread(target=func_to_run, args=arguments, name=message))",
                )
            self.write(0, "return result")
        self.emptyLine()

        self.write(0, "def callFunc(prefix, func_name_str, *arguments, verbose=True):")
        self.write(
            1,
            f"return callMethod(prefix, {self.module_name}, func_name_str, *arguments, verbose=verbose)",
        )
        self.emptyLine()

        if self.options.oom_fuzz:
            self.write_block(
                0,
                f"""
                _OOM_MAX_START = {self.options.oom_max_start}
                _OOM_VERBOSE = {bool(self.options.oom_verbose)}

                def oom_call(label, func, *args, **kwargs):
                    # Dense OOM sweep: fail every allocation from #_start onward, one
                    # _start per iteration. The per-call marker (printed once, before the
                    # sweep) identifies which invocation was running if a crash follows --
                    # more reliable than the faulthandler frame, which is often an
                    # incidental allocation rather than the fuzzed target. MemoryError is
                    # the expected outcome and is swallowed silently; SystemError is
                    # surfaced (PyCFunction contract violations); a real crash
                    # (segfault/abort) terminates the process, the signal fusil scores.
                    # The inner finally DISARMS injection (set_nomemory with an unreachable start)
                    # so the except clauses allocate freely, WITHOUT swapping the allocator -- the
                    # swap is not thread-safe and would corrupt the heap if the fuzzed call left
                    # worker threads running (see the one-time install note above).
                    if not _OOM_AVAILABLE or func is None:
                        return
                    print("[OOM] " + label, file=stderr)
                    for _start in range(_OOM_MAX_START):
                        if _OOM_VERBOSE:
                            print("[OOM]   start=" + str(_start), file=stderr)
                        _set_nomemory(_start, 0)
                        try:
                            try:
                                func(*args, **kwargs)
                            finally:
                                _set_nomemory(_OOM_DISABLE, 0)
                        except MemoryError:
                            pass
                        except SystemError:
                            print("[OOM] SystemError in " + label, file=stderr)
                        except BaseException:
                            pass
            """,
            )
            self.emptyLine()

        if self.options.oom_fuzz and self.options.oom_seq:
            self.write_block(
                0,
                f"""
                _OOM_WINDOW = {self.options.oom_window}

                def oom_run(label, thunk, window=_OOM_WINDOW):
                    # Stateful OOM sequence (Phase 4): sweep a bounded failure window
                    # across a multi-step thunk so a failure in one step can corrupt
                    # state a later step trips over. set_nomemory(start, start+window)
                    # fails `window` allocations then resumes succeeding, so steps after
                    # the burst run on the damaged state (window == 0 -> fail forever,
                    # the legacy single-call semantics). `window` defaults to _OOM_WINDOW
                    # but is passed per-sequence when --oom-seq-randomize is set. The thunk
                    # guards each step internally so the tail still runs after an earlier
                    # step raises; a real crash (segfault/abort) terminates the process and
                    # is scored.
                    if not _OOM_AVAILABLE:
                        try:
                            thunk()
                        except BaseException:
                            pass
                        return
                    print("[OOM-SEQ] " + label + " window=" + str(window), file=stderr)
                    for _start in range(_OOM_MAX_START):
                        if _OOM_VERBOSE:
                            print("[OOM-SEQ]   start=" + str(_start) + " window=" + str(window), file=stderr)
                        if window > 0:
                            _set_nomemory(_start, _start + window)
                        else:
                            _set_nomemory(_start, 0)
                        try:
                            try:
                                thunk()
                            finally:
                                _set_nomemory(_OOM_DISABLE, 0)
                        except MemoryError:
                            pass
                        except SystemError:
                            print("[OOM-SEQ] SystemError in " + label, file=stderr)
                        except BaseException:
                            pass
            """,
            )
            self.emptyLine()

    def _write_main_fuzzing_logic(self) -> None:
        """Writes the core fuzzing loops for functions, classes, and objects."""
        self._write_fuzzing_logic_preamble()

        self._write_function_fuzzing_loop()
        self.emptyLine()

        # OOM mode (Phase 2): after the module-level function sweeps, sweep class
        # constructors and methods -- where the high-value unchecked-allocation bugs
        # live -- then stop (the non-OOM class/object blocks below are skipped).
        if self.options.oom_fuzz:
            self._write_oom_class_fuzzing_loop()
            return

        self._write_class_fuzzing_loop()
        self.emptyLine()

        self._write_object_fuzzing_loop()
        self.emptyLine()

    def _write_fuzzing_logic_preamble(self) -> None:
        """Emits the module alias, thread/async registries, and the runtime imports."""
        self.write(0, f"fuzz_target_module = {self.module_name}")
        self.emptyLine()

        if self.enable_threads:
            self.write(0, "fuzzer_threads_alive = []")
        if self.enable_async:
            self.write(0, "fuzzer_async_tasks = []")
        self.emptyLine()

        self.write(0, "\n# FUSIL_BOILERPLATE_END\n")
        self.write(
            0,
            dedent(
                """
            import sys
            from random import choice, randint, random, sample
            from sys import stderr, path as sys_path
            """
            ),
        )
        self.emptyLine()

    def _write_function_fuzzing_loop(self) -> None:
        """Fuzzes module-level functions (OOM sweep or standard calls)."""
        if not self.module_functions:
            return
        self.write_print_to_stderr(
            0,
            f'"--- Fuzzing {len(self.module_functions)} functions in {self.module_name} ---"',
        )
        n_calls = self.options.oom_calls if self.options.oom_fuzz else self.options.functions_number
        for i in range(n_calls):
            self._write_one_function_fuzz(f"f{i + 1}")

    def _write_one_function_fuzz(self, prefix: str) -> None:
        """Emits one function-fuzzing call for `prefix` (OOM sequence/sweep or standard)."""
        if self.options.oom_fuzz:
            if self.options.oom_seq:
                # OOM sequence: several functions under one failure window so a
                # failure in one can corrupt state a later one trips over.
                self._generate_oom_function_sequence(prefix)
                return
            # OOM injection: wrap a function call in a dense set_nomemory sweep
            func_name = choice(self.module_functions)
            try:
                func_obj = getattr(self.module, func_name)
            except AttributeError:
                return
            self._generate_oom_function_call(prefix, func_name, func_obj)
            return

        # Standard function call fuzzing
        func_name = choice(self.module_functions)
        try:
            func_obj = getattr(self.module, func_name)
        except AttributeError:
            return
        self._generate_and_write_call(
            prefix=prefix,
            callable_name=func_name,
            callable_obj=func_obj,
            min_arg_count=1,
            target_obj_expr="fuzz_target_module",
            is_method_call=False,
            generation_depth=0,
        )

    def _write_oom_class_fuzzing_loop(self) -> None:
        """OOM Phase 2: sweep class constructors + methods for allocation-failure bugs."""
        if not (self.module_classes and self.options.oom_classes > 0):
            return
        self.write_print_to_stderr(
            0,
            f'"--- OOM-fuzzing {len(self.module_classes)} classes in {self.module_name} ---"',
        )
        for i in range(self.options.oom_classes):
            class_name = choice(self.module_classes)
            if class_name in OBJECT_BLACKLIST:
                continue
            try:
                class_obj = getattr(self.module, class_name)
            except AttributeError:
                continue
            self._generate_oom_class_fuzzing(f"oc{i + 1}", class_name, class_obj)

    def _write_class_fuzzing_loop(self) -> None:
        """Fuzzes module classes: instantiate each and call its methods."""
        if not self.module_classes:
            return
        self.write_print_to_stderr(
            0,
            f'"--- Fuzzing {len(self.module_classes)} classes in {self.module_name} ---"',
        )
        for i in range(self.options.classes_number):
            if not self.module_classes:
                break
            class_name = choice(self.module_classes)
            if class_name in OBJECT_BLACKLIST:
                continue
            try:
                class_obj = getattr(self.module, class_name)
            except AttributeError:
                continue

            self._fuzz_one_class(class_idx=i, class_name_str=class_name, class_type=class_obj)

    def _write_object_fuzzing_loop(self) -> None:
        """Fuzzes module-level objects (skipping submodules and blacklisted names)."""
        if not self.module_objects:
            return
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

    def _fuzz_one_class(self, class_idx: int, class_name_str: str, class_type: type) -> None:
        """Generates code to instantiate a class and fuzz its methods."""
        prefix = f"c{class_idx + 1}"
        self.write_print_to_stderr(
            0, f'"[{prefix}] Attempting to instantiate class: {class_name_str}"'
        )
        if class_name_str in OBJECT_BLACKLIST:
            self.write_print_to_stderr(
                0, f'"[{prefix}] Skipping blacklisted class: {class_name_str}"'
            )
            return
        instance_var_name = (
            f"instance_{prefix}_{class_name_str.lower().replace('.', '_')}"  # Unique name
        )

        num_constructor_args = class_arg_number(class_name_str, class_type)
        self.write(0, f"{instance_var_name} = None # Initialize instance variable")

        # Plugin class handlers get first chance to emit specialized instantiation (e.g. an
        # h5py.File needs a backing file, not a generic callFunc). A handler returns True to
        # claim the class; otherwise we fall through to the standard callFunc instantiation.
        # With no handlers registered this is byte-identical to the pre-plugin behaviour.
        handled = False
        if self.plugin_manager:
            for handler in self.plugin_manager.get_class_handlers():
                if handler(self, class_name_str, class_type, instance_var_name, prefix):
                    handled = True
                    break

        if not handled:
            self.write(0, "try:")
            with self.indented():
                self.write(
                    0, f"{instance_var_name} = callFunc('{prefix}_init', '{class_name_str}',"
                )
                self._write_arguments_for_call_lines(num_constructor_args, 1)  # Indent args by 1
                self.write(0, "  )")  # Close callFunc
            self.write(0, "except Exception as e_instantiate:")
            with self.indented():
                self.write(0, f"{instance_var_name} = None")
                self.write_print_to_stderr(
                    0,
                    f'"[{prefix}] Failed to instantiate {class_name_str}: {{e_instantiate.__class__.__name__}} {{e_instantiate}}"',
                )
                # callFunc may not set instance_var_name on error, so set it explicitly.
                self.write(0, f"{instance_var_name} = None")
        self.emptyLine()

        self._dispatch_fuzz_on_instance(
            current_prefix=f"{prefix}_{class_name_str.lower()}_ops",
            target_obj_expr_str=instance_var_name,
            class_name_hint=class_name_str,
            generation_depth=0,
        )

        # If instance_var_name was successfully created, fuzz its methods.
        self.write(
            0, f"if {instance_var_name} is not None and {instance_var_name} is not SENTINEL_VALUE:"
        )
        with self.indented():
            # class_type is the type object of the class that was "instantiated"
            self._fuzz_methods_on_object_or_specific_types(
                current_prefix=f"{prefix}m",  # e.g. "o1m", "c1m"
                target_obj_expr_str=instance_var_name,
                target_obj_class_name=class_name_str,  # Original class name string
                target_obj_actual_type_obj=class_type,  # The actual type object
                num_method_calls_to_make=self.options.methods_number,
            )
            self.write(0, f"del {instance_var_name} # Cleanup instance")
            self.write_print_to_stderr(
                0, f'"[{prefix}] -explicit garbage collection for class instance-"'
            )
            self.write(0, "collect()")
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
            self.write(0, "try:")
            self.write_print_to_stderr(
                1,
                f"f'Max fuzz code generation depth ({self.MAX_FUZZ_GENERATION_DEPTH}) reached for {{ {target_obj_expr_str}!r }}, not generating deeper fuzzing.'",
            )
            self.write(0, "except Exception:")
            self.write_print_to_stderr(
                1,
                f"f'Max fuzz code generation depth ({self.MAX_FUZZ_GENERATION_DEPTH}) reached for {class_name_hint}, not generating deeper fuzzing.'",
            )

            return
        self.write(0, "try:")
        self.write_print_to_stderr(
            1,
            f'f"--- (Depth {generation_depth}) Dispatching Fuzz for: {{ {target_obj_expr_str}!r }} (hint: {class_name_hint}, prefix: {current_prefix}) ---"',
        )
        self.write(0, "except Exception as e:")
        self.write_print_to_stderr(
            1,
            f'f"--- (Depth {generation_depth}) Error calling repr() prefix: {current_prefix}) ---"',
        )
        self.write(0, f"if {target_obj_expr_str} is not None:")
        with self.indented():
            self.write(0, f"if skip_trivial_type({target_obj_expr_str}):")
            with self.indented():
                self.write_print_to_stderr(
                    0,
                    f"f'Skipping deep diving on {target_obj_expr_str} {{type({target_obj_expr_str})}}'",
                )
            # Plugin instance dispatchers emit specialized `elif isinstance(target, T):`
            # branches here (after skip-trivial, before the generic fallback). A dispatcher
            # may open a trailing `else:` and return the level to restore to, so the generic
            # fallback below runs only when no specialized branch matched; None (the default,
            # e.g. no plugins) leaves the fallback unconditional -- byte-identical to the
            # pre-plugin behaviour.
            L_else_generic = None
            if self.plugin_manager:
                for dispatcher in self.plugin_manager.get_instance_dispatchers():
                    level = dispatcher(
                        self,
                        current_prefix,
                        target_obj_expr_str,
                        class_name_hint,
                        generation_depth,
                    )
                    if level is not None:
                        L_else_generic = level
            try:
                self.write(0, "try:")
                self.write_print_to_stderr(
                    1,
                    f"f'Instance {{ {target_obj_expr_str}!r }} (actual type {{type({target_obj_expr_str}).__name__}}) has no specific fuzzer type, doing generic calls.'",
                )
                self.write(0, "except Exception as e:")
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
                if L_else_generic is not None:
                    self.restoreLevel(L_else_generic)

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
        # This part usually involves:
        # 1. Getting a list of callable attributes (methods).
        # 2. Looping `num_calls` times.
        # 3. In each iteration, choosing a random method.
        # 4. Calling `self._generate_and_write_call` for that method.
        # The deep dive part comes if _generate_and_write_call is enhanced.
        self.write(0, f"if skip_trivial_type({target_obj_expr_str}):")
        with self.indented():
            self.write_print_to_stderr(
                0,
                f"f'Skipping deep diving on {target_obj_expr_str} {{type({target_obj_expr_str})}}'",
            )
        self.write(0, "else:")
        with self.indented():
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
            self.write(0, "try:")
            with self.indented():
                self.write(0, f"for {current_prefix}_attr_name in dir({target_obj_expr_str}):")
                with self.indented():
                    self.write(
                        0, f"if {current_prefix}_attr_name.startswith('_'): continue"
                    )  # Skip private/dunder for simplicity
                    self.write(0, "try:")  # Inner try for getattr
                    with self.indented():
                        self.write(
                            0,
                            f"{current_prefix}_attr_val = getattr({target_obj_expr_str}, {current_prefix}_attr_name)",
                        )
                        self.write(
                            0,
                            f"if callable({current_prefix}_attr_val) and not {current_prefix}_attr_val.__name__ in ('wait', '_rehash'): {current_prefix}_methods.append(({current_prefix}_attr_name, {current_prefix}_attr_val))",
                        )
                    self.write(0, "except Exception: pass")
            self.write(
                0, f"except Exception: {current_prefix}_methods = [] # Failed to get methods"
            )

            self.write(0, f"if {current_prefix}_methods:")
            with self.indented():
                self.write_print_to_stderr(
                    0,
                    f"f'Found {{len({current_prefix}_methods)}} callable methods for generic fuzzing of {target_obj_expr_str}'",
                )
                self.write(
                    0,
                    f"for _i_{current_prefix} in range(min(len({current_prefix}_methods), {self.options.methods_number})):",
                )  # Use configured num calls
                with self.indented():
                    self.write(
                        0,
                        f"{current_prefix}_method_name_to_call, {current_prefix}_method_obj_to_call = choice({current_prefix}_methods)",
                    )
                    # Now call _generate_and_write_call using {current_prefix}_method_name_to_call (string)
                    # and {current_prefix}_method_obj_to_call (the callable).
                    # _generate_and_write_call needs adaptation if method_obj is a runtime variable.
                    # For simplicity here, let's assume _generate_and_write_call can take the method *name*
                    # and the target object expression.
                    self.write(0, "# Conceptual call to generic method fuzzer")
                    self.write(
                        0,
                        f"if {current_prefix}_method_name_to_call not in ('wait', '_rehash'): callMethod(f'{current_prefix}_gen{{_i_{current_prefix}}}', {target_obj_expr_str}, {current_prefix}_method_name_to_call)",
                    )  # Example simplified call
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
        with self.indented():
            self.write_print_to_stderr(
                0,
                f"f'Skipping deep diving on {target_obj_expr_str} {{type({target_obj_expr_str})}}'",
            )

        # General method fuzzing for other types
        self.write(0, f"# General method fuzzing for {target_obj_expr_str}")
        methods_dict = {}
        if target_obj_actual_type_obj:  # If WritePythonCode has the type
            methods_dict = self._get_object_methods(
                target_obj_actual_type_obj, target_obj_class_name
            )
        else:
            # No static type info: skip method discovery here (runtime discovery in the
            # generated script proved too complex to be worth it; methods_dict comes from
            # _get_object_methods based on type info).
            pass

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
            last_char = ","

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

    def _generate_oom_function_call(
        self, prefix: str, func_name: str, func_obj: Callable[..., Any]
    ) -> None:
        """Emits a module-level function call wrapped in a dense OOM sweep."""
        min_arg, max_arg = get_arg_number(func_obj, func_name, 1)
        num_args = randint(min_arg, max_arg)
        # Per-call marker: the last one printed before a crash is the culprit call.
        label = f"{prefix}:{self.module_name}.{func_name}"
        self.write(0, f"# OOM sweep: {func_name}")
        self.write(0, f'oom_call("{label}", getattr(fuzz_target_module, "{func_name}"),')
        self._write_arguments_for_call_lines(num_args, 1)
        self.write(0, ")")
        self.emptyLine()

    def _oom_seq_randomize(self) -> bool:
        return bool(getattr(self.options, "oom_seq_randomize", False))

    def _oom_pick_seq_len(self) -> int:
        """Step count for ONE sequence. With --oom-seq-randomize, uniform in [1, oom_seq_len]
        (the configured value is the upper bound); otherwise the fixed oom_seq_len."""
        n = max(1, self.options.oom_seq_len)
        if self._oom_seq_randomize() and n > 1:
            return randint(1, n)
        return n

    def _oom_pick_window(self):
        """Failure window for ONE sequence, or None to emit the harness default (_OOM_WINDOW).
        With --oom-seq-randomize, uniform in [1, oom_window] (upper bound); otherwise None so
        the generated oom_run() call is unchanged. window 0 (legacy fail-forever) is left as
        the static default and never randomized into."""
        if self._oom_seq_randomize() and self.options.oom_window > 1:
            return randint(1, self.options.oom_window)
        return None

    def _write_oom_sequence(self, fn_name: str, seq_label: str, steps, window=None) -> None:
        """Emit a guarded multi-step thunk plus an oom_run() call (Phase 4 sequence).

        steps: list of (sublabel, target_expr, num_args), where target_expr is a string
        evaluating to the callable (e.g. 'getattr(fuzz_target_module, "dumps", None)').
        Each step is wrapped in try/except so a failing step does not abort the tail --
        the shared state (a live instance, or module/interpreter globals such as a pending
        exception) is what a later step may trip over. Result values are not threaded
        between steps yet (Phase 4b); the steps interact only through shared state.

        window: per-sequence failure window (--oom-seq-randomize); None emits the default
        oom_run(label, thunk) call (uses the module-level _OOM_WINDOW).
        """
        self.write(0, f"def {fn_name}():")
        with self.indented():
            wrote = False
            for sublabel, target_expr, num_args in steps:
                # The verbose marker is INSIDE the try: under a low window the failing
                # allocation can land in the print itself, and we want that swallowed so the
                # tail steps still run (it does perturb the allocation count, so verbose is for
                # coarse pinpointing -- the authoritative locator is faulthandler's traceback).
                self.write(0, "try:")
                self.write(1, "if _OOM_VERBOSE:")
                self.write(2, f'print("[OOM-SEQ]     step {sublabel}", file=stderr)')
                self.write(1, f"{target_expr}(")
                self._write_arguments_for_call_lines(num_args, 2)
                self.write(1, ")")
                self.write(0, "except BaseException:")
                self.write(1, "pass")
                wrote = True
            if not wrote:
                self.write(0, "pass")
        if window is None:
            self.write(0, f'oom_run("{seq_label}", {fn_name})')
        else:
            self.write(0, f'oom_run("{seq_label}", {fn_name}, window={window})')
        self.emptyLine()

    def _generate_oom_function_sequence(self, prefix: str) -> None:
        """Emit one OOM sequence (Phase 4) over several module-level functions.

        The functions run in order under one bounded failure window, so a failure in one
        can leave module/interpreter state (a pending exception, specializer/GC state)
        that a later one trips over -- the stale-exception class (e.g. OOM-0008/0010/
        0011/0015/0025/0032).
        """
        steps = []
        names = []
        for j in range(self._oom_pick_seq_len()):
            func_name = choice(self.module_functions)
            try:
                func_obj = getattr(self.module, func_name)
            except AttributeError:
                continue
            min_arg, max_arg = get_arg_number(func_obj, func_name, 1)
            num_args = randint(min_arg, max_arg)
            steps.append(
                (
                    f"s{j + 1}:{func_name}",
                    f'getattr(fuzz_target_module, "{func_name}", None)',
                    num_args,
                )
            )
            names.append(func_name)
        if not steps:
            return
        seq_label = f"{prefix}:{self.module_name}[" + ">".join(names) + "]"
        self.write(0, f"# OOM sequence: {' > '.join(names)}")
        self._write_oom_sequence(
            f"_oom_seq_{prefix}", seq_label, steps, window=self._oom_pick_window()
        )

    def _generate_oom_class_fuzzing(self, prefix: str, class_name: str, class_obj: type) -> None:
        """Emits an OOM sweep over a class constructor and, on a live instance, its methods.

        Phase 2 of OOM fuzzing: constructors and methods reach allocation paths the
        module-level function sweep cannot (e.g. OOM-0030 is a str-subclass constructor
        bug). The constructor is swept directly -- the class is itself the callable -- and
        methods are swept on a single instance built once outside the sweep, so each runs
        against a real object. Argument values are built once at the oom_call(...)
        expression; arming happens inside oom_call.
        """
        # 1. Constructor sweep -- the class object is the callable.
        ctor_args = class_arg_number(class_name, class_obj)
        ctor_label = f"{prefix}:{self.module_name}.{class_name}"
        self.write(0, f"# OOM sweep: {class_name}() constructor")
        self.write(
            0, f'oom_call("{ctor_label}", getattr(fuzz_target_module, "{class_name}", None),'
        )
        self._write_arguments_for_call_lines(ctor_args, 1)
        self.write(0, ")")
        self.emptyLine()

        # 2. Discover methods (generation-time, blacklist-respecting). None -> done.
        methods = self._get_object_methods(class_obj, class_name)
        if not methods or self.options.oom_methods < 1:
            return
        method_names = sorted(methods.keys())

        # 3. Build one live instance (plain, outside any sweep) to fuzz methods against.
        inst = f"oom_inst_{prefix}_{class_name.lower().replace('.', '_')}"
        self.write(0, f"{inst} = None")
        self.write(0, "try:")
        self.write(1, f'{inst} = callFunc("{prefix}_init", "{class_name}",')
        self._write_arguments_for_call_lines(ctor_args, 2)
        self.write(1, ")")
        self.write(0, "except Exception:")
        self.write(1, f"{inst} = None")
        self.emptyLine()

        # 4. Method sweeps on the live instance.
        self.write(0, f"if {inst} is not None and {inst} is not SENTINEL_VALUE:")
        with self.indented():
            if self.options.oom_seq:
                # Phase 4: one sequence of methods on the SAME instance under a single
                # failure window, so a failure in method A can leave the instance in a state
                # method B trips over (e.g. OOM-0035: write... then getvalue()).
                steps = []
                mnames = []
                for j in range(self._oom_pick_seq_len()):
                    m_name = choice(method_names)
                    m_obj = methods[m_name]
                    min_arg, max_arg = get_arg_number(m_obj, m_name, 0)
                    num_args = randint(min_arg, max_arg)
                    steps.append(
                        (
                            f"m{j + 1}:{m_name}",
                            f'getattr({inst}, "{m_name}", None)',
                            num_args,
                        )
                    )
                    mnames.append(m_name)
                seq_label = f"{prefix}:{self.module_name}.{class_name}[" + ">".join(mnames) + "]"
                self.write(0, f"# OOM sequence on {class_name}: {' > '.join(mnames)}")
                self._write_oom_sequence(
                    f"_oom_seq_{prefix}", seq_label, steps, window=self._oom_pick_window()
                )
            else:
                for j in range(self.options.oom_methods):
                    m_name = choice(method_names)
                    m_obj = methods[m_name]
                    min_arg, max_arg = get_arg_number(m_obj, m_name, 0)
                    num_args = randint(min_arg, max_arg)
                    m_label = f"{prefix}m{j + 1}:{self.module_name}.{class_name}.{m_name}"
                    self.write(0, f"# OOM sweep: {class_name}.{m_name}()")
                    self.write(0, f'oom_call("{m_label}", getattr({inst}, "{m_name}", None),')
                    self._write_arguments_for_call_lines(num_args, 1)
                    self.write(0, ")")
            self.write(0, f"del {inst}")
            self.write(0, "collect()")
        self.emptyLine()

    def _generate_and_write_call(
        self,
        prefix: str,
        callable_name: str,
        callable_obj: Callable[..., Any],
        min_arg_count: int,
        target_obj_expr: str,  # e.g., "fuzz_target_module" or "instance_var"
        is_method_call: bool,
        generation_depth: int,
        verbose: bool = True,
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
        num_args = self._pick_call_arg_count(min_arg, max_arg)

        call_prefix = (
            f'callMethod("{prefix}", {target_obj_expr}, "{callable_name}"'
            if is_method_call
            else f'callFunc("{prefix}", "{callable_name}"'
        )

        self.write(0, f"res_{prefix} = {call_prefix},")
        self._write_arguments_for_call_lines(num_args, 1)
        self.write(0, f"verbose={verbose})")
        self.emptyLine()

        self._write_result_deep_dive(prefix, callable_name, generation_depth)

        self._write_target_func_fetch(prefix, callable_name, target_obj_expr)
        self.emptyLine()

        self._write_thread_call_wrapper(prefix, callable_name, num_args)
        self._write_async_call_wrapper(prefix, callable_name, num_args)

    def _pick_call_arg_count(self, min_arg: int, max_arg: int) -> int:
        """Picks how many arguments to pass: mostly in-range, with edge cases (0, 1, max+1)."""
        rand_choice = randint(0, 19)
        if rand_choice < 1:  # 0 (5%)
            return 0
        elif rand_choice < 2:  # 1 (5%)
            return 1
        elif rand_choice < 3:  # max_arg + 1 (5%)
            return max_arg + 1
        elif min_arg == max_arg:
            return min_arg
        else:  # (remaining 85%)
            return randint(min_arg, max_arg)

    def _write_result_deep_dive(
        self, prefix: str, callable_name: str, generation_depth: int
    ) -> None:
        """Opt-in (--deep-dive): recursively fuzz the call's return value.

        Multiplicative (every returning call spawns another round of fuzzing on the result)
        and has not historically paid off, so it is off by default.
        """
        if not self.options.deep_dive:
            return
        self.write(0, f"# Deep dive on result of {callable_name}")
        self.write(
            0,
            f"if 'res_{prefix}' in locals() and res_{prefix} is not None and res_{prefix} is not SENTINEL_VALUE:",
        )
        with self.indented():
            self.write(0, f"{prefix}_res_type_name = type(res_{prefix}).__name__")
            self.write(0, "try:")
            with self.indented():
                self.write_print_to_stderr(
                    0,
                    f"f'CALL_RESULT ({prefix}): Method {callable_name} returned {{res_{prefix}!r}} of type {{{prefix}_res_type_name}}. Attempting deep dive.'",
                )
            self.write(0, "except Exception as e:")
            with self.indented():
                self.write_print_to_stderr(
                    0,
                    "f'EXCEPTION printing CALL_RESULT: { e }'",
                )
            self._dispatch_fuzz_on_instance(
                current_prefix=f"{prefix}_res_dive",
                target_obj_expr_str=f"res_{prefix}",  # The variable holding the result
                class_name_hint=f"{prefix}_res_type_name",  # Runtime type name
                generation_depth=generation_depth + 1,  # Incremented depth
            )

    def _write_target_func_fetch(
        self, prefix: str, callable_name: str, target_obj_expr: str
    ) -> None:
        """Fetches the bound callable into `target_func` for the thread/async wrappers."""
        if not (self.enable_threads or self.enable_async):
            return
        self.write(0, "target_func = None")
        self.write(0, "try:")
        self.write(1, f"target_func = getattr({target_obj_expr}, '{callable_name}')")
        self.write(0, "except Exception as e_get_target_func:")
        self.write_print_to_stderr(
            1,
            f'f"[{prefix}] Failed to get attribute {callable_name} from {target_obj_expr}: '
            f'{{e_get_target_func.__class__.__name__}} {{e_get_target_func}}"',
        )

    def _write_thread_call_wrapper(self, prefix: str, callable_name: str, num_args: int) -> None:
        """Wraps the call in a Thread appended to fuzzer_threads_alive (when --threads)."""
        if not self.enable_threads:
            return
        self.write(0, "if target_func is not None:")
        with self.indented():
            self.write(0, "try:")
            with self.indented():
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
            self.write(0, "except Exception as e_thread_create:")
            self.write_print_to_stderr(
                1,
                f'f"[{prefix}] Failed to create thread for {callable_name}: {{e_thread_create.__class__.__name__}}"',
            )
        self.emptyLine()

    def _write_async_call_wrapper(self, prefix: str, callable_name: str, num_args: int) -> None:
        """Wraps the call in an async task appended to fuzzer_async_tasks (when --async)."""
        if not self.enable_async:
            return
        async_func_name = f"async_call_{prefix}_{callable_name}"
        self.write(0, "if target_func is not None:")
        with self.indented():
            self.write(0, f"def {async_func_name}(target_func=target_func):")
            with self.indented():
                self.write_print_to_stderr(0, f'"Starting async task: {async_func_name}"')
                self.write(0, f"time.sleep({random() / 1000:.6f}) # Small delay")
                self.write(0, "try:")
                with self.indented():
                    arg_expr_list_async = []
                    for _ in range(num_args):
                        arg_lines = self.arg_generator.create_simple_argument()
                        arg_expr_list_async.append(" ".join(arg_lines))

                    args_str_async = ", ".join(arg_expr_list_async)

                    self.write(0, f"target_func({args_str_async})")
                self.write(0, "except Exception as e_async_call:")
                self.write_print_to_stderr(
                    1,
                    f'f"[{prefix}] Exception in async task {async_func_name}: {{e_async_call.__class__.__name__}} {{e_async_call}}"',
                )
                self.write_print_to_stderr(0, f'"Ending async task: {async_func_name}"')
            self.write(0, f"fuzzer_async_tasks.append({async_func_name})")
        self.emptyLine()

    def _write_concurrency_finalization(self) -> None:
        """Writes code to start/join threads and run asyncio tasks."""
        if self.enable_threads:
            self.write_block(
                0,
                """
                print("--- Starting and Joining Fuzzer Threads ---", file=stderr)
                for t_obj in fuzzer_threads_alive:
                    try:
                        print(f"Starting thread: {t_obj.name}", file=stderr)
                        t_obj.start()
                    except Exception as e_thread_start:
                        print(f"Failed to start thread {t_obj.name}: {e_thread_start.__class__.__name__}", file=stderr)
                for t_obj in fuzzer_threads_alive:
                    try:
                        print(f"Joining thread: {t_obj.name}", file=stderr)
                        t_obj.join(timeout=1.0) # Add timeout to join
                    except Exception as e_thread_join:
                        print(f"Failed to join thread {t_obj.name}: {e_thread_join.__class__.__name__}", file=stderr)
                """,
            )
            self.emptyLine()

        if self.enable_async:
            self.write_block(
                0,
                """
                print("--- Running Fuzzer Async Tasks ---", file=stderr)
                async def main_async_fuzzer_tasks():
                    if not fuzzer_async_tasks: return
                    task_objects = [asyncio.to_thread(func) for func in fuzzer_async_tasks]
                    await asyncio.gather(*task_objects, return_exceptions=True)

                runner = asyncio.Runner()
                try:
                    runner.run(main_async_fuzzer_tasks())
                except Exception as e_async_runner_run:
                    print(f'Exception in async runner: {e_async_runner_run.__class__.__name__} {e_async_runner_run}')
                finally:
                    runner.close()
                """,
            )
            self.emptyLine()

    def generate_fuzzing_script(self) -> None:
        """Creates and writes the entire fuzzing script to the specified file."""
        self.createFile(self.generated_filename)

        self._write_script_header_and_imports()
        self._write_tricky_definitions()
        self._write_helper_call_functions()

        # Check for active plugin mode
        active_mode = None
        if hasattr(self, "plugin_manager") and self.plugin_manager:
            active_mode = self.plugin_manager.get_active_mode(self.options)

        if active_mode:
            self.write_print_to_stderr(0, f'"--- Running in {active_mode.name} Mode ---"')
            self.emptyLine()
            active_mode.setup_script(self)  # Let the plugin generate the main logic
        else:
            # Standard fuzzing logic
            self._write_main_fuzzing_logic()
            self._write_concurrency_finalization()

        self.parent_python_source.warning(
            f"--- Fuzzing script generation for {self.module_name} complete ---"
        )
        self.close()
