from __future__ import annotations

import sys
import time

import fusil.python.tricky_weird
from fusil.application import Application
from fusil.config import (
    OptionGroupWithSections,
    OptionParserWithSections,
    createFilename,
)
from fusil.process.create import CreateProcess
from fusil.process.stdout import WatchStdout
from fusil.process.watch import WatchProcess
from fusil.project import Project
from fusil.python.python_source import PythonSource
from fusil.python.utils import print_running_time
from fusil.python.write_python_code import time_start

print(sys.version)

IGNORE_TIMEOUT = True
IGNORE_CPU = True
SHOW_STDOUT = False
DEBUG = False
TIMEOUT = 900.0
PYTHON = sys.executable
FILENAMES = "/etc/machine-id,/bin/sh"
DEFAULT_NB_CALL = 250
DEFAULT_NB_METHOD = 15
DEFAULT_NB_CLASS = 50
DEFAULT_NB_OBJ = 100


class Fuzzer(Application):
    """Main fuzzer application that coordinates the fuzzing process."""

    NAME = "python"

    def createFuzzerOptions(self, parser: OptionParserWithSections) -> None:
        """Create command-line options for the fuzzer configuration."""
        input_options = OptionGroupWithSections(parser, "Input")
        input_options.add_option(
            "--modules",
            help="Tested Python module names separated by commas (default: test all modules)",
            type="str",
            default="*",
        )
        input_options.add_option(
            "--packages",
            help="Tested Python packages names separated by commas (default: test all packages)",
            type="str",
            default="*",
        )
        input_options.add_option(
            "--skip-test",
            help="Skip modules with 'test' in the name (default: False)",
            action="store_true",
            default=False,
        )
        input_options.add_option(
            "--blacklist",
            help='Module blacklist separated by commas (eg. "_lsprof,_json")',
            type="str",
            default="",
        )
        input_options.add_option(
            "--test-private",
            help="Test private methods (default: skip privates methods)",
            action="store_true",
            default=False,
        )
        input_options.add_option(
            "--only-c",
            help="Only search for modules written in C (default: search all module)",
            action="store_true",
            default=False,
        )
        input_options.add_option(
            "--no-site-packages",
            help="Don't search modules in site-packages directory",
            action="store_true",
            default=False,
        )
        running_options = OptionGroupWithSections(parser, "Running")
        running_options.add_option(
            "--timeout",
            help="Timeout in seconds (default: %d)" % TIMEOUT,
            type="float",
            default=TIMEOUT,
        )
        running_options.add_option(
            "--python",
            help="Python executable program path (default: %s)" % PYTHON,
            type="str",
            default=PYTHON,
        )
        running_options.add_option(
            "--record-timeouts",
            help="Consider timeouts as errors (default: False)",
            action="store_true",
            default=False,
        )
        running_options.add_option(
            "--exitcode-score",
            help="Score for exitcode (default: 0.0)",
            type="float",
            default=0.0,
        )
        running_options.add_option(
            "--record-high-cpu",
            help="Consider high CPU usage an error (default: False)",
            action="store_true",
            default=False,
        )
        running_options.add_option(
            "--show-stdout",
            help="Display STDOUT (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options = OptionGroupWithSections(parser, "Fuzzing")
        fuzzing_options.add_option(
            "--functions-number",
            help="Number of function calls to generate per module (default: %d)" % DEFAULT_NB_CALL,
            type="int",
            default=DEFAULT_NB_CALL,
        )
        fuzzing_options.add_option(
            "--methods-number",
            help="Number of method calls to create for each class or object (default: %d)"
            % DEFAULT_NB_METHOD,
            type="int",
            default=DEFAULT_NB_METHOD,
        )
        fuzzing_options.add_option(
            "--classes-number",
            help="Number of classes to fuzz per module (default: %d)" % DEFAULT_NB_CLASS,
            type="int",
            default=DEFAULT_NB_CLASS,
        )
        fuzzing_options.add_option(
            "--objects-number",
            help="Number of objects to fuzz per module (default: %d)" % DEFAULT_NB_OBJ,
            type="int",
            default=DEFAULT_NB_OBJ,
        )
        # options.add_option(
        #     "--no-mangle",
        #     help="Don't mangle objects (default: False)",
        #     action="store_true",
        # )
        fuzzing_options.add_option(
            "--fuzz-exceptions",
            help="Include basic Exceptions in fuzzing (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options.add_option(
            "--no-async",
            help="Don't run code asynchronously (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options.add_option(
            "--no-threads",
            help="Don't run code in threads (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options.add_option(
            "--no-numpy",
            help="Don't use Numpy (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options.add_option(
            "--no-tstrings",
            help="Don't use template strings (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options.add_option(
            "--filenames",
            help="Names separated by commas of readable files (default: %s)" % FILENAMES,
            type="str",
            default=FILENAMES,
        )
        jit_options = OptionGroupWithSections(parser, "JIT Fuzzing")
        jit_options.add_option(
            "--jit-fuzz",
            help="Enable JIT-stressing code generation patterns (default: False)",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--jit-loop-iterations",
            help="Number of iterations for JIT hot loops (default: 10000)",
            type="int",
            default=10000,
        )
        jit_options.add_option(
            "--jit-polymorphic-degree",
            help="Number of different types to use in a polymorphic call (default: 4)",
            type="int",
            default=4,
        )
        jit_options.add_option(
            "--jit-pattern-mix-prob",
            help="Probability (0.0-1.0) of generating a JIT-pattern block instead of a standard call (default: 0.25)",
            type="float",
            default=0.25,
        )
        jit_options.add_option(
            "--jit-hostile-prob",
            help="Probability (0.0-1.0) of generating a hostile invalidation scenario (default: 0.1)",
            type="float",
            default=0.2,
        )
        jit_options.add_option(
            "--jit-fuzz-level",
            help="Set the intensity of JIT fuzzing. "
                 "1=Friendly Patterns, 2=Isolated Hostile Scenarios, 3=Mixed Hostile Scenarios. "
                 "Requires --jit-fuzz. (default: 1)",
            type="int",
            default=1,
        )
        jit_options.add_option(
            "--jit-aggressive-gc",
            help="Interleave frequent gc.collect() calls inside JIT hot loops (default: False)",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--jit-gc-frequency",
            help="Run gc.collect() every N iterations in a JIT hot loop (default: 100)",
            type="int",
            default=100,
        )
        jit_options.add_option(
            "--jit-hostile-side-exits",
            help="Enable scenarios that force frequent JIT deoptimization (default: False)",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--jit-raise-exceptions",
            help="Deliberately raise exceptions inside JIT-hot loops (default: False)",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--jit-exception-prob",
            help="The probability (0.0 to 1.0) of raising an exception per loop (default: 0.001)",
            type="float",
            default=0.001,
        )
        jit_options.add_option(
            "--jit-hostile-isinstance",
            help="Enable scenarios that attack the JIT's isinstance elimination (default: False)",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--jit-correctness-testing",
            help="Enable self-checking correctness tests for JIT scenarios (default: False)",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--rediscover-decref-crash",
            help="Run ONLY the specific scenario to rediscover the GH-124483 crash.",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--jit-fuzz-patterns",
            help="Fuzz specific JIT bug patterns by comma-separated names (e.g., 'decref_escapes').",
            type="str",
            default=None,
        )
        jit_options.add_option(
            "--jit-fuzz-systematic-values",
             help="When fuzzing a pattern, systematically iterate through all INTERESTING values as the payload. Disables random payload generation.",
             action="store_true",
             default=False,
        )
        jit_options.add_option(
            "--jit-fuzz-type-aware",
            help="When fuzzing a pattern, systematically iterate through a set of contrasting types for the payload.",
            action="store_true",
            default=False,
        )
        config_options = OptionGroupWithSections(parser, "Configuration")
        config_options.add_option(
            "--write-config",
            help="Write a sample configuration file if one doesn't exist (default: False)",
            action="store_true",
            default=False,
        )
        config_options.add_option(
            "--config-file",
            help="Name of the configuration file to be read or written (default: %s)"
            % createFilename(),
            type="str",
            default=createFilename(),
        )
        config_options.add_option(
            "--use-config",
            help="Load settings from configuration file (default: False)",
            action="store_true",
            default=False,
        )

        options = input_options, running_options, fuzzing_options, jit_options, config_options
        for option in options:
            parser.add_option_group(option)

    def setupProject(self) -> None:
        """Initialize the fuzzing project with process monitoring and output analysis."""
        project = self.project
        assert isinstance(project, Project)

        project.error(f"Start time: {time.asctime()}")
        project.error("Use python interpreter: %s" % self.options.python)
        version = " -- ".join(line.strip() for line in sys.version.splitlines())
        project.error("Python version: %s" % version)
        PythonSource(project, self.options)
        process = PythonProcess(
            project,
            [self.options.python, "-u", "<source.py>"],
            timeout=self.options.timeout,
        )
        process.max_memory = 4000 * 1024 * 1024 * 1024 * 1024
        options = {"exitcode_score": self.options.exitcode_score}
        if not self.options.record_timeouts:
            options["timeout_score"] = 0
        watch = WatchProcess(process, **options)
        if watch.cpu and not self.options.record_high_cpu:
            watch.cpu.max_score = 0

        stdout = WatchStdout(process)
        stdout.max_nb_line = None

        # Disable dummy error messages
        stdout.words = {
            "oops": 0.30,
            "bug": 0.10,
            "fatal": 0.1,
            # "assert": 0.025,
            "assertion": 1.0,
            "critical": 1.0,
            "panic": 1.0,
            "panicked": 1.0,  # For Rust errors
            "glibc detected": 1.0,
            "segfault": 1.0,
            "segmentation fault": 1.0,
            "SystemError": 1.0,
            "AddressSanitizer": 1.0,
        }

        stdout.kill_words = {"MemoryError", "mimalloc"}

        # CPython critical messages
        stdout.addRegex("^XXX undetected error", 1.0)
        stdout.addRegex("Fatal Python error", 1.0)
        # Match "Cannot allocate memory"?

        # PyPy messages
        stdout.addRegex("Fatal RPython error", 1.0)

        if self.options.show_stdout or self.options.debug:
            stdout.show_matching = True
            stdout.show_not_matching = True

        # avoid matching on "assert" keyword
        stdout.ignoreRegex(r"ast\.Assert()")

        # PyPy interact prompt
        # avoid false positive on "# assert did not crash"
        stdout.ignoreRegex(r"^And now for something completely different:")

        # import_all()

    def exit(self, keep_log: bool = True) -> None:
        """Clean up and exit the fuzzer, printing runtime statistics."""
        super().exit(keep_log=keep_log)
        self.error(print_running_time(time_start))


class PythonProcess(CreateProcess):
    """Handles the execution of generated Python test code."""

    def on_python_source(self, filename: str) -> None:
        """Execute the generated Python source file."""
        self.cmdline.arguments[-1] = filename
        self.createProcess()
