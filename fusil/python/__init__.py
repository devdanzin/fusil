from __future__ import annotations

import sys
import time
import warnings

# python-ptrace (imported transitively below) emits deprecation warnings on
# recent Python versions; hide them while importing the fusil runtime stack.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import fusil.python.tricky_weird  # noqa: F401  (imported here to suppress its import warnings)
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
    from fusil.python.utils import print_running_time, remove_logging_pycache
    from fusil.python.write_python_code import time_start

IGNORE_TIMEOUT = True
IGNORE_CPU = True
SHOW_STDOUT = False
DEBUG = False
TIMEOUT = 900.0
PYTHON = sys.executable
# Empty default => auto-created, expendable fixture files (fusil.python.fixtures).
# NEVER default to real system files: a fuzzed call may open a --filenames path for
# writing/truncation, and a privileged child (e.g. root under --unsafe) will clobber it.
# The historical "/etc/machine-id,/bin/sh" default did exactly that.
FILENAMES = ""
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
            "--no-memory-limit",
            help="Don't apply the per-child memory cap (RLIMIT_AS). Automatically "
            "implied for AddressSanitizer targets, whose huge address-space "
            "reservation is incompatible with RLIMIT_AS (default: False)",
            action="store_true",
            default=False,
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
        running_options.add_option(
            "--only-generate",
            help="Do not run scripts, only generate them (default: False)",
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
        fuzzing_options.add_option(
            "--fuzz-exceptions",
            help="Include basic Exceptions in fuzzing (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options.add_option(
            "--deep-dive",
            help="Recursively fuzz the return value of every method call (multiplicative; "
            "off by default)",
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
            help="Comma-separated readable files to feed as fuzz arguments. WARNING: a "
            "fuzzed call may open these for writing -- pass only expendable files. "
            "Default: auto-created throwaway fixtures (fusil.python.fixtures).",
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
            "--jit-mode",
            help="Main JIT fuzzing strategy: "
            "'synthesize' (default: create new patterns with AST), "
            "'variational' (mutate existing patterns from the library), "
            "'legacy' (run old hardcoded scenarios for regression testing), or "
            "'all' (randomly pick a strategy and modifiers for each test case, for maximum coverage).",
            choices=("synthesize", "variational", "legacy", "all"),
            default="synthesize",
        )

        # --- Variational Mode Modifiers ---
        jit_options.add_option(
            "--jit-pattern-name",
            help="[variational mode] Specifies which pattern(s) to use, e.g., 'decref_escapes' or 'ALL'.",
            type="str",
            default="ALL",
        )
        jit_options.add_option(
            "--jit-fuzz-ast-mutation",
            action="store_true",
            default=False,
            help="[variational mode] Enable the AST-based structural mutator on library patterns.",
        )
        jit_options.add_option(
            "--jit-fuzz-systematic-values",
            action="store_true",
            default=False,
            help="[variational mode] Systematically iterate through all known boundary values as the corruption payload.",
        )
        jit_options.add_option(
            "--jit-fuzz-type-aware",
            action="store_true",
            default=False,
            help="[variational mode] Systematically iterate through a set of contrasting types for the corruption payload.",
        )

        # --- Synthesizer Mode Modifier ---
        jit_options.add_option(
            "--jit-wrap-statements",
            action="store_true",
            default=False,
            help="[synthesize mode] Wrap each generated statement in a try/except block to increase resilience against benign errors.",
        )

        # --- Legacy Mode Modifier ---
        jit_options.add_option(
            "--jit-hostile-prob",
            type="float",
            default=0.1,
            help="[legacy mode] Probability (0.0-1.0) of generating a hostile scenario instead of a friendly one.",
        )

        # --- General Behavior Modifiers (Apply to most modes) ---
        jit_options.add_option(
            "--jit-correctness-testing",
            action="store_true",
            default=False,
            help="Enable 'Twin Execution' for supported patterns to find silent correctness bugs instead of just crashes.",
        )
        jit_options.add_option(
            "--jit-correctness-prob",
            type="float",
            default=0.2,
            help="Probability (0.0-1.0) of running a correctness test when correctness testing is enabled.",
        )
        jit_options.add_option(
            "--jit-loop-iterations",
            type="int",
            default=500,
            help="Number of iterations for JIT-warming hot loops.",
        )

        # --- Special-purpose legacy flag ---
        jit_options.add_option(
            "--rediscover-decref-crash",
            action="store_true",
            default=False,
            help="[legacy mode] Run the specific, hard-coded scenario to reproduce the GH-124483 decref bug.",
        )

        # --- New Strategy-Enabling Flag ---
        jit_options.add_option(
            "--jit-fuzz-classes",
            action="store_true",
            default=False,
            help="Enable the JIT class method fuzzer. This will occasionally generate scenarios that instantiate classes and call their methods in a hot loop.",
        )

        jit_options.add_option(
            "--jit-target-uop",
            help="Target a specific JIT micro-op (uop) for fuzzing. Provide the name "
            "of the uop (e.g., '_STORE_ATTR'). This will generate patterns "
            "specifically designed to stress that uop.",
            type="str",
            default=None,
        )

        jit_options.add_option(
            "--jit-feedback-driven-mode",
            help="Enable feedback-driven mode, mutating from the corpus.",
            action="store_true",
            default=False,
        )
        jit_options.add_option(
            "--source-output-path",
            help="Specify an exact output path for the generated source file.",
            type="str",
            default=None,
        )
        jit_options.add_option(
            "--stdout-path",
            help="Specify an exact output path for the process stdout/stderr.",
            type="str",
            default=None,
        )
        jit_options.add_option(
            "--no-jit-external-references",
            help="Prevent argument generators from creating references to boilerplate-defined names. Use for minimized corpus generation. (Default: allows references)",
            action="store_false",
            dest="jit_external_references",
            default=True,
        )

        oom_options = OptionGroupWithSections(parser, "OOM Fuzzing")
        oom_options.add_option(
            "--oom-fuzz",
            help="Enable OOM (out-of-memory) injection: wrap calls in dense "
            "_testcapi.set_nomemory sweeps to drive allocation-failure error "
            "paths and find crashes (default: False)",
            action="store_true",
            default=False,
        )
        oom_options.add_option(
            "--oom-max-start",
            help="Dense OOM sweep upper bound (exclusive): each call sweeps "
            "range(0, N) (default: 1000)",
            type="int",
            default=1000,
        )
        oom_options.add_option(
            "--oom-calls",
            help="Number of OOM-wrapped function calls to generate per script "
            "(replaces --functions-number in OOM mode, default: 10)",
            type="int",
            default=10,
        )
        oom_options.add_option(
            "--oom-classes",
            help="Number of classes to OOM-fuzz per script: each gets a constructor "
            "sweep plus method sweeps on a live instance (0 disables class "
            "fuzzing in OOM mode, default: 5)",
            type="int",
            default=5,
        )
        oom_options.add_option(
            "--oom-methods",
            help="Number of method sweeps to generate per OOM-fuzzed class instance (default: 5)",
            type="int",
            default=5,
        )
        oom_options.add_option(
            "--oom-seq",
            help="OOM mode (Phase 4): emit stateful call SEQUENCES -- several calls per "
            "scan under one bounded failure window -- so a failure in one call can "
            "corrupt state a later call trips over (default: disabled)",
            action="store_true",
            default=False,
        )
        oom_options.add_option(
            "--oom-seq-len",
            help="Steps (calls) per OOM sequence when --oom-seq is set (default: 3)",
            type="int",
            default=3,
        )
        oom_options.add_option(
            "--oom-window",
            help="OOM failure-burst width for sequences: set_nomemory(start, start+k) "
            "fails k allocations then resumes succeeding so later steps run on the "
            "damaged state (default: 1); 0 = fail forever (legacy single-call mode)",
            type="int",
            default=1,
        )
        oom_options.add_option(
            "--oom-verbose",
            help="In OOM mode, also print the sweep start index before each "
            "injection so the exact failing allocation can be pinpointed on "
            "replay (verbose output; default: False)",
            action="store_true",
            default=False,
        )
        oom_options.add_option(
            "--oom-dedup-catalog",
            help="Path to known_sites.tsv (cpython-oom-findings). Enables in-loop "
            "crash dedupe: label each crash dir with its matched bug id and, "
            "with --oom-dedup-prune, drop known duplicates (default: disabled)",
            type="str",
            default=None,
        )
        oom_options.add_option(
            "--oom-dedup-keep",
            help="Keep at most N sample directories per known bug (default: 5)",
            type="int",
            default=5,
        )
        oom_options.add_option(
            "--oom-dedup-prune",
            help="Remove known-duplicate crash dirs beyond the keep cap "
            "(default: keep all, label only)",
            action="store_true",
            default=False,
        )
        oom_options.add_option(
            "--oom-dedup-resolve-segv",
            help="Resolve segv/generic-assert crashes to their real site by re-running "
            "source.py under gdb (deterministic on the same binary), so they "
            "dedupe/label/prune like aborts instead of staying 'oomSEGV' "
            "(default: False; adds a bounded gdb run per unresolved crash)",
            action="store_true",
            default=False,
        )
        oom_options.add_option(
            "--oom-dedup-gdb-timeout",
            help="Per-crash gdb resolution timeout in seconds (default: 120)",
            type="int",
            default=120,
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

        options = (
            input_options,
            running_options,
            fuzzing_options,
            jit_options,
            oom_options,
            config_options,
        )
        for option in options:
            parser.add_option_group(option)

        # Add plugin CLI options
        plugin_opts = self.plugin_manager.get_cli_options()

        if plugin_opts:
            plugin_options_group = OptionGroupWithSections(parser, "Plugin Options")
            for args, kwargs in plugin_opts:
                plugin_options_group.add_option(*args, **kwargs)
            parser.add_option_group(plugin_options_group)

    def setupProject(self) -> None:
        """Initialize the fuzzing project with process monitoring and output analysis."""
        project = self.project
        if not self.project:
            project = self.project = Project(self)
        assert isinstance(project, Project)

        project.error(f"Start time: {time.asctime()}")
        project.error("Use python interpreter: %s" % self.options.python)
        version = " -- ".join(line.strip() for line in sys.version.splitlines())
        project.error("Python version: %s" % version)
        self.source = PythonSource(
            project, self.options, source_output_path=self.options.source_output_path
        )
        process = PythonProcess(
            project,
            self.options,
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

        # In OOM mode, MemoryError is the expected (boring) outcome of injection,
        # so it must not abort the session; real crashes still score via signal.
        if self.options.oom_fuzz:
            stdout.kill_words = {"mimalloc"}
        else:
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

        # In-loop OOM crash dedupe: install a keep-policy that SessionDirectory
        # consults for each crashing session (label dirs, optionally prune known dups).
        self._deduper = None
        if self.options.oom_dedup_catalog:
            from fusil.python.oom_dedup import Deduper

            self._deduper = Deduper(
                self.options.oom_dedup_catalog,
                keep=self.options.oom_dedup_keep,
                prune=self.options.oom_dedup_prune,
                python_bin=self.options.python,
                gdb_timeout=self.options.oom_dedup_gdb_timeout,
                resolve_segv=self.options.oom_dedup_resolve_segv,
                # Drop the gdb segv re-run to the same unprivileged user the fuzzing
                # children use, so the fuzzed source.py is never replayed as root.
                drop_uid=self.config.process_uid,
                drop_gid=self.config.process_gid,
            )
            self.session_keep_policy = self._oom_keep_policy
            project.error(
                "OOM dedupe enabled: %s (keep=%d, prune=%s, resolve_segv=%s)"
                % (
                    self.options.oom_dedup_catalog,
                    self.options.oom_dedup_keep,
                    self.options.oom_dedup_prune,
                    self.options.oom_dedup_resolve_segv,
                )
            )

    def _oom_keep_policy(self, session):
        """Return (keep, label) for a crashed session from its captured stdout.

        Consulted synchronously by SessionDirectory.checkKeepDirectory, where the
        stdout file is already complete. Returns (True, None) on any error so a crash
        is never lost to a dedupe failure.
        """
        import os

        session_dir = session.directory.directory
        try:
            with open(os.path.join(session_dir, "stdout"), errors="replace") as fh:
                text = fh.read()
        except OSError:
            return True, None
        return self._deduper.decide(text, source_path=os.path.join(session_dir, "source.py"))

    def exit(self, keep_log: bool = True) -> None:
        """Clean up and exit the fuzzer, printing runtime statistics."""
        super().exit(keep_log=keep_log)
        if getattr(self, "_deduper", None):
            self.error(self._deduper.report())
        self.error(print_running_time(time_start))


class PythonProcess(CreateProcess):
    """Handles the execution of generated Python test code."""

    def on_python_source(self, filename: str) -> None:
        """Execute the generated Python source file."""
        self.cmdline.arguments[-1] = filename
        if self.options.only_generate:
            self.error("Only generating Python source, skipping running it.")
            self.application().exit()
            self.destroy()
            sys.exit(0)
        self.createProcess()


def main() -> None:
    """Console-script entry point for ``fusil-python-threaded``."""
    remove_logging_pycache()
    Fuzzer().main()
