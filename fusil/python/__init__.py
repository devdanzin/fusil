from __future__ import annotations

import sys
import time
import warnings
from optparse import OptionGroup, OptionParser

# python-ptrace (imported transitively below) emits deprecation warnings on
# recent Python versions; hide them while importing the fusil runtime stack.
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import fusil.python.tricky_weird  # noqa: F401  (imported here to suppress its import warnings)
    from fusil.application import Application
    from fusil.process.create import CreateProcess
    from fusil.process.stdout import WatchStdout
    from fusil.process.watch import WatchProcess
    from fusil.project import Project
    from fusil.python.python_source import PythonSource
    from fusil.python.utils import print_running_time
    from fusil.python.write_python_code import time_start

IGNORE_TIMEOUT = True
IGNORE_CPU = True
SHOW_STDOUT = False
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

    def createFuzzerOptions(self, parser: OptionParser) -> None:
        """Create command-line options for the fuzzer configuration."""
        input_options = OptionGroup(parser, "Input")
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
        running_options = OptionGroup(parser, "Running")
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
        running_options.add_option(
            "--suppress-hit-regex",
            help="Drop a crashing-session hit whose stdout matches this regex (re.search), "
            "the way troublesome/known crashes are deduplicated by hand. Repeatable; "
            "composes with --suppress-hit-file and plugin rules (default: none)",
            action="append",
            dest="suppress_hit_regex",
            default=None,
        )
        running_options.add_option(
            "--suppress-hit-file",
            help="Read hit-suppression regexes from FILE (one per line; '#' comments; an "
            "optional reason after ' ## '). Repeatable; composes with --suppress-hit-regex "
            "(default: none)",
            action="append",
            dest="suppress_hit_file",
            default=None,
        )
        running_options.add_option(
            "--suppress-hit-ignore-case",
            help="Match --suppress-hit-regex / --suppress-hit-file patterns "
            "case-insensitively (default: False)",
            action="store_true",
            default=False,
        )
        fuzzing_options = OptionGroup(parser, "Fuzzing")
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
            "--gc-aggressive",
            help="Emit gc.set_threshold(1, 1, 1) at the top of the generated script, forcing a "
            "gen-0 collection on ~every allocation (surfaces GC-during-partial-init crashes); "
            "off by default",
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
        # NOTE: the JIT-fuzzing subsystem (the "JIT Fuzzing" option group + fusil/python/jit/)
        # was removed once lafleur took over JIT fuzzing natively (see doc/jit-decision-memo.md).
        # These three options outlived it -- they are general output / argument-generation knobs
        # that were historically grouped under it -- so they move to the general Fuzzing group.
        fuzzing_options.add_option(
            "--source-output-path",
            help="Specify an exact output path for the generated source file.",
            type="str",
            default=None,
        )
        fuzzing_options.add_option(
            "--stdout-path",
            help="Specify an exact output path for the process stdout/stderr.",
            type="str",
            default=None,
        )
        fuzzing_options.add_option(
            "--no-external-references",
            help="Prevent argument generators from creating references to boilerplate-defined names. Use for minimized corpus generation. (Default: allows references)",
            action="store_false",
            dest="external_references",
            default=True,
        )

        oom_options = OptionGroup(parser, "OOM Fuzzing")
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
            "range(--oom-start-min, N) (default: 1000)",
            type="int",
            default=1000,
        )
        oom_options.add_option(
            "--oom-start-min",
            help="Dense OOM sweep lower bound (inclusive): each call sweeps "
            "range(M, --oom-max-start) instead of range(0, ...). Skips shallow "
            "failure points, and (with a small window below --oom-max-start) enables "
            "fast targeted replay of a known crash near its trigger start (default: 0)",
            type="int",
            default=0,
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
            "--oom-seq-randomize",
            help="Randomize each emitted sequence's length (in [1, --oom-seq-len]) and "
            "failure window (in [1, --oom-window]) independently, so one instance covers a "
            "range of sequence shapes instead of a single static config. The --oom-seq-len / "
            "--oom-window values become the upper bounds (default: off)",
            action="store_true",
            default=False,
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
        oom_options.add_option(
            "--oom-foreign",
            help="Inject allocation failures at the C malloc() layer via an LD_PRELOAD shim "
            "(instead of _testcapi.set_nomemory), reaching FOREIGN C-library allocations "
            "(HDF5, zstd, libxml2, ...) that set_nomemory can't. Composes with --oom-fuzz "
            "(reuses the same sweep); needs a C compiler. Default: False",
            action="store_true",
            default=False,
        )
        oom_options.add_option(
            "--oom-foreign-pythonmalloc",
            help="With --oom-foreign, also set PYTHONMALLOC=malloc so CPython's own "
            "allocations route through the shim too (superset of set_nomemory + foreign; "
            "noisier). Default: False (leave pymalloc on, target foreign/large allocs)",
            action="store_true",
            default=False,
        )

        tsan_options = OptionGroup(parser, "TSan Fuzzing")
        tsan_options.add_option(
            "--tsan",
            help="Enable ThreadSanitizer concurrency-stress mode: generate code that hammers "
            "SHARED objects from many threads at once to surface C-level data races. Requires "
            "a free-threaded, --with-thread-sanitizer target interpreter (see --python) run "
            "under disabled ASLR (fusil wraps it in `setarch -R`). Mutually exclusive with "
            "--oom-fuzz/--oom-foreign. Default: False",
            action="store_true",
            default=False,
        )
        tsan_options.add_option(
            "--tsan-threads",
            help="Worker threads per shared object in the stress region (>=2 so each shared "
            "object is hit concurrently). Default: 4",
            type="int",
            default=4,
        )
        tsan_options.add_option(
            "--tsan-iterations",
            help="Op iterations each worker runs over its shared object (repetition = race "
            "manifestation). Default: 200",
            type="int",
            default=200,
        )
        tsan_options.add_option(
            "--tsan-shared-objects",
            help="How many module objects are instantiated and shared across workers. Default: 3",
            type="int",
            default=3,
        )
        tsan_options.add_option(
            "--tsan-suppressions",
            help="Path to a ThreadSanitizer suppressions file (passed to the target via "
            "TSAN_OPTIONS=suppressions=..., and honoured post-hoc by --tsan-dedup-catalog). "
            "Default: none (CPython's suppressions_free_threading.txt is currently empty, so "
            "core races are in scope).",
            type="str",
            default=None,
        )
        tsan_options.add_option(
            "--tsan-dedup-catalog",
            help="Path to a known_races.tsv snapshot (from the cpython-tsan-findings catalog). "
            "In-loop dedupe: each detected race is reduced to its site-pair signature, labelled "
            "with its race id (or tsanNEW / tsanFRAME), and -- with --tsan-dedup-prune -- known "
            "duplicates past --tsan-dedup-keep are dropped. Default: none (label-only, keep all).",
            type="str",
            default=None,
        )
        tsan_options.add_option(
            "--tsan-dedup-keep",
            help="With --tsan-dedup-prune, keep at most N dirs per known race (default: 5)",
            type="int",
            default=5,
        )
        tsan_options.add_option(
            "--tsan-dedup-prune",
            help="Drop known-race duplicate crash dirs past --tsan-dedup-keep (default: False)",
            action="store_true",
            default=False,
        )

        options = (
            input_options,
            running_options,
            fuzzing_options,
            oom_options,
            tsan_options,
        )
        for option in options:
            parser.add_option_group(option)

        # Add plugin CLI options
        plugin_opts = self.plugin_manager.get_cli_options()

        if plugin_opts:
            plugin_options_group = OptionGroup(parser, "Plugin Options")
            for args, kwargs in plugin_opts:
                plugin_options_group.add_option(*args, **kwargs)
            parser.add_option_group(plugin_options_group)

    def setupProject(self) -> None:
        """Initialize the fuzzing project with process monitoring and output analysis."""
        # --oom-foreign reuses the whole OOM harness (oom_call/oom_run sweep), just with the
        # LD_PRELOAD malloc shim as the arming backend instead of _testcapi.set_nomemory.
        if self.options.oom_foreign:
            self.options.oom_fuzz = True

        # Each OOM sweep is range(--oom-start-min, --oom-max-start); an empty range would make
        # every oom_call/oom_run a silent no-op (labels printed, no injection). Fail fast rather
        # than run a useless campaign -- e.g. `--oom-start-min 30` with the default max-start is
        # fine, but `--oom-start-min 30 --oom-max-start 30` injects nothing.
        if self.options.oom_fuzz and self.options.oom_start_min >= self.options.oom_max_start:
            raise ValueError(
                "--oom-start-min (%d) must be < --oom-max-start (%d); the sweep range "
                "range(min, max) would otherwise be empty and inject nothing"
                % (self.options.oom_start_min, self.options.oom_max_start)
            )

        # --tsan is a different failure class (data races) on a different build (free-threaded +
        # ThreadSanitizer) and cannot share a run with OOM injection: the _testcapi.set_nomemory
        # allocator swap is itself thread-unsafe (the documented _thread-*-oomNEW harness race), so
        # combining them just manufactures harness races. Fail fast.
        if self.options.tsan and (self.options.oom_fuzz or self.options.oom_foreign):
            raise ValueError(
                "--tsan is mutually exclusive with --oom-fuzz/--oom-foreign (the set_nomemory "
                "allocator swap is not thread-safe; combining them races the harness itself)"
            )

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
        # Score-neutral observer: fold each finished session into the run dir's
        # fusil_stats.json sidecar (read back by `fleet report`). Parent-side only; does not
        # override getScore(), so it never affects scoring or the generated source.
        from fusil.python.stats_agent import StatsAgent

        StatsAgent(project, self.source)
        # Under --tsan the target MUST run with ASLR disabled: ThreadSanitizer's shadow-memory
        # layout is incompatible with modern high-entropy ASLR ("memory layout is incompatible"
        # -> it silently detects nothing). `setarch -R` (ADDR_NO_RANDOMIZE) is a thin exec wrapper
        # -- it sets the personality then execs the target, so the PID (and thus process
        # monitoring) is unaffected. Keeping the source file last preserves on_python_source's
        # `arguments[-1] = filename` substitution.
        target_cmd = [self.options.python, "-u", "<source.py>"]
        if self.options.tsan:
            target_cmd = ["setarch", "-R"] + target_cmd
        process = PythonProcess(
            project,
            self.options,
            target_cmd,
            timeout=self.options.timeout,
        )
        # ThreadSanitizer reserves more virtual address space than any finite RLIMIT_AS allows and
        # re-execs itself to raise the cap; a finite hard cap makes that re-exec fail (setrlimit
        # EINVAL) and TSan then runs DEGRADED, detecting nothing. So leave the cap OFF under --tsan
        # -- CreateProcess already zeroed max_memory for it, and limitResources resets RLIMIT_AS to
        # unlimited. (This ~4 PiB cap is fine for ASan, which fits within it.)
        if not self.options.tsan:
            process.max_memory = 4000 * 1024 * 1024 * 1024 * 1024

        # Foreign-allocator OOM: preload the malloc-failure shim so the generated harness can
        # inject failures at the C malloc() layer (reaching foreign C libraries). Fail fast if
        # requested but unbuildable -- the user asked for it and needs a working compiler.
        if self.options.oom_foreign:
            from fusil.python.foreign_oom import (
                ShimShadowedError,
                get_shim_path,
                probe_shim_effective,
            )

            shim = get_shim_path()
            process.env.set("LD_PRELOAD", shim)
            self.error("Foreign-OOM: LD_PRELOAD=%s" % shim)
            # Fail fast if the shim is loaded but doesn't actually intercept the target's
            # malloc (e.g. a statically-linked ASan build shadows it) -- otherwise the whole
            # run silently injects nothing. `None` (couldn't verify) is non-fatal.
            effective = probe_shim_effective(self.options.python, shim)
            if effective is False:
                raise ShimShadowedError(
                    "--oom-foreign: the malloc shim is preloaded but does NOT intercept "
                    "allocations in the target interpreter (%s) -- allocations bypass it, so "
                    "NO failures would be injected. The usual cause is a statically-linked "
                    "AddressSanitizer target whose own malloc shadows the LD_PRELOAD shim. Use "
                    "a non-ASan target, or rebuild with -shared-libasan and set "
                    "ASAN_OPTIONS=verify_asan_link_order=0. Aborting rather than running a "
                    "no-op OOM campaign." % self.options.python
                )
            if effective:
                self.error("Foreign-OOM: shim interception verified on %s" % self.options.python)
            if self.options.oom_foreign_pythonmalloc:
                process.env.set("PYTHONMALLOC", "malloc")
                self.error("Foreign-OOM: PYTHONMALLOC=malloc (CPython allocs route through shim)")

        # ThreadSanitizer mode: verify the target build and set the child environment. Fail fast if
        # the interpreter is not free-threaded + TSan-instrumented -- otherwise the whole run
        # silently finds nothing (mirrors the --oom-foreign shim-shadow self-check).
        if self.options.tsan:
            import os
            import subprocess

            probe = (
                "import sys, sysconfig; ca = sysconfig.get_config_var('CONFIG_ARGS') or ''; "
                "print(int(not sys._is_gil_enabled()), int('thread-sanitizer' in ca))"
            )
            try:
                out = subprocess.run(
                    [self.options.python, "-c", probe],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env={**os.environ, "PYTHON_GIL": "0"},
                ).stdout.split()
            except (OSError, subprocess.SubprocessError, ValueError):
                out = []
            free_threaded = out[:1] == ["1"]
            thread_sanitizer = out[1:2] == ["1"]
            if not (free_threaded and thread_sanitizer):
                raise ValueError(
                    "--tsan requires a free-threaded, --with-thread-sanitizer interpreter as "
                    "--python (probed free_threaded=%s thread_sanitizer=%s for %s). Build CPython "
                    "with `--disable-gil --with-thread-sanitizer` and point --python at it."
                    % (free_threaded, thread_sanitizer, self.options.python)
                )
            # symbolize=1: the "symbolizer hang" was NOT a TSan/build fault -- llvm-symbolizer
            # honours DEBUGINFOD_URLS (Ubuntu sets it to debuginfod.ubuntu.com in every login
            # shell) and blocks ~forever on that currently-blackholed endpoint. With it cleared in
            # the child (below), symbolization returns in ~0.3s with full file:line frames -- worth
            # having in-loop, since the racing site then lands in the crash dir for triage/dedup.
            # halt_on_error=1/exitcode=66: stop at the first race with a clean exit.
            tsan_opts = ["halt_on_error=1", "symbolize=1", "exitcode=66", "history_size=4"]
            if self.options.tsan_suppressions:
                tsan_opts.append("suppressions=%s" % self.options.tsan_suppressions)
            process.env.set("TSAN_OPTIONS", ":".join(tsan_opts))
            process.env.set("PYTHON_GIL", "0")
            # Clear DEBUGINFOD_URLS so llvm-symbolizer resolves frames from the target's own (full)
            # debug info instead of blocking on the unreachable Ubuntu debuginfod server. fusil's
            # child env is minimal and does not copy DEBUGINFOD_URLS, but set it empty explicitly so
            # symbolization stays fast regardless of how the parent env is configured.
            process.env.set("DEBUGINFOD_URLS", "")
            self.error(
                "TSan: target verified free-threaded + ThreadSanitizer; ASLR disabled via "
                "`setarch -R`; TSAN_OPTIONS=%s" % ":".join(tsan_opts)
            )

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

        # fusil's own hostile-object machinery deliberately raises exceptions (SystemError
        # among them) from injected bomb/weird objects -- that is the harness testing that
        # the TARGET propagates hostile exceptions, not a target crash. Ignore our own
        # synthetic signatures so a caught+printed SystemError neither ends the session
        # early (FileWatch stops the moment the score reaches 1.0, and "SystemError" is a
        # 1.0 word) nor keeps the session as noise; a genuine target-raised SystemError
        # (different text) still scores. Plugins add their own synthetic signatures via
        # PluginManager.add_stdout_ignore_regex (e.g. the cereggii plugin's raise_SystemError).
        core_ignore_regexes = (
            # The whole bomb-message family from fusil/python/samples/bomb_objects.py: any of
            # these is the injected object's own exception text, never a target crash.
            r"fusil (bomb|iter bomb|superbomb|fileno bomb|hidden name|descriptor (get|set)"
            r"|stateful hash)",
        )
        for ignore_pattern in core_ignore_regexes + tuple(
            self.plugin_manager.get_stdout_ignore_regexes()
        ):
            stdout.ignoreRegex(ignore_pattern)

        # CPython critical messages
        stdout.addRegex("^XXX undetected error", 1.0)
        stdout.addRegex("Fatal Python error", 1.0)
        # Match "Cannot allocate memory"?

        # ThreadSanitizer data-race report (--tsan). The `WARNING:` header is printed before the
        # (possibly unsymbolized) frames, so this scores the session even with symbolize=0. Added
        # unconditionally: it only matches when a TSan-instrumented target actually reports a race.
        stdout.addRegex("WARNING: ThreadSanitizer: data race", 1.0)

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

        # TSan race dedupe (Phase 2): the --tsan analogue of the OOM catalog dedupe above. Reduce
        # each detected data race to its site-pair signature, label the crash dir with its race id
        # (or tsanNEW / tsanFRAME), and optionally prune known duplicates past the sample cap. Only
        # under --tsan (mutually exclusive with --oom-*, so it never coexists with the OOM deduper).
        self._tsan_deduper = None
        if self.options.tsan and self.options.tsan_dedup_catalog:
            from fusil.python.tsan_dedup import TSanDeduper

            self._tsan_deduper = TSanDeduper(
                self.options.tsan_dedup_catalog,
                keep=self.options.tsan_dedup_keep,
                prune=self.options.tsan_dedup_prune,
                suppressions_path=self.options.tsan_suppressions,
            )
            self.session_keep_policy = self._tsan_keep_policy
            project.error(
                "TSan dedupe enabled: %s (keep=%d, prune=%s)"
                % (
                    self.options.tsan_dedup_catalog,
                    self.options.tsan_dedup_keep,
                    self.options.tsan_dedup_prune,
                )
            )

        # Regex hit suppression (issue #53): drop known/uninteresting crashing-session hits
        # whose stdout matches a user- or plugin-supplied regex -- the general/non-OOM analogue
        # of the OOM-catalog dedupe above. Composes with it: suppression runs first (a matched
        # hit is pruned even if the OOM deduper would keep it); otherwise the previously-installed
        # policy (if any -- OOM or TSan dedupe) still decides.
        self._hit_suppressor = None
        suppress_regexes = self.options.suppress_hit_regex or []
        suppress_files = self.options.suppress_hit_file or []
        plugin_suppressions = self.plugin_manager.get_suppression_entries()
        if suppress_regexes or suppress_files or plugin_suppressions:
            from fusil.python.hit_suppression import build_suppressor

            self._hit_suppressor = build_suppressor(
                regexes=suppress_regexes,
                files=suppress_files,
                plugin_entries=plugin_suppressions,
                ignore_case=self.options.suppress_hit_ignore_case,
            )
            self._suppression_prev_policy = getattr(self, "session_keep_policy", None)
            self.session_keep_policy = self._suppression_keep_policy
            project.error(
                "Hit suppression enabled: %d rule(s) (%d CLI, %d file(s), %d plugin)"
                % (
                    len(self._hit_suppressor.rules),
                    len(suppress_regexes),
                    len(suppress_files),
                    len(plugin_suppressions),
                )
            )

    def _suppression_keep_policy(self, session):
        """Return (keep, label): drop a crashed session whose stdout matches a suppression
        regex (issue #53), else defer to the previously-installed policy (e.g. OOM dedupe).

        Consulted synchronously by SessionDirectory.checkKeepDirectory, where the stdout file
        is already complete. Returns (True, None) on any error so a crash is never lost to a
        suppression failure.
        """
        import os

        session_dir = session.directory.directory
        try:
            from fusil.python.oom_dedup import read_crash_stdout

            # Bounded read: a crashing session's stdout can be tens of MB; reading it whole
            # would make the suppression regexes backtrack catastrophically in this
            # synchronous keep-policy (runs in deinit).
            text = read_crash_stdout(os.path.join(session_dir, "stdout"))
            keep, rule = self._hit_suppressor.decide(text)
            if not keep:
                reason = " (%s)" % rule.reason if rule.reason else ""
                self.error(
                    "Hit suppressed by regex %r%s: prune %s" % (rule.pattern, reason, session_dir)
                )
                return False, None
        except Exception as err:
            self.error("Hit suppression failed (%s); keeping crash dir" % err)
            return True, None
        # Not suppressed: defer to the previous keep-policy (e.g. OOM dedupe) if one exists.
        prev = getattr(self, "_suppression_prev_policy", None)
        if prev is not None:
            return prev(session)
        return True, None

    def _oom_keep_policy(self, session):
        """Return (keep, label) for a crashed session from its captured stdout.

        Consulted synchronously by SessionDirectory.checkKeepDirectory, where the
        stdout file is already complete. Returns (True, None) on any error so a crash
        is never lost to a dedupe failure.
        """
        import os

        session_dir = session.directory.directory
        try:
            from fusil.python.oom_dedup import read_crash_stdout

            # Bounded read: a crashing session's stdout can be tens of MB (OOM-verbose spew /
            # runaway vehicle); reading it whole would make decide()'s regexes backtrack
            # catastrophically and stall this keep-policy (it runs synchronously in deinit).
            text = read_crash_stdout(os.path.join(session_dir, "stdout"))
            return self._deduper.decide(text, source_path=os.path.join(session_dir, "source.py"))
        except Exception as err:
            # Never let a dedupe failure abort the session's keep/rename (deinit): keep the
            # crash dir unlabelled rather than lose it. (decide() resolves segvs via gdb, whose
            # captured output can be binary -- a past UnicodeDecodeError here left crash dirs
            # stuck as session-NNNN instead of renamed.)
            self.error("OOM keep-policy failed (%s); keeping crash dir unlabelled" % err)
            return True, None

    def _tsan_keep_policy(self, session):
        """Return (keep, label) for a crashed --tsan session from its captured stdout: reduce the
        ThreadSanitizer report to its race signature, then label / prune via the catalog.

        Consulted synchronously by SessionDirectory.checkKeepDirectory (stdout is complete).
        Returns (True, None) on any error so a race is never lost to a dedupe failure.
        """
        import os

        session_dir = session.directory.directory
        try:
            from fusil.python.tsan_dedup import read_crash_stdout

            text = read_crash_stdout(os.path.join(session_dir, "stdout"))
            return self._tsan_deduper.decide(text)
        except Exception as err:
            self.error("TSan keep-policy failed (%s); keeping crash dir unlabelled" % err)
            return True, None

    def exit(self, keep_log: bool = True) -> None:
        """Clean up and exit the fuzzer, printing runtime statistics."""
        super().exit(keep_log=keep_log)
        if getattr(self, "_deduper", None):
            self.error(self._deduper.report())
        if getattr(self, "_tsan_deduper", None):
            self.error(self._tsan_deduper.report())
        if getattr(self, "_hit_suppressor", None):
            self.error(self._hit_suppressor.report())
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
    Fuzzer().main()
