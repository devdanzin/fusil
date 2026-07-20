from __future__ import annotations

import os
import sys
import time
from os.path import exists as path_exists
from os.path import isabs
from random import choice
from types import ModuleType

from fusil.config import FusilConfig
from fusil.project import Project
from fusil.project_agent import ProjectAgent
from fusil.python.blacklists import MODULE_BLACKLIST
from fusil.python.fixtures import ensure_fixture_files
from fusil.python.list_all_modules import ListAllModules
from fusil.python.utils import print_running_time
from fusil.python.write_python_code import WritePythonCode

time_start = time.time()


class PythonSource(ProjectAgent):
    """Manages module discovery, loading, and Python source code generation."""

    def __init__(
        self,
        project: Project,
        options: FusilConfig,
        source_output_path: str | None = None,
        module_lister_factory=None,
        write_code_factory=None,
    ):
        ProjectAgent.__init__(self, project, "python_source")
        self.module: ModuleType | None = None
        self.module_name = ""
        # Slice B: the --tsan shared-object composition of the last-generated session, read back
        # by StatsAgent for per-session attribution (None outside --tsan). Set in on_session_start.
        self.tsan_shared_kind: str | None = None
        self.write: WritePythonCode | None = None
        self.filename = ""
        self.options = options
        self.source_output_path = source_output_path

        # Factories for the two heavyweight collaborators, injectable for testing. Both default
        # to None and resolve to the real class at the use site (staying monkeypatchable):
        #   - module_lister_factory builds the module discoverer (ListAllModules), which scans
        #     the whole importable module set in its search_modules()/discover_modules().
        #   - write_code_factory builds the per-module code generator (WritePythonCode) in
        #     loadModule(). None -> the module-global classes.
        self.module_lister_factory = module_lister_factory
        self.write_code_factory = write_code_factory
        lister_factory = self.module_lister_factory or ListAllModules

        self.plugin_manager = None
        if hasattr(project.application(), "plugin_manager"):
            self.plugin_manager = project.application().plugin_manager

        modules_file = getattr(self.options, "modules_file", None)
        if self.options.modules != "*" or modules_file:
            # Explicit module set: --modules literal and/or --modules-file, bypassing
            # discovery/blacklists. Unioned so a curated file can be augmented on the CLI.
            self.modules = set()
            if self.options.modules != "*":
                for module in self.options.modules.split(","):
                    module = module.strip()
                    if not len(module):
                        continue
                    self.modules.add(module)
            if modules_file:
                with open(modules_file) as module_file_handle:
                    for line in module_file_handle:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        self.modules.add(line)
        else:
            self.error("Search all Python modules...")
            self.modules = lister_factory(
                self,
                self.options.only_c,
                not self.options.no_site_packages,
                MODULE_BLACKLIST | set(name for name in self.options.blacklist.split(",") if name),
                self.options.skip_test,
                verbose=self.options.verbose,
            ).search_modules()

        if self.options.packages != "*":
            self.info("Adding packages...")
            all_modules = lister_factory(
                self,
                self.options.only_c,
                not self.options.no_site_packages,
                MODULE_BLACKLIST | set(name for name in self.options.blacklist.split(",") if name),
                self.options.skip_test,
                verbose=self.options.verbose,
            )

            packages = self.options.packages.split(",")

            for package in packages:
                package = package.strip().strip("/")
                if not len(package):
                    continue
                pack = __import__(package)
                path = pack.__path__[0]
                self.info("Adding package: %s (%s)" % (package, path))
                package_walker = all_modules.discover_modules([path], package + ".")
                self.modules |= set(name for finder, name, ispgk in package_walker)

            self.info(
                "Known modules (%d): %s" % (len(self.modules), ",".join(sorted(self.modules)))
            )

        blacklist_str = self.options.blacklist
        if blacklist_str:
            blacklist = set(blacklist_str.split(","))
            removed = self.modules & blacklist
            self.error("Blacklist modules: %s" % removed)
            self.modules = self.modules - blacklist
        self.modules_list = list(self.modules)
        self.modules_list.sort()
        self.error("Found %s Python modules" % len(self.modules_list))
        for name in self.modules_list:
            self.info("Python module: %s" % name)

        if self.options.filenames:
            # User-supplied paths. WARNING: a fuzzed call may open these for writing,
            # so only ever pass expendable files here.
            self.filenames = self.options.filenames.split(",")
        else:
            # Default: auto-created, read-only, throwaway fixture files. Never default to
            # real system files (the historical /etc/machine-id,/bin/sh default could be
            # clobbered when a fuzzed call wrote to them as root).
            self.filenames = ensure_fixture_files()
        for filename in self.filenames:
            if not isabs(filename):
                raise ValueError(
                    "Filename %r is not an absolute path! Fix the --filenames option" % filename
                )
            if not path_exists(filename):
                raise ValueError(
                    "File doesn't exist: %s! Use different --filenames option" % filename
                )
        project.error("Use filenames: %s" % ", ".join(self.filenames))
        self.error(print_running_time(time_start))

    def loadModule(self, module_name: str) -> None:
        """Load a specific module and prepare it for fuzzing."""
        self.module_name = module_name
        self.debug("Import %s" % self.module_name)
        self.module = __import__(self.module_name)

        for name in self.module_name.split(".")[1:]:
            self.module = getattr(self.module, name)
        assert isinstance(self.module, ModuleType)

        try:
            self.warning("Module filename: %s" % self.module.__file__)
        except AttributeError:
            pass

        write_code_factory = self.write_code_factory or WritePythonCode
        self.write = write_code_factory(
            self,
            self.filename,
            self.module,
            self.module_name,
            # --tsan / --concurrency-stress replace the per-call one-thread-per-callsite wrappers
            # with a concentrated concurrency-stress region (WritePythonCode.
            # _write_tsan_stress_region), so disable them here -- otherwise they would dilute the
            # stress and double-run every call.
            threads=(not self.options.no_threads)
            and not (self.options.tsan or getattr(self.options, "concurrency_stress", False)),
            _async=(not self.options.no_async)
            and not (self.options.tsan or getattr(self.options, "concurrency_stress", False)),
            plugin_manager=self.plugin_manager,
        )

    def _thread_flags(self) -> tuple[bool, bool]:
        """(threads, async) for the writer -- disabled under --tsan/--concurrency-stress (which
        replace the per-call wrappers with the concentrated stress region)."""
        stress = self.options.tsan or getattr(self.options, "concurrency_stress", False)
        return (
            (not self.options.no_threads) and not stress,
            (not self.options.no_async) and not stress,
        )

    def _target_discovery_env(self) -> dict:
        """Minimal env for the discovery subprocess running the TARGET interpreter. Inherits the
        current env (so a fleet's exported PYTHON_GIL etc. carry over) + the pycache/debuginfod
        overrides fusil already uses for target children, and forces PYTHON_GIL=0 under --tsan."""
        env = dict(os.environ)
        env["PYTHONPYCACHEPREFIX"] = "/tmp/fusil-pycache-root"
        env["DEBUGINFOD_URLS"] = ""  # dodge the llvm-symbolizer debuginfod hang; harmless otherwise
        if getattr(self.options, "tsan", False):
            env["PYTHON_GIL"] = "0"
        return env

    def discoverInTarget(self, module_name: str) -> bool:
        """Discover a module's members by introspecting it in a subprocess running the TARGET
        interpreter (``--discover-in-target``), so the runner venv need not have the extension
        installed. Sets up ``self.write`` from the returned metadata and returns True; returns
        False if the subprocess failed (import error / timeout / bad output) so the caller skips
        the module -- the same disposition as a failed runner import."""
        from fusil.python.target_introspect import introspect_module

        self.module_name = module_name
        self.module = None
        timeout = int(getattr(self.options, "discover_timeout", 60))
        metadata = introspect_module(
            self.options.python, module_name, env=self._target_discovery_env(), timeout=timeout
        )
        if metadata is None:
            return False
        threads, _async = self._thread_flags()
        write_code_factory = self.write_code_factory or WritePythonCode
        self.write = write_code_factory(
            self,
            self.filename,
            None,  # no live module: generation reads member_metadata via _MetaProxy
            module_name,
            threads=threads,
            _async=_async,
            plugin_manager=self.plugin_manager,
            member_metadata=metadata,
        )
        return True

    def on_session_start(self) -> None:
        """Start a new fuzzing session by selecting a module and generating test code."""
        if self.source_output_path:
            self.filename = self.source_output_path
        else:
            self.filename = self.session().createFilename("source.py")

        # copy sys.modules
        old_sys_modules = sys.modules.copy()

        name = "NO_MODULES!"
        discover_in_target = getattr(self.options, "discover_in_target", False)
        while self.modules_list:
            name = choice(self.modules_list)
            try:
                if discover_in_target:
                    # Introspect in a subprocess running the target interpreter (runner needn't
                    # have the extension). A failed subprocess is an unloadable module.
                    if not self.discoverInTarget(name):
                        raise ImportError("target-subprocess discovery failed for %s" % name)
                else:
                    self.loadModule(name)
                break
            except (Exception, SystemExit) as err:
                # Catch Exception plus SystemExit: a module that runs argparse/optparse on
                # sys.argv or calls sys.exit() at import time (seeing fusil's own flags) raises
                # SystemExit, which would otherwise propagate straight through the fuzzer and
                # kill it (clean exit code 2, "Project done", systemd restart). Treat it as an
                # unloadable module instead. A real KeyboardInterrupt is BaseException but
                # neither Exception nor SystemExit, so it still propagates and stops the run.
                self.error(
                    "Unable to load module %s: [%s] %s" % (name, err.__class__.__name__, err)
                )
                self.modules_list.remove(name)
        if not self.modules_list:
            self.error("There are no more modules!")
            self.send("project_stop")
            return
        self.error("Test module %s" % name)
        self.error(print_running_time(time_start))
        self.send("session_rename", name)

        # Narrow the Optional for type-checkers and guard against a missing generator; after a
        # successful loadModule this is a WritePythonCode (or an injected test double), never None.
        assert self.write is not None
        self.write.generate_fuzzing_script()
        # Slice B: expose this session's --tsan shared-object composition for StatsAgent to
        # attribute (None outside --tsan, where the emitter never set it).
        self.tsan_shared_kind = getattr(self.write, "tsan_shared_kind", None)
        self.send("python_source", self.filename)

        # unload new modules
        sys.modules.clear()
        sys.modules.update(old_sys_modules)
