from __future__ import annotations

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
from fusil.python.list_all_modules import ListAllModules
from fusil.python.utils import print_running_time
from fusil.python.write_python_code import WritePythonCode

time_start = time.time()


class PythonSource(ProjectAgent):
    """Manages module discovery, loading, and Python source code generation."""

    def __init__(self, project: Project, options: FusilConfig, source_output_path: str | None = None):
        ProjectAgent.__init__(self, project, "python_source")
        self.module: ModuleType | None = None
        self.module_name = ""
        self.write: WritePythonCode | None = None
        self.filename = ""
        self.options = options
        self.source_output_path = source_output_path

        self.plugin_manager = None
        if hasattr(project.application(), 'plugin_manager'):
            self.plugin_manager = project.application().plugin_manager

        if self.options.modules != "*":
            self.modules = set()
            for module in self.options.modules.split(","):
                module = module.strip()
                if not len(module):
                    continue
                self.modules.add(module)
        else:
            self.error("Search all Python modules...")
            self.modules = ListAllModules(
                self,
                self.options.only_c,
                not self.options.no_site_packages,
                MODULE_BLACKLIST | set(name for name in self.options.blacklist.split(",") if name),
                self.options.skip_test,
                verbose=self.options.verbose,
            ).search_modules()

        if self.options.fuzz_cereggii_scenarios:
            self.error("Cereggii Scenario Mode: Forcing target module to 'cereggii'.")

            self.modules = {'cereggii'}

        if self.options.packages != "*":
            print("\nAdding packages...")
            all_modules = ListAllModules(
                self,
                self.options.only_c,
                not self.options.no_site_packages,
                MODULE_BLACKLIST | set(name for name in self.options.blacklist.split(",") if name),
                self.options.skip_test,
                verbose=self.options.verbose,
            )

            packages = self.options.packages.split(",")
            if self.options.fuzz_cereggii_scenarios:
                self.error("Cereggii Scenario Mode: Forcing packages to 'cereggii'.")
                packages = ["cereggii"]

            for package in packages:
                package = package.strip().strip("/")
                if not len(package):
                    continue
                pack = __import__(package)
                path = pack.__path__[0]
                print(f"Adding package: {package} ({path})")
                package_walker = all_modules.discover_modules([path], package + ".")
                self.modules |= set(name for finder, name, ispgk in package_walker)

            if self.options.verbose:
                print(f"\nKnown modules ({len(self.modules)}): {','.join(sorted(self.modules))}")

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

        self.filenames = self.options.filenames.split(",")
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

        self.write = WritePythonCode(
            self,
            self.filename,
            self.module,
            self.module_name,
            threads=not self.options.no_threads,
            _async=not self.options.no_async,
            is_cereggii_scenario_mode=getattr(self.options, 'fuzz_cereggii_scenarios', False),
            plugin_manager = self.plugin_manager,
        )

    def on_session_start(self) -> None:
        """Start a new fuzzing session by selecting a module and generating test code."""
        if self.source_output_path:
            self.filename = self.source_output_path
        else:
            self.filename = self.session().createFilename("source.py")

        # copy sys.modules
        old_sys_modules = sys.modules.copy()

        name = "NO_MODULES!"
        while self.modules_list:
            name = choice(self.modules_list)
            try:
                self.loadModule(name)
                break
            except BaseException as err:
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

        assert isinstance(self.write, WritePythonCode)
        self.write.generate_fuzzing_script()
        self.send("python_source", self.filename)

        # unload new modules
        sys.modules.clear()
        sys.modules.update(old_sys_modules)
