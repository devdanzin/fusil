from __future__ import annotations

import pathlib
import pkgutil
import sys
from types import ModuleType
from typing import Any, Callable, Generator

from python import PythonSource


class ListAllModules:
    """
    Discovers and filters Python modules suitable for fuzzing.

    This class provides functionality to scan the available Python modules,
    applying various filters to identify modules that are appropriate for
    fuzzing operations. It can filter based on module type (C vs Python),
    location (site-packages vs stdlib), and custom blacklists.

    Args:
        logger: Logger instance for outputting messages
        only_c: If True, only include C extension modules
        site_package: If True, include modules from site-packages
        blacklist: set of module names/patterns to exclude
        skip_test: If True, skip test modules (currently unused)
        verbose: If True, output detailed logging information
    """

    def __init__(
        self,
        logger: PythonSource,
        only_c: bool,
        site_package: bool,
        blacklist: set[str],
        skip_test: bool,
        verbose: bool = False,
    ):
        self.logger = logger
        self.only_c = only_c
        self.site_package = site_package
        self.blacklist = blacklist
        self.skip_test = skip_test
        self.verbose = verbose

        self.discovered_modules: set[str] = set(sys.builtin_module_names) - {"__main__"}
        self._seen_paths: set[str] = set()

    def _is_valid_module(
        self,
        name: str,
        is_package: bool,
        filename: str | None,
        path: list[str] | None,
        package: str | None,
        prefix: str = "",
    ) -> bool:
        """
        Check if a module meets the filtering criteria for fuzzing.

        Args:
            name: Module name
            is_package: True if the module is a package
            filename: Module filename (if available)
            path: Module path list (if available)
            package: Parent package name (if available)
            prefix: Module name prefix (for submodules)

        Returns:
            True if the module should be included, False otherwise
        """
        filename = filename or ""
        path = path or []
        package = package or ""

        if not self.site_package:
            if "site-packages" in filename or any("site-packages" in p for p in path):
                return False

        if self.only_c:
            if any(filename.endswith(ext) for ext in (".py", ".pyc", ".pyo")):
                return False
            if is_package or not self._is_c_module(name, prefix):
                return False

        search_targets = [name, package, pathlib.Path(filename).name, prefix]
        if any(
            blacklist_entry in target
            for blacklist_entry in self.blacklist
            for target in search_targets
        ):
            return False

        return True

    def _is_c_module(self, name: str, prefix: str) -> bool:
        """
        Determine if a module is implemented in C.

        Args:
            name: Module name
            prefix: Module prefix

        Returns:
            True if the module is a (probable) C extension, False if it's Python
        """
        fullname = prefix + name

        if self.verbose:
            print(f"Testing if {fullname} is C module...")

        module = self._find_module(fullname, name, prefix)

        if not module:
            if self.verbose:
                print(f"    Could not import {fullname}, assuming C module")
            return True

        if not hasattr(module, "__file__") or module.__file__ is None:
            if self.verbose:
                print(f"    {fullname} has no __file__, likely builtin C module")
            return True

        module_file = str(module.__file__)
        is_python = module_file.endswith((".py", ".pyc", ".pyo", ".pyw"))

        if self.verbose:
            file_type = "Python" if is_python else "C"
            print(f"    {fullname} is {file_type} module (file: {module_file})")

        if is_python and self.verbose:
            self.logger.error(f"SKIP PYTHON MODULE {fullname}")

        return not is_python

    def _find_module(self, fullname: str, name: str, prefix: str) -> ModuleType | None:
        """
        Attempt to find and import a module using various strategies.

        Args:
            fullname: Full module name with prefix
            name: Base module name
            prefix: Module prefix

        Returns:
            The imported module or None if not found
        """
        # Try different module name variations
        candidates = [
            fullname,
            name,
            name.split(".")[0],
            prefix.rstrip("."),
            prefix.split(".")[0] if prefix else None,
        ]

        for candidate in candidates:
            if candidate and candidate in sys.modules:
                return sys.modules[candidate]

        try:
            return __import__(fullname)
        except ImportError as e:
            if self.verbose:
                print(f"    Import failed for {fullname}: {e}")
            return None

    def discover_modules(
        self,
        path: list[str] | None = None,
        prefix: str = "",
        onerror: Callable[[str], None] | None = None,
    ) -> Generator[pkgutil.ModuleInfo, None, None]:
        """
        Recursively discover modules, yielding valid ones.

        Args:
            path: list of paths to search (None for default)
            prefix: Current module prefix
            onerror: Callback for handling import errors

        Yields:
            ModuleInfo objects for valid modules
        """
        for info in pkgutil.iter_modules(path, prefix):
            if info.name in self.blacklist:
                continue

            # Skip Debian debug modules (e.g., "_bisect_d")
            if info.name.endswith("_d"):
                continue

            module_data = self._get_module_metadata(info.name)

            if not self._is_valid_module(
                info.name,
                info.ispkg,
                module_data.get("filename"),
                module_data.get("path"),
                module_data.get("package"),
                prefix,
            ):
                if self.verbose:
                    print(f"SKIPPED {prefix + info.name}", file=sys.stderr)
                continue

            yield info

            if info.ispkg:
                yield from self._process_package(info, onerror)

    def _get_module_metadata(self, module_name: str) -> dict[str, Any]:
        """Get metadata for a module if it's already imported."""
        if module_name not in sys.modules:
            return {}

        module = sys.modules[module_name]
        return {
            "path": getattr(module, "__path__", None),
            "package": getattr(module, "__package__", None),
            "filename": getattr(module, "__file__", None),
        }

    def _process_package(
        self, info: pkgutil.ModuleInfo, onerror: Callable[[str], None] | None
    ) -> Generator[pkgutil.ModuleInfo, None, None]:
        """
        Process a package by importing it and recursively scanning submodules.

        Args:
            info: Package information
            onerror: Error handling callback

        Yields:
            ModuleInfo objects for submodules
        """
        try:
            __import__(info.name)
        except (ImportError, Exception) as e:
            if onerror:
                onerror(info.name)
            elif not isinstance(e, ImportError):
                raise
            return

        if info.name not in sys.modules:
            return

        module_path = getattr(sys.modules[info.name], "__path__", None)
        if not module_path:
            return

        # Filter out already seen paths
        new_paths = [p for p in module_path if p not in self._seen_paths]
        self._seen_paths.update(new_paths)

        if new_paths:
            yield from self.discover_modules(new_paths, info.name + ".", onerror)

    def search_modules(self, prefix: str = "") -> set[str]:
        """
        Search for and return all valid modules for fuzzing.

        Args:
            prefix: Optional prefix to add to module names

        Returns:
            set of module names that passed all filters
        """
        for info in self.discover_modules(onerror=lambda x: None):
            fullname = prefix + info.name
            if self.verbose:
                self.logger.error(f"ADDING {fullname}: {prefix}+{info.name}")
            self.discovered_modules.add(fullname)

        return self.discovered_modules
