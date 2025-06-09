from __future__ import annotations

import pathlib
import pkgutil
import sys
from types import ModuleType
from typing import TYPE_CHECKING, Any, Callable, Generator

if TYPE_CHECKING:
    from fusil.python.python_source import PythonSource


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
        logger: "PythonSource",
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
        search_path: str = "",
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
            if "site-packages" in search_path:
                return False
            if "site-packages" in filename or any("site-packages" in p for p in path):
                return False

        if self.only_c:
            if not filename:
                return False

            if is_package:
                return False

            is_c_extension = any(filename.endswith(ext) for ext in (".so", ".pyd"))
            return is_c_extension

        search_targets = [name, package, pathlib.Path(filename).name, prefix]
        if any(
            blacklist_entry in target
            for blacklist_entry in self.blacklist
            for target in search_targets
        ):
            return False

        return True

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
    ) -> Generator[tuple, None, None]:
        """
        Recursively discover modules, yielding valid ones.

        Args:
            path: list of paths to search (None for default)
            prefix: Current module prefix
            onerror: Callback for handling import errors

        Yields:
            ModuleInfo objects for valid modules
        """
        if path is None:
            path = sys.path

        for finder, name, ispkg in pkgutil.walk_packages(path, prefix, onerror):
            if name in self.blacklist:
                continue

            if name.endswith("_d"):
                continue

            filename = None
            try:
                spec = finder.find_spec(name)
                if spec:
                    filename = spec.origin
            except (ImportError, SyntaxError):
                filename = None

            module_data = self._get_module_metadata(name)
            search_path = finder.path if hasattr(finder, 'path') else ""

            if not self._is_valid_module(
                name,
                ispkg,
                filename,
                module_data.get("path"),
                module_data.get("package"),
                prefix,
                search_path=search_path
            ):
                if self.verbose:
                    print(f"SKIPPED {name}", file=sys.stderr)
                continue

            yield (finder, name, ispkg)

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
    ) -> Generator[tuple, None, None]:
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
            name = info[1]
            fullname = prefix + name
            if self.verbose:
                self.logger.error(f"ADDING {fullname}: {prefix}+{name}")
            self.discovered_modules.add(fullname)

        return self.discovered_modules
