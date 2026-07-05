"""
Plugin Manager for Fusil

This module provides the plugin architecture for fusil, allowing external
packages to extend fusil's functionality through a well-defined API.

Plugins are discovered via entry points in the 'fusil.plugins' group.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from fnmatch import fnmatch
from importlib.metadata import entry_points
from typing import Any, Callable


@dataclass
class ArgumentGeneratorRegistration:
    """Registration info for an argument generator function."""

    generator_func: Callable[[], list[str]]
    category: str  # 'simple', 'complex', 'hashable'
    weight: int = 1
    condition: Callable[[Any, str], bool] = lambda cfg, mod: True  # Default: always active


@dataclass
class DefinitionsProvider:
    """Registration info for a definitions/boilerplate provider."""

    provider_func: Callable[[Any, str], str | None]


@dataclass
class FuzzingMode:
    """Registration info for a fuzzing mode."""

    name: str
    activation_check: Callable[[Any], bool]
    setup_script: Callable[[Any], None]  # Takes WritePythonCode instance


@dataclass
class InstanceDispatcher:
    """A per-instance dispatch provider.

    Called from ``WritePythonCode._dispatch_fuzz_on_instance`` (after the
    skip-trivial check, before the generic fallback). It emits specialized
    ``elif isinstance(target, SomeType):`` fuzzing branches into the generated
    script. To wrap the generic fallback in a trailing ``else:`` it may open an
    indentation level and return the level to restore to (an int); returning
    ``None`` means "no branches opened, run the generic fallback unconditionally".
    """

    provider_func: (
        Callable  # (writer, current_prefix, target_expr, class_name_hint, depth) -> int | None
    )


@dataclass
class ClassHandler:
    """A class-instantiation handler.

    Called from ``WritePythonCode._fuzz_one_class`` before the generic
    ``callFunc`` instantiation. It may claim a class (e.g. an h5py.File) and emit
    specialized instantiation code, returning ``True`` if it handled the class
    (suppressing the generic instantiation) or ``False`` to fall through.
    """

    provider_func: Callable  # (writer, class_name, class_type, instance_var, prefix) -> bool


@dataclass
class NameFilterEntry:
    """A blacklist/whitelist entry for discovered names.

    ``kind`` is one of 'module', 'class', 'function', 'object', 'method'.
    ``pattern_type`` is 'exact' (default) or 'glob' (fnmatch, e.g. '*Test').
    """

    kind: str
    pattern: str
    pattern_type: str = "exact"

    def matches(self, name: str) -> bool:
        if self.pattern_type == "glob":
            return fnmatch(name, self.pattern)
        return name == self.pattern


@dataclass
class SuppressionEntry:
    """A hit-suppression rule contributed by a plugin (issues #53/#52).

    ``pattern`` is a regex matched (``re.search``) against a crashing session's stdout to
    drop known/uninteresting hits, the same way ``--suppress-hit-regex`` does; ``reason``
    is an optional human-readable note recorded in the logs when the rule fires.
    """

    pattern: str
    reason: str | None = None


@dataclass
class PluginMetadata:
    """Metadata about a loaded plugin."""

    name: str
    entry_point: Any
    dependencies: list[str] = field(default_factory=list)
    incompatibilities: list[str] = field(default_factory=list)


class PluginManager:
    """
    Manages fusil plugins: discovery, loading, and registration API.

    Plugins register their functionality through this manager's API methods.
    """

    def __init__(self):
        self.plugins: dict[str, PluginMetadata] = {}
        self.cli_options: list[tuple[tuple, dict]] = []  # (args, kwargs) for add_option
        self.argument_generators: list[ArgumentGeneratorRegistration] = []
        self.definitions_providers: list[DefinitionsProvider] = []
        self.fuzzing_modes: dict[str, FuzzingMode] = {}
        self.instance_dispatchers: list[InstanceDispatcher] = []
        self.class_handlers: list[ClassHandler] = []
        self.blacklist_entries: list[NameFilterEntry] = []
        self.whitelist_entries: list[NameFilterEntry] = []
        self.suppression_entries: list[SuppressionEntry] = []
        self.hooks: dict[str, list[Callable]] = {
            "startup": [],
            "shutdown": [],
        }

    def discover_and_load_plugins(self, entry_points_func: Callable | None = None) -> None:
        """
        Discover plugins via entry points and call their register functions.

        Plugins should define an entry point in the 'fusil.plugins' group.
        The entry point should point to a callable that takes the PluginManager
        as its single argument.

        Args:
            entry_points_func: injectable ``importlib.metadata.entry_points`` replacement
                (tests pass a fake); defaults to the real ``entry_points`` at runtime.
        """
        if entry_points_func is None:
            entry_points_func = entry_points

        # Handle different Python versions' entry_points API
        if sys.version_info >= (3, 10):
            eps = entry_points_func(group="fusil.plugins")
        else:
            eps = entry_points_func().get("fusil.plugins", [])

        for ep in eps:
            plugin_name = ep.name
            print(f"[PluginManager] Loading plugin: {plugin_name}", file=sys.stderr)

            try:
                # Load the entry point (this imports the module)
                register_func = ep.load()

                # Create metadata
                metadata = PluginMetadata(name=plugin_name, entry_point=ep)
                self.plugins[plugin_name] = metadata

                # Call the plugin's register function
                register_func(self)

                print(
                    f"[PluginManager] Successfully loaded plugin: {plugin_name}",
                    file=sys.stderr,
                )

            except Exception as e:
                print(
                    f"[PluginManager] ERROR loading plugin {plugin_name}: {e}",
                    file=sys.stderr,
                )
                import traceback

                traceback.print_exc()

    def add_cli_option(self, *args, **kwargs) -> None:
        """
        Register a command-line option to be added to fusil's argument parser.

        Args:
            *args: Positional arguments for parser.add_option()
            **kwargs: Keyword arguments for parser.add_option()
        """
        self.cli_options.append((args, kwargs))

    def add_argument_generator(
        self,
        generator_func: Callable[[], list[str]],
        category: str,
        weight: int = 1,
        condition: Callable[[Any, str], bool] = lambda cfg, mod: True,
    ) -> None:
        """
        Register an argument generator function.

        Args:
            generator_func: Function that returns a list of code strings (lines)
            category: 'simple', 'complex', or 'hashable'
            weight: Relative frequency (higher = more likely to be chosen)
            condition: Function(config, module_name) -> bool to check if generator should be active
        """
        if category not in ("simple", "complex", "hashable"):
            raise ValueError(
                f"Invalid category: {category}. Must be 'simple', 'complex', or 'hashable'"
            )

        registration = ArgumentGeneratorRegistration(
            generator_func=generator_func,
            category=category,
            weight=weight,
            condition=condition,
        )
        self.argument_generators.append(registration)

    def add_definitions_provider(self, provider_func: Callable[[Any, str], str | None]) -> None:
        """
        Register a definitions/boilerplate code provider.

        Args:
            provider_func: Function(config, module_name) -> str | None
                          Returns source code to embed in generated scripts, or None
        """
        self.definitions_providers.append(DefinitionsProvider(provider_func=provider_func))

    def add_fuzzing_mode(
        self,
        name: str,
        activation_check: Callable[[Any], bool],
        setup_script: Callable[[Any], None],
    ) -> None:
        """
        Register a distinct fuzzing mode.

        Args:
            name: Unique name for this mode
            activation_check: Function(config) -> bool to check if mode should be active
            setup_script: Function(WritePythonCode) that generates the main execution logic
        """
        if name in self.fuzzing_modes:
            raise ValueError(f"Fuzzing mode '{name}' already registered")

        mode = FuzzingMode(name=name, activation_check=activation_check, setup_script=setup_script)
        self.fuzzing_modes[name] = mode

    def add_instance_dispatcher(self, provider_func: Callable) -> None:
        """Register a per-instance dispatch provider (see InstanceDispatcher).

        Args:
            provider_func: (writer, current_prefix, target_expr, class_name_hint, depth)
                -> int | None. Emits specialized ``elif isinstance(...)`` branches and
                optionally opens a trailing ``else:`` level (returned int) that the core
                fills with the generic fallback; return None to leave the fallback
                unconditional.
        """
        self.instance_dispatchers.append(InstanceDispatcher(provider_func=provider_func))

    def add_class_handler(self, provider_func: Callable) -> None:
        """Register a class-instantiation handler (see ClassHandler).

        Args:
            provider_func: (writer, class_name, class_type, instance_var, prefix) -> bool.
                Emits specialized instantiation and returns True if it claimed the class
                (suppressing the generic ``callFunc`` instantiation), else False.
        """
        self.class_handlers.append(ClassHandler(provider_func=provider_func))

    def add_blacklist_entry(self, kind: str, pattern: str, pattern_type: str = "exact") -> None:
        """Blacklist a discovered name (module/class/function/object/method).

        Args:
            kind: 'module', 'class', 'function', 'object', or 'method'.
            pattern: the name (or glob pattern) to exclude.
            pattern_type: 'exact' (default) or 'glob' (fnmatch, e.g. '*Test').
        """
        self.blacklist_entries.append(NameFilterEntry(kind, pattern, pattern_type))

    def add_whitelist_entry(self, kind: str, pattern: str, pattern_type: str = "exact") -> None:
        """Whitelist a discovered name so it is kept even when normally skipped.

        Currently honoured for 'method' names: a whitelisted method (e.g. '__del__')
        is kept even though private/dunder names are skipped by default.
        """
        self.whitelist_entries.append(NameFilterEntry(kind, pattern, pattern_type))

    def add_suppression_entry(self, pattern: str, reason: str | None = None) -> None:
        """Register a regex that suppresses a crashing-session hit when it matches stdout.

        Lets a plugin drop known/uninteresting hits the same way ``--suppress-hit-regex``
        does (issue #53); ``reason`` is recorded in the logs when the rule fires. This is
        the plugin-extensible suppression store called for in #52.

        Args:
            pattern: a regex matched (``re.search``) against a crash's captured stdout.
            reason: optional human-readable note logged when the rule suppresses a hit.
        """
        self.suppression_entries.append(SuppressionEntry(pattern=pattern, reason=reason))

    def add_hook(self, hook_name: str, hook_func: Callable) -> None:
        """
        Register a lifecycle hook.

        Args:
            hook_name: 'startup' or 'shutdown'
            hook_func: Callable to run at the specified lifecycle point
        """
        if hook_name not in self.hooks:
            raise ValueError(f"Unknown hook: {hook_name}. Valid hooks: {list(self.hooks.keys())}")

        self.hooks[hook_name].append(hook_func)

    def declare_dependency(self, plugin_name: str, required_version: str | None = None) -> None:
        """
        Declare that the current plugin depends on another plugin.

        Args:
            plugin_name: Name of the required plugin
            required_version: Optional version constraint
        """
        # Note: This is called during a plugin's register() function,
        # so we need to figure out which plugin is calling it.
        # For now, we'll store it simply. A more robust implementation
        # would track the "current" plugin being loaded.
        # For V1, we can just add it to the last loaded plugin's metadata.
        if self.plugins:
            last_plugin = list(self.plugins.values())[-1]
            dep_str = f"{plugin_name}@{required_version}" if required_version else plugin_name
            last_plugin.dependencies.append(dep_str)

    def declare_incompatibility(self, plugin_name: str) -> None:
        """
        Declare that the current plugin is incompatible with another plugin.

        Args:
            plugin_name: Name of the incompatible plugin
        """
        if self.plugins:
            last_plugin = list(self.plugins.values())[-1]
            last_plugin.incompatibilities.append(plugin_name)

    def get_cli_options(self) -> list[tuple[tuple, dict]]:
        """Get all registered CLI options."""
        return self.cli_options

    def get_argument_generators(
        self, config: Any, module_name: str, category: str
    ) -> list[Callable]:
        """
        Get active argument generators for the given context and category.

        Args:
            config: Fusil configuration object
            module_name: Target module being fuzzed
            category: 'simple', 'complex', or 'hashable'

        Returns:
            List of generator functions, with weights applied
        """
        generators = []
        for reg in self.argument_generators:
            if reg.category == category and reg.condition(config, module_name):
                # Add the generator 'weight' times to implement weighting
                generators.extend([reg.generator_func] * reg.weight)
        return generators

    def get_definitions(self, config: Any, module_name: str) -> list[str]:
        """
        Get all definitions/boilerplate code from providers.

        Args:
            config: Fusil configuration object
            module_name: Target module being fuzzed

        Returns:
            List of source code strings
        """
        definitions = []
        for provider in self.definitions_providers:
            code = provider.provider_func(config, module_name)
            if code:
                definitions.append(code)
        return definitions

    def get_instance_dispatchers(self) -> list[Callable]:
        """Return the registered per-instance dispatch provider functions."""
        return [d.provider_func for d in self.instance_dispatchers]

    def get_class_handlers(self) -> list[Callable]:
        """Return the registered class-instantiation handler functions."""
        return [h.provider_func for h in self.class_handlers]

    def is_blacklisted(self, kind: str, name: str) -> bool:
        """True if a plugin blacklisted `name` for the given `kind`."""
        return any(e.kind == kind and e.matches(name) for e in self.blacklist_entries)

    def is_whitelisted(self, kind: str, name: str) -> bool:
        """True if a plugin whitelisted `name` for the given `kind`."""
        return any(e.kind == kind and e.matches(name) for e in self.whitelist_entries)

    def get_suppression_entries(self) -> list[tuple[str, str | None]]:
        """Return plugin-registered hit-suppression rules as ``(pattern, reason)`` pairs."""
        return [(e.pattern, e.reason) for e in self.suppression_entries]

    def get_active_mode(self, config: Any) -> FuzzingMode | None:
        """
        Determine which fuzzing mode should be active based on config.

        Args:
            config: Fusil configuration object

        Returns:
            The active FuzzingMode, or None if no special mode is active
        """
        active_modes = []
        for mode_name, mode in self.fuzzing_modes.items():
            if mode.activation_check(config):
                active_modes.append(mode)

        if len(active_modes) > 1:
            mode_names = [m.name for m in active_modes]
            raise ValueError(
                f"Multiple fuzzing modes active: {mode_names}. Only one mode can be active at a time."
            )

        return active_modes[0] if active_modes else None

    def run_hooks(self, hook_name: str, *args, **kwargs) -> None:
        """
        Run all registered hooks for a given lifecycle event.

        Args:
            hook_name: Name of the hook to run
            *args, **kwargs: Arguments to pass to hook functions
        """
        if hook_name not in self.hooks:
            return

        for hook_func in self.hooks[hook_name]:
            try:
                hook_func(*args, **kwargs)
            except Exception as e:
                print(f"[PluginManager] ERROR in hook {hook_name}: {e}", file=sys.stderr)
                import traceback

                traceback.print_exc()

    def check_dependencies(self) -> list[str]:
        """
        Check if all plugin dependencies are satisfied.

        Returns:
            List of error messages for unsatisfied dependencies
        """
        errors = []
        loaded_plugins = set(self.plugins.keys())

        for plugin_name, metadata in self.plugins.items():
            for dep in metadata.dependencies:
                # Simple check: just see if the dependency is loaded
                # For V1, ignore version constraints
                dep_name = dep.split("@")[0]
                if dep_name not in loaded_plugins:
                    errors.append(
                        f"Plugin '{plugin_name}' requires '{dep_name}' which is not loaded"
                    )

            for incompat in metadata.incompatibilities:
                if incompat in loaded_plugins:
                    errors.append(
                        f"Plugin '{plugin_name}' is incompatible with '{incompat}' which is loaded"
                    )

        return errors


# Global plugin manager instance
_plugin_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    """Get the global PluginManager instance, creating it if needed."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager
