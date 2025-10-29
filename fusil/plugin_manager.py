"""
Plugin Manager for Fusil

This module provides the plugin architecture for fusil, allowing external
packages to extend fusil's functionality through a well-defined API.

Plugins are discovered via entry points in the 'fusil.plugins' group.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Callable, Any


@dataclass
class ArgumentGeneratorRegistration:
    """Registration info for an argument generator function."""

    generator_func: Callable[[], list[str]]
    category: str  # 'simple', 'complex', 'hashable'
    weight: int = 1
    condition: Callable[[Any, str], bool] = (
        lambda cfg, mod: True
    )  # Default: always active


@dataclass
class DefinitionsProvider:
    """Registration info for a definitions/boilerplate provider."""

    provider_func: Callable[[Any, str], str | None]


@dataclass
class ScenarioProvider:
    """Registration info for a scenario provider."""

    provider_func: Callable[[Any, str], dict[str, Callable] | None]


@dataclass
class FuzzingMode:
    """Registration info for a fuzzing mode."""

    name: str
    activation_check: Callable[[Any], bool]
    setup_script: Callable[[Any], None]  # Takes WritePythonCode instance


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
        self.scenario_providers: list[ScenarioProvider] = []
        self.fuzzing_modes: dict[str, FuzzingMode] = {}
        self.hooks: dict[str, list[Callable]] = {
            "startup": [],
            "shutdown": [],
        }

    def discover_and_load_plugins(self) -> None:
        """
        Discover plugins via entry points and call their register functions.

        Plugins should define an entry point in the 'fusil.plugins' group.
        The entry point should point to a callable that takes the PluginManager
        as its single argument.
        """
        # Handle different Python versions' entry_points API
        if sys.version_info >= (3, 10):
            eps = entry_points(group="fusil.plugins")
        else:
            eps = entry_points().get("fusil.plugins", [])

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

    def add_definitions_provider(
        self, provider_func: Callable[[Any, str], str | None]
    ) -> None:
        """
        Register a definitions/boilerplate code provider.

        Args:
            provider_func: Function(config, module_name) -> str | None
                          Returns source code to embed in generated scripts, or None
        """
        self.definitions_providers.append(
            DefinitionsProvider(provider_func=provider_func)
        )

    def add_scenario_provider(
        self, provider_func: Callable[[Any, str], dict[str, Callable] | None]
    ) -> None:
        """
        Register a scenario provider.

        Args:
            provider_func: Function(config, module_name) -> dict[str, Callable] | None
                          Returns a dict of {scenario_name: scenario_function}, or None
        """
        self.scenario_providers.append(ScenarioProvider(provider_func=provider_func))

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

        mode = FuzzingMode(
            name=name, activation_check=activation_check, setup_script=setup_script
        )
        self.fuzzing_modes[name] = mode

    def add_hook(self, hook_name: str, hook_func: Callable) -> None:
        """
        Register a lifecycle hook.

        Args:
            hook_name: 'startup' or 'shutdown'
            hook_func: Callable to run at the specified lifecycle point
        """
        if hook_name not in self.hooks:
            raise ValueError(
                f"Unknown hook: {hook_name}. Valid hooks: {list(self.hooks.keys())}"
            )

        self.hooks[hook_name].append(hook_func)

    def declare_dependency(
        self, plugin_name: str, required_version: str | None = None
    ) -> None:
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
            dep_str = (
                f"{plugin_name}@{required_version}" if required_version else plugin_name
            )
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

    def get_scenarios(self, config: Any, module_name: str) -> dict[str, Callable]:
        """
        Get all scenarios from providers.

        Args:
            config: Fusil configuration object
            module_name: Target module being fuzzed

        Returns:
            Dictionary mapping scenario names to scenario functions
        """
        all_scenarios = {}
        for provider in self.scenario_providers:
            scenarios = provider.provider_func(config, module_name)
            if scenarios:
                all_scenarios.update(scenarios)
        return all_scenarios

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
                print(
                    f"[PluginManager] ERROR in hook {hook_name}: {e}", file=sys.stderr
                )
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
