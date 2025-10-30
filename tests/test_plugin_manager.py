"""
Tests for the core PluginManager functionality.

Run with: pytest test_plugin_manager.py -v
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from fusil.plugin_manager import (
    PluginManager,
    ArgumentGeneratorRegistration,
    DefinitionsProvider,
    ScenarioProvider,
    FuzzingMode,
    PluginMetadata,
    get_plugin_manager,
)


class TestPluginManagerInitialization:
    """Test plugin manager initialization and basic state."""

    def test_plugin_manager_initializes_empty(self):
        """Test that a new PluginManager has empty state."""
        pm = PluginManager()

        assert pm.plugins == {}
        assert pm.cli_options == []
        assert pm.argument_generators == []
        assert pm.definitions_providers == []
        assert pm.scenario_providers == []
        assert pm.fuzzing_modes == {}
        assert 'startup' in pm.hooks
        assert 'shutdown' in pm.hooks
        assert pm.hooks['startup'] == []
        assert pm.hooks['shutdown'] == []

    def test_get_plugin_manager_singleton(self):
        """Test that get_plugin_manager returns the same instance."""
        pm1 = get_plugin_manager()
        pm2 = get_plugin_manager()

        assert pm1 is pm2


class TestCLIOptions:
    """Test CLI option registration."""

    def test_add_cli_option(self):
        """Test adding a single CLI option."""
        pm = PluginManager()

        pm.add_cli_option('--test-option', help='Test', action='store_true')

        assert len(pm.cli_options) == 1
        args, kwargs = pm.cli_options[0]
        assert args == ('--test-option',)
        assert kwargs['help'] == 'Test'
        assert kwargs['action'] == 'store_true'

    def test_add_multiple_cli_options(self):
        """Test adding multiple CLI options."""
        pm = PluginManager()

        pm.add_cli_option('--option1', help='First')
        pm.add_cli_option('--option2', help='Second', type='int')
        pm.add_cli_option('--option3', help='Third', default='default_value')

        assert len(pm.cli_options) == 3

    def test_get_cli_options(self):
        """Test retrieving CLI options."""
        pm = PluginManager()

        pm.add_cli_option('--test', help='Test')
        options = pm.get_cli_options()

        assert options == pm.cli_options
        assert len(options) == 1


class TestArgumentGenerators:
    """Test argument generator registration and retrieval."""

    def test_add_simple_argument_generator(self):
        """Test registering a simple argument generator."""
        pm = PluginManager()

        def gen_test():
            return ["'test_value'"]

        pm.add_argument_generator(gen_test, 'simple')

        assert len(pm.argument_generators) == 1
        assert pm.argument_generators[0].generator_func == gen_test
        assert pm.argument_generators[0].category == 'simple'
        assert pm.argument_generators[0].weight == 1

    def test_add_generator_with_weight(self):
        """Test that generator weight is stored correctly."""
        pm = PluginManager()

        def gen_test():
            return ["'test'"]

        pm.add_argument_generator(gen_test, 'hashable', weight=5)

        assert pm.argument_generators[0].weight == 5

    def test_add_generator_with_condition(self):
        """Test registering a generator with a condition function."""
        pm = PluginManager()

        def gen_test():
            return ["'test'"]

        condition = lambda cfg, mod: mod == 'test_module'

        pm.add_argument_generator(gen_test, 'complex', condition=condition)

        assert pm.argument_generators[0].condition == condition

    def test_add_generator_invalid_category_raises_error(self):
        """Test that invalid category raises ValueError."""
        pm = PluginManager()

        def gen_test():
            return ["'test'"]

        with pytest.raises(ValueError, match="Invalid category"):
            pm.add_argument_generator(gen_test, 'invalid_category')

    def test_get_argument_generators_applies_weight(self):
        """Test that weight causes generators to appear multiple times."""
        pm = PluginManager()

        def gen_test():
            return ["'test'"]

        pm.add_argument_generator(gen_test, 'simple', weight=3)

        mock_config = Mock()
        generators = pm.get_argument_generators(mock_config, 'any_module', 'simple')

        assert len(generators) == 3
        assert all(g == gen_test for g in generators)

    def test_get_argument_generators_filters_by_category(self):
        """Test that only generators of the requested category are returned."""
        pm = PluginManager()

        def gen_simple():
            return ["'simple'"]

        def gen_complex():
            return ["'complex'"]

        pm.add_argument_generator(gen_simple, 'simple')
        pm.add_argument_generator(gen_complex, 'complex')

        mock_config = Mock()
        simple_gens = pm.get_argument_generators(mock_config, 'any', 'simple')
        complex_gens = pm.get_argument_generators(mock_config, 'any', 'complex')

        assert len(simple_gens) == 1
        assert len(complex_gens) == 1
        assert simple_gens[0] == gen_simple
        assert complex_gens[0] == gen_complex

    def test_get_argument_generators_respects_condition(self):
        """Test that condition functions filter generators correctly."""
        pm = PluginManager()

        def gen_test():
            return ["'test'"]

        # This generator should only be active for 'target_module'
        condition = lambda cfg, mod: mod == 'target_module'
        pm.add_argument_generator(gen_test, 'simple', condition=condition)

        mock_config = Mock()

        # Should return the generator for target_module
        gens_match = pm.get_argument_generators(mock_config, 'target_module', 'simple')
        assert len(gens_match) == 1

        # Should not return the generator for other modules
        gens_no_match = pm.get_argument_generators(mock_config, 'other_module', 'simple')
        assert len(gens_no_match) == 0

    def test_get_argument_generators_with_multiple_weights_and_conditions(self):
        """Test complex scenario with multiple generators, weights, and conditions."""
        pm = PluginManager()

        def gen1():
            return ["'gen1'"]

        def gen2():
            return ["'gen2'"]

        def gen3():
            return ["'gen3'"]

        # Always active, weight 2
        pm.add_argument_generator(gen1, 'simple', weight=2)
        # Only for 'special' module, weight 3
        pm.add_argument_generator(gen2, 'simple', weight=3,
                                  condition=lambda cfg, mod: mod == 'special')
        # Never active
        pm.add_argument_generator(gen3, 'simple', weight=1,
                                  condition=lambda cfg, mod: False)

        mock_config = Mock()

        # For 'special' module
        gens_special = pm.get_argument_generators(mock_config, 'special', 'simple')
        assert len(gens_special) == 5  # gen1 (2) + gen2 (3)

        # For other module
        gens_other = pm.get_argument_generators(mock_config, 'other', 'simple')
        assert len(gens_other) == 2  # gen1 (2) only


class TestDefinitionsProviders:
    """Test definitions provider registration and retrieval."""

    def test_add_definitions_provider(self):
        """Test registering a definitions provider."""
        pm = PluginManager()

        def provide_defs(config, module_name):
            return "# Test definitions"

        pm.add_definitions_provider(provide_defs)

        assert len(pm.definitions_providers) == 1
        assert pm.definitions_providers[0].provider_func == provide_defs

    def test_get_definitions(self):
        """Test retrieving definitions from providers."""
        pm = PluginManager()

        def provide_defs1(config, module_name):
            return "# Definitions 1"

        def provide_defs2(config, module_name):
            if module_name == 'special':
                return "# Special definitions"
            return None

        pm.add_definitions_provider(provide_defs1)
        pm.add_definitions_provider(provide_defs2)

        mock_config = Mock()

        # For special module, should get both
        defs_special = pm.get_definitions(mock_config, 'special')
        assert len(defs_special) == 2
        assert "Definitions 1" in defs_special[0]
        assert "Special definitions" in defs_special[1]

        # For other module, should only get first one
        defs_other = pm.get_definitions(mock_config, 'other')
        assert len(defs_other) == 1
        assert "Definitions 1" in defs_other[0]


class TestScenarioProviders:
    """Test scenario provider registration and retrieval."""

    def test_add_scenario_provider(self):
        """Test registering a scenario provider."""
        pm = PluginManager()

        def provide_scenarios(config, module_name):
            return {'test_scenario': lambda: None}

        pm.add_scenario_provider(provide_scenarios)

        assert len(pm.scenario_providers) == 1

    def test_get_scenarios(self):
        """Test retrieving scenarios from providers."""
        pm = PluginManager()

        def scenario1():
            pass

        def scenario2():
            pass

        def provide_scenarios1(config, module_name):
            return {'scenario1': scenario1}

        def provide_scenarios2(config, module_name):
            if module_name == 'special':
                return {'scenario2': scenario2}
            return None

        pm.add_scenario_provider(provide_scenarios1)
        pm.add_scenario_provider(provide_scenarios2)

        mock_config = Mock()

        # For special module
        scenarios_special = pm.get_scenarios(mock_config, 'special')
        assert len(scenarios_special) == 2
        assert 'scenario1' in scenarios_special
        assert 'scenario2' in scenarios_special

        # For other module
        scenarios_other = pm.get_scenarios(mock_config, 'other')
        assert len(scenarios_other) == 1
        assert 'scenario1' in scenarios_other


class TestFuzzingModes:
    """Test fuzzing mode registration and selection."""

    def test_add_fuzzing_mode(self):
        """Test registering a fuzzing mode."""
        pm = PluginManager()

        def check(config):
            return True

        def setup(wpc):
            pass

        pm.add_fuzzing_mode('test_mode', check, setup)

        assert 'test_mode' in pm.fuzzing_modes
        assert pm.fuzzing_modes['test_mode'].name == 'test_mode'
        assert pm.fuzzing_modes['test_mode'].activation_check == check
        assert pm.fuzzing_modes['test_mode'].setup_script == setup

    def test_add_duplicate_mode_raises_error(self):
        """Test that adding a duplicate mode name raises ValueError."""
        pm = PluginManager()

        pm.add_fuzzing_mode('test_mode', lambda cfg: True, lambda wpc: None)

        with pytest.raises(ValueError, match="already registered"):
            pm.add_fuzzing_mode('test_mode', lambda cfg: True, lambda wpc: None)

    def test_get_active_mode_returns_none_when_none_active(self):
        """Test that get_active_mode returns None when no mode is active."""
        pm = PluginManager()

        pm.add_fuzzing_mode('test_mode', lambda cfg: False, lambda wpc: None)

        mock_config = Mock()
        result = pm.get_active_mode(mock_config)

        assert result is None

    def test_get_active_mode_returns_active_mode(self):
        """Test that get_active_mode returns the active mode."""
        pm = PluginManager()

        def check(config):
            return config.test_mode_active

        pm.add_fuzzing_mode('test_mode', check, lambda wpc: None)

        mock_config = Mock()
        mock_config.test_mode_active = True

        result = pm.get_active_mode(mock_config)

        assert result is not None
        assert result.name == 'test_mode'

    def test_get_active_mode_raises_error_on_multiple_active(self):
        """Test that multiple active modes raises ValueError."""
        pm = PluginManager()

        pm.add_fuzzing_mode('mode1', lambda cfg: True, lambda wpc: None)
        pm.add_fuzzing_mode('mode2', lambda cfg: True, lambda wpc: None)

        mock_config = Mock()

        with pytest.raises(ValueError, match="Multiple fuzzing modes active"):
            pm.get_active_mode(mock_config)


class TestLifecycleHooks:
    """Test lifecycle hook registration and execution."""

    def test_add_hook(self):
        """Test registering a hook."""
        pm = PluginManager()

        def startup_hook(config):
            pass

        pm.add_hook('startup', startup_hook)

        assert len(pm.hooks['startup']) == 1
        assert pm.hooks['startup'][0] == startup_hook

    def test_add_hook_invalid_name_raises_error(self):
        """Test that invalid hook name raises ValueError."""
        pm = PluginManager()

        with pytest.raises(ValueError, match="Unknown hook"):
            pm.add_hook('invalid_hook', lambda: None)

    def test_run_hooks(self):
        """Test that hooks are executed."""
        pm = PluginManager()

        call_tracker = []

        def hook1(config):
            call_tracker.append('hook1')

        def hook2(config):
            call_tracker.append('hook2')

        pm.add_hook('startup', hook1)
        pm.add_hook('startup', hook2)

        mock_config = Mock()
        pm.run_hooks('startup', mock_config)

        assert call_tracker == ['hook1', 'hook2']

    def test_run_hooks_handles_exceptions(self):
        """Test that hook exceptions don't crash the system."""
        pm = PluginManager()

        call_tracker = []

        def bad_hook(config):
            call_tracker.append('bad_hook')
            raise ValueError("Test error")

        def good_hook(config):
            call_tracker.append('good_hook')

        pm.add_hook('startup', bad_hook)
        pm.add_hook('startup', good_hook)

        mock_config = Mock()
        pm.run_hooks('startup', mock_config)

        # Both hooks should have been called despite exception
        assert 'bad_hook' in call_tracker
        assert 'good_hook' in call_tracker


class TestDependencyManagement:
    """Test plugin dependency and incompatibility checking."""

    def test_declare_dependency(self):
        """Test declaring a plugin dependency."""
        pm = PluginManager()

        # Add a plugin to the manager first
        pm.plugins['test_plugin'] = PluginMetadata('test_plugin', None)

        # Declare dependency
        pm.declare_dependency('required_plugin', '1.0.0')

        # The dependency should be added to the last plugin
        assert 'required_plugin@1.0.0' in pm.plugins['test_plugin'].dependencies

    def test_declare_incompatibility(self):
        """Test declaring a plugin incompatibility."""
        pm = PluginManager()

        pm.plugins['test_plugin'] = PluginMetadata('test_plugin', None)

        pm.declare_incompatibility('incompatible_plugin')

        assert 'incompatible_plugin' in pm.plugins['test_plugin'].incompatibilities

    def test_check_dependencies_missing_dependency(self):
        """Test that missing dependencies are detected."""
        pm = PluginManager()

        pm.plugins['plugin1'] = PluginMetadata(
            'plugin1', None, dependencies=['missing_plugin']
        )

        errors = pm.check_dependencies()

        assert len(errors) > 0
        assert any('missing_plugin' in err for err in errors)

    def test_check_dependencies_incompatibility(self):
        """Test that incompatibilities are detected."""
        pm = PluginManager()

        pm.plugins['plugin1'] = PluginMetadata(
            'plugin1', None, incompatibilities=['plugin2']
        )
        pm.plugins['plugin2'] = PluginMetadata('plugin2', None)

        errors = pm.check_dependencies()

        assert len(errors) > 0
        assert any('incompatible' in err.lower() for err in errors)

    def test_check_dependencies_satisfied(self):
        """Test that satisfied dependencies return no errors."""
        pm = PluginManager()

        pm.plugins['plugin1'] = PluginMetadata(
            'plugin1', None, dependencies=['plugin2']
        )
        pm.plugins['plugin2'] = PluginMetadata('plugin2', None)

        errors = pm.check_dependencies()

        assert len(errors) == 0


class TestPluginDiscovery:
    """Test plugin discovery and loading."""

    @patch('fusil.plugin_manager.entry_points')
    def test_discover_and_load_plugins(self, mock_entry_points):
        """Test that plugins are discovered and loaded correctly."""
        pm = PluginManager()

        # Create a mock entry point
        mock_ep = Mock()
        mock_ep.name = 'test_plugin'

        # Create a mock register function
        call_tracker = []

        def mock_register(manager):
            call_tracker.append('registered')
            manager.add_cli_option('--test', help='Test')

        mock_ep.load.return_value = mock_register
        mock_entry_points.return_value = [mock_ep]

        # Discover and load plugins
        pm.discover_and_load_plugins()

        # Check that the plugin was registered
        assert 'test_plugin' in pm.plugins
        assert 'registered' in call_tracker
        assert len(pm.cli_options) == 1

    @patch('fusil.plugin_manager.entry_points')
    def test_discover_handles_plugin_errors_gracefully(self, mock_entry_points):
        """Test that plugin loading errors don't crash the system."""
        pm = PluginManager()

        # Create a mock entry point that raises an error
        mock_ep = Mock()
        mock_ep.name = 'broken_plugin'
        mock_ep.load.side_effect = ImportError("Broken plugin")
        mock_entry_points.return_value = [mock_ep]

        # This should not raise an exception
        pm.discover_and_load_plugins()

        # Plugin should not be registered
        assert 'broken_plugin' not in pm.plugins


if __name__ == '__main__':
    pytest.main([__file__, '-v'])