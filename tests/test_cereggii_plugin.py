"""
Tests for the cereggii plugin functionality.

Run with: pytest test_cereggii_plugin.py -v
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from fusil.plugin_manager import PluginManager


class TestCereggiiPluginInstallation:
    """Test that the cereggii plugin is correctly installed and discoverable."""

    def test_cereggii_plugin_entry_point_exists(self):
        """Test that the cereggii plugin entry point is registered."""
        try:
            from importlib.metadata import entry_points
            import sys

            if sys.version_info >= (3, 10):
                eps = entry_points(group='fusil.plugins')
            else:
                eps = entry_points().get('fusil.plugins', [])

            cereggii_ep = [ep for ep in eps if ep.name == 'cereggii']
            assert len(
                cereggii_ep) > 0, "Cereggii plugin entry point not found. Make sure to install it with 'pip install -e fusil-cereggii-plugin'"
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

    def test_cereggii_plugin_module_importable(self):
        """Test that the cereggii plugin module can be imported."""
        try:
            import fusil_cereggii_plugin
            assert hasattr(fusil_cereggii_plugin, 'register')
        except ImportError:
            pytest.skip("Cereggii plugin not installed")


class TestCereggiiPluginRegistration:
    """Test that the cereggii plugin registers its components correctly."""

    def test_cereggii_plugin_registers_cli_option(self):
        """Test that the cereggii plugin adds its CLI option."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        # Check that --fuzz-cereggii-scenarios was added
        cli_opts = pm.get_cli_options()
        assert len(cli_opts) > 0

        option_names = [args[0] for args, kwargs in cli_opts]
        assert '--fuzz-cereggii-scenarios' in option_names

    def test_cereggii_cli_option_properties(self):
        """Test that the CLI option has correct properties."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        cli_opts = pm.get_cli_options()
        for args, kwargs in cli_opts:
            if '--fuzz-cereggii-scenarios' in args:
                assert kwargs.get('action') == 'store_true'
                assert kwargs.get('default') == False
                assert 'help' in kwargs
                break
        else:
            pytest.fail("Could not find --fuzz-cereggii-scenarios option")

    def test_cereggii_plugin_registers_multiple_argument_generators(self):
        """Test that the cereggii plugin registers multiple argument generators."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        # The plugin should register generators for multiple categories
        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        # For cereggii module
        gens_simple = pm.get_argument_generators(mock_config, 'cereggii', 'simple')
        gens_complex = pm.get_argument_generators(mock_config, 'cereggii', 'complex')
        gens_hashable = pm.get_argument_generators(mock_config, 'cereggii', 'hashable')

        # Should have generators when targeting cereggii
        assert len(gens_simple) > 0, "No simple generators for cereggii"
        assert len(gens_complex) > 0, "No complex generators for cereggii"
        assert len(gens_hashable) > 0, "No hashable generators for cereggii"

    def test_cereggii_generators_not_active_for_other_modules(self):
        """Test that cereggii generators are not active for non-cereggii modules."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        # For a non-cereggii module, should not have cereggii generators
        # (unless fuzz_cereggii_scenarios is True)
        gens_simple = pm.get_argument_generators(mock_config, 'random_module', 'simple')
        gens_complex = pm.get_argument_generators(mock_config, 'random_module', 'complex')
        gens_hashable = pm.get_argument_generators(mock_config, 'random_module', 'hashable')

        # Should have no generators for non-cereggii modules
        assert len(gens_simple) == 0
        assert len(gens_complex) == 0
        assert len(gens_hashable) == 0

    def test_cereggii_generators_active_when_scenario_mode_enabled(self):
        """Test that cereggii generators become active when scenario mode is enabled."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = True

        # When scenario mode is on, generators should be active for any module
        gens_simple = pm.get_argument_generators(mock_config, 'any_module', 'simple')
        assert len(gens_simple) > 0

    def test_atomicint64_generator_produces_valid_output(self):
        """Test that the AtomicInt64 generator produces valid references."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        gens = pm.get_argument_generators(mock_config, 'cereggii', 'simple')

        # Find and test generators
        for gen in gens[:5]:  # Test a few generators
            result = gen()
            assert isinstance(result, list)
            assert len(result) == 1
            # Should produce either a direct instantiation or a reference
            assert 'tricky_atomic_ints' in result[0] or 'AtomicInt64' in result[0]

    def test_atomicdict_generator_produces_valid_output(self):
        """Test that the AtomicDict generator produces valid references."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        gens = pm.get_argument_generators(mock_config, 'cereggii', 'complex')

        # Test a generator
        for gen in gens[:5]:
            result = gen()
            assert isinstance(result, list)
            assert len(result) == 1
            # Should produce either a direct instantiation or a reference
            assert 'tricky_atomic_dicts' in result[0] or 'AtomicDict' in result[0]

    def test_hashable_key_generator_produces_valid_output(self):
        """Test that the hashable key generator produces valid references."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        gens = pm.get_argument_generators(mock_config, 'cereggii', 'hashable')

        # Test generators
        for gen in gens[:5]:
            result = gen()
            assert isinstance(result, list)
            assert len(result) == 1
            # Should produce a reference to a hashable key or a hashable AtomicInt64
            assert (
                    'tricky_hashable_keys' in result[0] or
                    'tricky_atomic_ints' in result[0] or
                    'fallback_key' in result[0] or
                    'AtomicInt64' in result[0]
            ), f"Unexpected hashable generator output: {result[0]}"

    def test_cereggii_plugin_registers_definitions_provider(self):
        """Test that the cereggii plugin provides definitions."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        # Should provide definitions for cereggii module
        defs = pm.get_definitions(mock_config, 'cereggii')
        assert len(defs) > 0

        # Definitions should contain expected markers
        definitions_code = '\n'.join(defs)
        assert 'BEGIN Tricky Cereggii Definitions' in definitions_code or 'tricky_atomic_ints' in definitions_code

    def test_cereggii_definitions_not_provided_for_other_modules(self):
        """Test that cereggii definitions are not provided for non-cereggii modules."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        # Should not provide definitions for non-cereggii modules
        defs = pm.get_definitions(mock_config, 'random_module')
        assert len(defs) == 0

    def test_cereggii_definitions_provided_in_scenario_mode(self):
        """Test that definitions are provided when scenario mode is enabled."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = True

        # Should provide definitions when scenario mode is on
        defs = pm.get_definitions(mock_config, 'any_module')
        assert len(defs) > 0

    def test_cereggii_plugin_registers_scenario_provider(self):
        """Test that the cereggii plugin registers a scenario provider."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        assert len(pm.scenario_providers) > 0

    def test_cereggii_scenarios_retrieved_for_cereggii_module(self):
        """Test that scenarios are retrieved for cereggii module."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        scenarios = pm.get_scenarios(mock_config, 'cereggii')
        # May return empty dict initially, but provider should exist
        assert scenarios is not None
        assert isinstance(scenarios, dict)

    def test_cereggii_plugin_registers_fuzzing_mode(self):
        """Test that the cereggii plugin registers its fuzzing mode."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        # Should have registered the cereggii_scenario mode
        assert 'cereggii_scenario' in pm.fuzzing_modes

        mode = pm.fuzzing_modes['cereggii_scenario']
        assert mode.name == 'cereggii_scenario'
        assert callable(mode.activation_check)
        assert callable(mode.setup_script)

    def test_cereggii_fuzzing_mode_activation(self):
        """Test that the fuzzing mode activates correctly."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mode = pm.fuzzing_modes['cereggii_scenario']

        # Test with scenario mode disabled
        mock_config_disabled = Mock()
        mock_config_disabled.fuzz_cereggii_scenarios = False
        assert mode.activation_check(mock_config_disabled) == False

        # Test with scenario mode enabled
        mock_config_enabled = Mock()
        mock_config_enabled.fuzz_cereggii_scenarios = True
        assert mode.activation_check(mock_config_enabled) == True

    def test_cereggii_fuzzing_mode_in_get_active_mode(self):
        """Test that get_active_mode correctly identifies cereggii mode."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        # When scenario mode is disabled
        mock_config_disabled = Mock()
        mock_config_disabled.fuzz_cereggii_scenarios = False
        active_mode = pm.get_active_mode(mock_config_disabled)
        assert active_mode is None

        # When scenario mode is enabled
        mock_config_enabled = Mock()
        mock_config_enabled.fuzz_cereggii_scenarios = True
        active_mode = pm.get_active_mode(mock_config_enabled)
        assert active_mode is not None
        assert active_mode.name == 'cereggii_scenario'

    def test_cereggii_plugin_registers_hooks(self):
        """Test that the cereggii plugin registers startup hooks."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        # Should have at least one startup hook
        assert len(pm.hooks['startup']) > 0

    def test_cereggii_plugin_startup_hook_executes(self):
        """Test that the startup hook executes without errors."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = True
        mock_config.modules = "cereggii"

        # This should not raise an exception
        pm.run_hooks('startup', mock_config)


class TestCereggiiPluginIntegration:
    """Test cereggii plugin integration with PluginManager."""

    def test_cereggii_plugin_loads_via_discovery(self):
        """Test that the cereggii plugin is loaded when discovering plugins."""
        try:
            from importlib.metadata import entry_points
            import sys

            if sys.version_info >= (3, 10):
                eps = entry_points(group='fusil.plugins')
            else:
                eps = entry_points().get('fusil.plugins', [])

            cereggii_eps = [ep for ep in eps if ep.name == 'cereggii']
            if not cereggii_eps:
                pytest.skip("Cereggii plugin not installed")
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        pm.discover_and_load_plugins()

        # Check that cereggii plugin was loaded
        assert 'cereggii' in pm.plugins

        # Check that its components were registered
        assert len(pm.cli_options) > 0
        assert len(pm.argument_generators) > 0
        assert len(pm.definitions_providers) > 0
        assert len(pm.scenario_providers) > 0
        assert len(pm.fuzzing_modes) > 0

    def test_cereggii_plugin_coexists_with_other_plugins(self):
        """Test that cereggii plugin can coexist with other plugins."""
        try:
            from importlib.metadata import entry_points
            import sys

            if sys.version_info >= (3, 10):
                eps = entry_points(group='fusil.plugins')
            else:
                eps = entry_points().get('fusil.plugins', [])

            if len([ep for ep in eps if ep.name == 'cereggii']) == 0:
                pytest.skip("Cereggii plugin not installed")
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        pm.discover_and_load_plugins()

        # Should load at least the cereggii plugin
        assert len(pm.plugins) >= 1
        assert 'cereggii' in pm.plugins


class TestCereggiiPluginConditions:
    """Test that the cereggii plugin's conditions work correctly."""

    def test_generators_only_active_for_cereggii_module(self):
        """Test that generators respect the module targeting."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        # For cereggii module
        gens_cereggii = pm.get_argument_generators(mock_config, 'cereggii', 'simple')
        assert len(gens_cereggii) > 0

        # For other modules
        gens_other = pm.get_argument_generators(mock_config, 'numpy', 'simple')
        assert len(gens_other) == 0

    def test_generators_active_everywhere_in_scenario_mode(self):
        """Test that generators are active for all modules in scenario mode."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = True

        # Should work for any module
        gens_random = pm.get_argument_generators(mock_config, 'random_module', 'simple')
        assert len(gens_random) > 0

    def test_definitions_only_provided_when_condition_met(self):
        """Test that definitions are only provided when condition is met."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        # Test with cereggii module, scenario mode off
        config1 = Mock()
        config1.fuzz_cereggii_scenarios = False
        defs1 = pm.get_definitions(config1, 'cereggii')
        assert len(defs1) > 0

        # Test with other module, scenario mode off
        config2 = Mock()
        config2.fuzz_cereggii_scenarios = False
        defs2 = pm.get_definitions(config2, 'random_module')
        assert len(defs2) == 0

        # Test with other module, scenario mode on
        config3 = Mock()
        config3.fuzz_cereggii_scenarios = True
        defs3 = pm.get_definitions(config3, 'random_module')
        assert len(defs3) > 0

    def test_generator_weights_are_respected(self):
        """Test that generators with higher weights appear more frequently."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.fuzz_cereggii_scenarios = False

        # Get generators - those with weight 10 should appear 10x
        gens_hashable = pm.get_argument_generators(mock_config, 'cereggii', 'hashable')

        # Count occurrences of each unique generator
        from collections import Counter
        gen_ids = [id(gen) for gen in gens_hashable]
        counts = Counter(gen_ids)

        # Should have some generators with higher counts (weight effect)
        # At least one should appear multiple times if weights are working
        assert max(counts.values()) > 1, "Weights don't seem to be applied"


class TestCereggiiPluginAggregator:
    """Test the cereggii aggregator functionality."""

    def test_aggregator_imports_successfully(self):
        """Test that the aggregator module can be imported."""
        try:
            from fusil_cereggii_plugin import tricky_cereggii_aggregator
            assert tricky_cereggii_aggregator is not None
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

    def test_aggregator_has_code_snippets(self):
        """Test that the aggregator has code snippets."""
        try:
            from fusil_cereggii_plugin import tricky_cereggii_aggregator
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        assert hasattr(tricky_cereggii_aggregator, 'tricky_cereggii_code_snippets')
        snippets = tricky_cereggii_aggregator.tricky_cereggii_code_snippets
        assert isinstance(snippets, dict)
        assert len(snippets) > 0

    def test_aggregator_has_instance_name_lists(self):
        """Test that the aggregator has lists of instance names."""
        try:
            from fusil_cereggii_plugin import tricky_cereggii_aggregator
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        # Check for expected lists
        expected_lists = [
            'tricky_atomicint64_instance_names',
            'tricky_atomicdict_instance_names',
            'tricky_hashable_key_names',
        ]

        for list_name in expected_lists:
            assert hasattr(tricky_cereggii_aggregator, list_name), f"Missing {list_name}"

    def test_aggregator_populates_instance_names(self):
        """Test that instance name lists are populated."""
        try:
            from fusil_cereggii_plugin import tricky_cereggii_aggregator
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        # At least one list should have some names
        all_names = (
                tricky_cereggii_aggregator.tricky_atomicint64_instance_names +
                tricky_cereggii_aggregator.tricky_atomicdict_instance_names +
                tricky_cereggii_aggregator.tricky_hashable_key_names
        )
        assert len(all_names) > 0, "No instance names were aggregated"

    def test_code_snippets_are_strings_or_none(self):
        """Test that code snippets are valid strings or None."""
        try:
            from fusil_cereggii_plugin import tricky_cereggii_aggregator
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        snippets = tricky_cereggii_aggregator.tricky_cereggii_code_snippets
        for name, code in snippets.items():
            assert code is None or isinstance(code, str), f"Invalid code snippet for {name}"


class TestCereggiiPluginSampleModules:
    """Test that the sample modules can be imported and have expected exports."""

    def test_tricky_atomicint64_importable(self):
        """Test that tricky_atomicint64 module can be imported."""
        try:
            from fusil_cereggii_plugin.samples import tricky_atomicint64
            assert tricky_atomicint64 is not None
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

    def test_tricky_atomicint64_exports(self):
        """Test that tricky_atomicint64 has expected exports."""
        try:
            from fusil_cereggii_plugin.samples import tricky_atomicint64
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        assert hasattr(tricky_atomicint64, 'tricky_atomic_ints')
        assert hasattr(tricky_atomicint64, 'overflow_operands')
        assert hasattr(tricky_atomicint64, 'weird_callables')

        # Check they're the right types
        assert isinstance(tricky_atomicint64.tricky_atomic_ints, dict)
        assert isinstance(tricky_atomicint64.overflow_operands, list)
        assert isinstance(tricky_atomicint64.weird_callables, dict)

    def test_tricky_atomicdict_importable(self):
        """Test that tricky_atomicdict module can be imported."""
        try:
            from fusil_cereggii_plugin.samples import tricky_atomicdict
            assert tricky_atomicdict is not None
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

    def test_tricky_atomicdict_exports(self):
        """Test that tricky_atomicdict has expected exports."""
        try:
            from fusil_cereggii_plugin.samples import tricky_atomicdict
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        assert hasattr(tricky_atomicdict, 'tricky_hashable_keys')
        assert hasattr(tricky_atomicdict, 'tricky_atomic_dicts')

        # Check they're the right types
        assert isinstance(tricky_atomicdict.tricky_hashable_keys, dict)
        assert isinstance(tricky_atomicdict.tricky_atomic_dicts, dict)

    def test_tricky_colliding_keys_importable(self):
        """Test that tricky_colliding_keys module can be imported."""
        try:
            from fusil_cereggii_plugin.samples import tricky_colliding_keys
            assert tricky_colliding_keys is not None
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

    def test_tricky_atomicint_scenarios_importable(self):
        """Test that tricky_atomicint_scenarios module can be imported."""
        try:
            from fusil_cereggii_plugin.samples import tricky_atomicint_scenarios
            assert tricky_atomicint_scenarios is not None
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

    def test_tricky_atomicint_scenarios_exports(self):
        """Test that tricky_atomicint_scenarios has expected exports."""
        try:
            from fusil_cereggii_plugin.samples import tricky_atomicint_scenarios
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        assert hasattr(tricky_atomicint_scenarios, 'atomicint_scenarios')
        assert isinstance(tricky_atomicint_scenarios.atomicint_scenarios, dict)

        # Check that scenarios are callable
        for scenario_name, scenario_func in tricky_atomicint_scenarios.atomicint_scenarios.items():
            assert callable(scenario_func), f"Scenario {scenario_name} is not callable"


class TestCereggiiPluginFuzzingModeScript:
    """Test the fuzzing mode script generation."""

    def test_fuzzing_mode_setup_script_callable(self):
        """Test that the setup_script is callable."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mode = pm.fuzzing_modes['cereggii_scenario']
        assert callable(mode.setup_script)

    def test_fuzzing_mode_setup_script_accepts_writer(self):
        """Test that setup_script can be called with a mock writer."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()
        register(pm)

        mode = pm.fuzzing_modes['cereggii_scenario']

        # Create a mock WritePythonCode object
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.emptyLine = MagicMock()
        mock_writer.write_print_to_stderr = MagicMock()

        # This should not raise an exception
        try:
            mode.setup_script(mock_writer)
        except Exception as e:
            pytest.fail(f"setup_script raised exception: {e}")

        # Verify that write methods were called
        assert mock_writer.write.called or mock_writer.write_print_to_stderr.called


class TestCereggiiPluginGeneratorFallbacks:
    """Test that generators handle fallback cases correctly."""

    def test_generators_have_fallbacks_when_lists_empty(self):
        """Test that generators provide fallbacks when instance lists are empty."""
        try:
            from fusil_cereggii_plugin import register
        except ImportError:
            pytest.skip("Cereggii plugin not installed")

        pm = PluginManager()

        # Mock the aggregator to have empty lists
        with patch('fusil_cereggii_plugin.tricky_cereggii_aggregator') as mock_agg:
            mock_agg.tricky_atomicint64_instance_names = []
            mock_agg.tricky_atomicdict_instance_names = []
            mock_agg.tricky_hashable_key_names = []
            mock_agg.tricky_recursive_object_names = []
            mock_agg.tricky_weird_cereggii_instance_names = []
            mock_agg.tricky_threadhandle_instance_names = []

            register(pm)

            mock_config = Mock()
            mock_config.fuzz_cereggii_scenarios = False

            # Get generators and test they still work
            gens = pm.get_argument_generators(mock_config, 'cereggii', 'simple')

            for gen in gens[:3]:
                result = gen()
                assert isinstance(result, list)
                assert len(result) > 0
                # Should have fallback values
                assert result[0] is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
