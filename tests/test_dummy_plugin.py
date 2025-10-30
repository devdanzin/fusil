"""
Tests for the dummy plugin functionality.

Run with: pytest test_dummy_plugin.py -v
"""

import pytest
from unittest.mock import Mock, patch
from fusil.plugin_manager import PluginManager


class TestDummyPluginInstallation:
    """Test that the dummy plugin is correctly installed and discoverable."""

    def test_dummy_plugin_entry_point_exists(self):
        """Test that the dummy plugin entry point is registered."""
        try:
            from importlib.metadata import entry_points
            import sys

            if sys.version_info >= (3, 10):
                eps = entry_points(group='fusil.plugins')
            else:
                eps = entry_points().get('fusil.plugins', [])

            dummy_ep = [ep for ep in eps if ep.name == 'dummy']
            assert len(
                dummy_ep) > 0, "Dummy plugin entry point not found. Make sure to install it with 'pip install -e fusil-dummy-plugin'"
        except ImportError:
            pytest.skip("Dummy plugin not installed")

    def test_dummy_plugin_module_importable(self):
        """Test that the dummy plugin module can be imported."""
        try:
            import fusil_dummy_plugin
            assert hasattr(fusil_dummy_plugin, 'register')
        except ImportError:
            pytest.skip("Dummy plugin not installed")


class TestDummyPluginRegistration:
    """Test that the dummy plugin registers its components correctly."""

    def test_dummy_plugin_registers_cli_option(self):
        """Test that the dummy plugin adds its CLI option."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        # Check that --dummy-option was added
        cli_opts = pm.get_cli_options()
        assert len(cli_opts) > 0

        option_names = [args[0] for args, kwargs in cli_opts]
        assert '--dummy-option' in option_names

    def test_dummy_plugin_registers_argument_generator(self):
        """Test that the dummy plugin registers its argument generator."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        # The generator should only be active when dummy_option is True
        mock_config_enabled = Mock()
        mock_config_enabled.dummy_option = True

        mock_config_disabled = Mock()
        mock_config_disabled.dummy_option = False

        gens_enabled = pm.get_argument_generators(mock_config_enabled, 'test', 'simple')
        gens_disabled = pm.get_argument_generators(mock_config_disabled, 'test', 'simple')

        # Should have generator when enabled
        assert len(gens_enabled) > 0
        # Should not have generator when disabled
        assert len(gens_disabled) == 0

    def test_dummy_generator_produces_correct_output(self):
        """Test that the dummy generator produces the expected output."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.dummy_option = True

        gens = pm.get_argument_generators(mock_config, 'test', 'simple')

        # Call the generator
        assert len(gens) > 0
        result = gens[0]()

        # Should return a list with the dummy value
        assert isinstance(result, list)
        assert len(result) == 1
        assert 'DUMMY_VALUE_FROM_PLUGIN' in result[0]

    def test_dummy_plugin_registers_definitions_provider(self):
        """Test that the dummy plugin provides definitions."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config_enabled = Mock()
        mock_config_enabled.dummy_option = True

        mock_config_disabled = Mock()
        mock_config_disabled.dummy_option = False

        defs_enabled = pm.get_definitions(mock_config_enabled, 'test')
        defs_disabled = pm.get_definitions(mock_config_disabled, 'test')

        # Should provide definitions when enabled
        assert len(defs_enabled) > 0
        assert 'DUMMY_CONSTANT' in defs_enabled[0]
        assert 'dummy_function' in defs_enabled[0]

        # Should not provide definitions when disabled
        assert len(defs_disabled) == 0

    def test_dummy_plugin_registers_hooks(self):
        """Test that the dummy plugin registers startup and shutdown hooks."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        # Check that hooks were registered
        assert len(pm.hooks['startup']) > 0
        assert len(pm.hooks['shutdown']) > 0

    def test_dummy_plugin_startup_hook_executes(self):
        """Test that the startup hook executes without errors."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        mock_config = Mock()
        mock_config.dummy_option = True

        # This should not raise an exception
        pm.run_hooks('startup', mock_config)

    def test_dummy_plugin_shutdown_hook_executes(self):
        """Test that the shutdown hook executes without errors."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        # This should not raise an exception
        pm.run_hooks('shutdown')


class TestDummyPluginIntegration:
    """Test dummy plugin integration with PluginManager."""

    def test_dummy_plugin_loads_via_discovery(self):
        """Test that the dummy plugin is loaded when discovering plugins."""
        try:
            from importlib.metadata import entry_points
            import sys

            if sys.version_info >= (3, 10):
                eps = entry_points(group='fusil.plugins')
            else:
                eps = entry_points().get('fusil.plugins', [])

            dummy_eps = [ep for ep in eps if ep.name == 'dummy']
            if not dummy_eps:
                pytest.skip("Dummy plugin not installed")
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        pm.discover_and_load_plugins()

        # Check that dummy plugin was loaded
        assert 'dummy' in pm.plugins

        # Check that its components were registered
        assert len(pm.cli_options) > 0
        assert len(pm.argument_generators) > 0
        assert len(pm.definitions_providers) > 0

    def test_multiple_plugins_coexist(self):
        """Test that dummy plugin can coexist with other plugins."""
        try:
            from importlib.metadata import entry_points
            import sys

            if sys.version_info >= (3, 10):
                eps = entry_points(group='fusil.plugins')
            else:
                eps = entry_points().get('fusil.plugins', [])

            if len([ep for ep in eps if ep.name == 'dummy']) == 0:
                pytest.skip("Dummy plugin not installed")
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        pm.discover_and_load_plugins()

        # Should load at least the dummy plugin
        assert len(pm.plugins) >= 1
        assert 'dummy' in pm.plugins


class TestDummyPluginConditions:
    """Test that the dummy plugin's conditions work correctly."""

    def test_generator_only_active_when_option_enabled(self):
        """Test that the generator respects the --dummy-option flag."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        # Config with option disabled (default)
        config_disabled = Mock()
        config_disabled.dummy_option = False

        # Config with option enabled
        config_enabled = Mock()
        config_enabled.dummy_option = True

        gens_disabled = pm.get_argument_generators(config_disabled, 'any_module', 'simple')
        gens_enabled = pm.get_argument_generators(config_enabled, 'any_module', 'simple')

        assert len(gens_disabled) == 0
        assert len(gens_enabled) > 0

    def test_definitions_only_provided_when_option_enabled(self):
        """Test that definitions are only provided when option is enabled."""
        try:
            from fusil_dummy_plugin import register
        except ImportError:
            pytest.skip("Dummy plugin not installed")

        pm = PluginManager()
        register(pm)

        config_disabled = Mock()
        config_disabled.dummy_option = False

        config_enabled = Mock()
        config_enabled.dummy_option = True

        defs_disabled = pm.get_definitions(config_disabled, 'any_module')
        defs_enabled = pm.get_definitions(config_enabled, 'any_module')

        assert len(defs_disabled) == 0
        assert len(defs_enabled) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])