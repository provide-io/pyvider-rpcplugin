"""
Tests for configuration manager integration.

This module tests the ConfigManager integration for managing multiple
RPC plugin configurations. Targets 100% code coverage.
"""

import pytest

from pyvider.rpcplugin.config import RPCPluginConfig
from pyvider.rpcplugin.config.manager import (
    clear_plugin_configs,
    export_all_plugin_configs,
    export_plugin_config,
    get_plugin_config,
    get_plugin_config_manager,
    list_plugin_configs,
    register_plugin_config,
    unregister_plugin_config,
    update_plugin_config,
)


class TestConfigManager:
    """Test config manager basic functionality."""

    def setup_method(self) -> None:
        """Clear configs before each test."""
        clear_plugin_configs()

    def teardown_method(self) -> None:
        """Clear configs after each test."""
        clear_plugin_configs()

    def test_get_plugin_config_manager(self) -> None:
        """Test getting the global config manager instance."""
        manager1 = get_plugin_config_manager()
        manager2 = get_plugin_config_manager()
        # Should return the same instance
        assert manager1 is manager2

    def test_register_and_get_plugin_config(self) -> None:
        """Test registering and retrieving a plugin config."""
        config = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("server1", config)

        retrieved = get_plugin_config("server1")
        assert retrieved is not None
        assert retrieved.plugin_server_port == 8080

    def test_get_nonexistent_config(self) -> None:
        """Test getting a config that doesn't exist."""
        result = get_plugin_config("nonexistent")
        assert result is None

    def test_register_duplicate_config_raises_error(self) -> None:
        """Test that registering duplicate config raises an error."""
        config1 = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("server1", config1)

        config2 = RPCPluginConfig(plugin_server_port=9000)
        with pytest.raises(ValueError, match="already registered"):
            register_plugin_config("server1", config2)

    def test_unregister_plugin_config(self) -> None:
        """Test unregistering a plugin config."""
        config = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("server1", config)
        assert get_plugin_config("server1") is not None

        unregister_plugin_config("server1")
        assert get_plugin_config("server1") is None

    def test_unregister_nonexistent_config(self) -> None:
        """Test unregistering a config that doesn't exist (should not raise)."""
        # Should not raise an error
        unregister_plugin_config("nonexistent")

    def test_list_plugin_configs(self) -> None:
        """Test listing registered plugin configs."""
        config1 = RPCPluginConfig(plugin_server_port=8080)
        config2 = RPCPluginConfig(plugin_server_port=9000)
        config3 = RPCPluginConfig(plugin_client_max_retries=10)

        register_plugin_config("server1", config1)
        register_plugin_config("server2", config2)
        register_plugin_config("client1", config3)

        configs = list_plugin_configs()
        assert len(configs) == 3
        assert "server1" in configs
        assert "server2" in configs
        assert "client1" in configs

    def test_list_plugin_configs_empty(self) -> None:
        """Test listing configs when none are registered."""
        configs = list_plugin_configs()
        assert configs == []

    def test_update_plugin_config(self) -> None:
        """Test updating a registered config."""
        config = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("server1", config)

        update_plugin_config("server1", {"plugin_server_port": 9000})

        retrieved = get_plugin_config("server1")
        assert retrieved.plugin_server_port == 9000

    def test_update_nonexistent_config_raises_error(self) -> None:
        """Test updating a config that doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            update_plugin_config("nonexistent", {"plugin_server_port": 9000})

    def test_export_plugin_config(self) -> None:
        """Test exporting a config to dictionary."""
        config = RPCPluginConfig(plugin_server_port=8080, plugin_server_host="example.com")
        register_plugin_config("server1", config)

        exported = export_plugin_config("server1")
        assert isinstance(exported, dict)
        assert exported["plugin_server_port"] == 8080
        assert exported["plugin_server_host"] == "example.com"

    def test_export_plugin_config_without_sensitive(self) -> None:
        """Test exporting config without sensitive fields."""
        config = RPCPluginConfig(
            plugin_server_port=8080,
            plugin_client_key="secret-key",
        )
        register_plugin_config("server1", config)

        exported = export_plugin_config("server1", include_sensitive=False)
        # Sensitive fields should be excluded or masked
        assert isinstance(exported, dict)

    def test_export_plugin_config_with_sensitive(self) -> None:
        """Test exporting config with sensitive fields."""
        config = RPCPluginConfig(
            plugin_server_port=8080,
            plugin_client_key="secret-key",
        )
        register_plugin_config("server1", config)

        exported = export_plugin_config("server1", include_sensitive=True)
        assert isinstance(exported, dict)
        # When include_sensitive=True, sensitive fields should be present
        assert "plugin_client_key" in exported

    def test_export_nonexistent_config_raises_error(self) -> None:
        """Test exporting a config that doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            export_plugin_config("nonexistent")

    def test_export_all_plugin_configs(self) -> None:
        """Test exporting all configs."""
        config1 = RPCPluginConfig(plugin_server_port=8080)
        config2 = RPCPluginConfig(plugin_server_port=9000)

        register_plugin_config("server1", config1)
        register_plugin_config("server2", config2)

        all_configs = export_all_plugin_configs()
        assert len(all_configs) == 2
        assert "server1" in all_configs
        assert "server2" in all_configs
        assert all_configs["server1"]["plugin_server_port"] == 8080
        assert all_configs["server2"]["plugin_server_port"] == 9000

    def test_export_all_plugin_configs_empty(self) -> None:
        """Test exporting all configs when none are registered."""
        all_configs = export_all_plugin_configs()
        assert all_configs == {}

    def test_export_all_with_sensitive(self) -> None:
        """Test exporting all configs with sensitive fields."""
        config1 = RPCPluginConfig(plugin_server_port=8080, plugin_client_key="key1")
        config2 = RPCPluginConfig(plugin_server_port=9000, plugin_client_key="key2")

        register_plugin_config("server1", config1)
        register_plugin_config("server2", config2)

        all_configs = export_all_plugin_configs(include_sensitive=True)
        assert len(all_configs) == 2
        assert "plugin_client_key" in all_configs["server1"]
        assert "plugin_client_key" in all_configs["server2"]

    def test_clear_plugin_configs(self) -> None:
        """Test clearing all registered configs."""
        config1 = RPCPluginConfig(plugin_server_port=8080)
        config2 = RPCPluginConfig(plugin_server_port=9000)

        register_plugin_config("server1", config1)
        register_plugin_config("server2", config2)
        assert len(list_plugin_configs()) == 2

        clear_plugin_configs()
        assert list_plugin_configs() == []

    def test_clear_plugin_configs_when_empty(self) -> None:
        """Test clearing configs when none are registered."""
        # Should not raise an error
        clear_plugin_configs()
        assert list_plugin_configs() == []


class TestConfigManagerMultiInstance:
    """Test managing multiple config instances."""

    def setup_method(self) -> None:
        """Clear configs before each test."""
        clear_plugin_configs()

    def teardown_method(self) -> None:
        """Clear configs after each test."""
        clear_plugin_configs()

    def test_multiple_server_configs(self) -> None:
        """Test managing multiple server configs."""
        server1 = RPCPluginConfig(plugin_server_port=8080, plugin_server_host="host1")
        server2 = RPCPluginConfig(plugin_server_port=9000, plugin_server_host="host2")
        server3 = RPCPluginConfig(plugin_server_port=9090, plugin_server_host="host3")

        register_plugin_config("server1", server1)
        register_plugin_config("server2", server2)
        register_plugin_config("server3", server3)

        # Verify all are registered
        assert len(list_plugin_configs()) == 3

        # Verify each can be retrieved correctly
        assert get_plugin_config("server1").plugin_server_port == 8080
        assert get_plugin_config("server2").plugin_server_port == 9000
        assert get_plugin_config("server3").plugin_server_port == 9090

    def test_mixed_server_and_client_configs(self) -> None:
        """Test managing both server and client configs."""
        server_config = RPCPluginConfig(plugin_server_port=8080)
        client_config = RPCPluginConfig(plugin_client_max_retries=10)

        register_plugin_config("server", server_config)
        register_plugin_config("client", client_config)

        # Verify both are accessible
        server = get_plugin_config("server")
        client = get_plugin_config("client")

        assert server.plugin_server_port == 8080
        assert client.plugin_client_max_retries == 10

    def test_update_one_config_doesnt_affect_others(self) -> None:
        """Test that updating one config doesn't affect others."""
        config1 = RPCPluginConfig(plugin_server_port=8080)
        config2 = RPCPluginConfig(plugin_server_port=9000)

        register_plugin_config("server1", config1)
        register_plugin_config("server2", config2)

        # Update server1
        update_plugin_config("server1", {"plugin_server_port": 8888})

        # Verify server1 was updated
        assert get_plugin_config("server1").plugin_server_port == 8888

        # Verify server2 was not affected
        assert get_plugin_config("server2").plugin_server_port == 9000


class TestConfigManagerEdgeCases:
    """Test edge cases and error conditions."""

    def setup_method(self) -> None:
        """Clear configs before each test."""
        clear_plugin_configs()

    def teardown_method(self) -> None:
        """Clear configs after each test."""
        clear_plugin_configs()

    def test_config_with_all_defaults(self) -> None:
        """Test registering a config with all default values."""
        config = RPCPluginConfig()
        register_plugin_config("defaults", config)

        retrieved = get_plugin_config("defaults")
        assert retrieved is not None
        assert retrieved.plugin_server_port == config.plugin_server_port

    def test_config_with_custom_values(self) -> None:
        """Test registering a config with many custom values."""
        config = RPCPluginConfig(
            plugin_server_port=8080,
            plugin_server_host="example.com",
            plugin_client_max_retries=10,
            plugin_handshake_timeout=60.0,
            plugin_connection_timeout=30.0,
        )
        register_plugin_config("custom", config)

        retrieved = get_plugin_config("custom")
        assert retrieved.plugin_server_port == 8080
        assert retrieved.plugin_server_host == "example.com"
        assert retrieved.plugin_client_max_retries == 10
        assert retrieved.plugin_handshake_timeout == 60.0
        assert retrieved.plugin_connection_timeout == 30.0

    def test_register_unregister_register_same_name(self) -> None:
        """Test registering, unregistering, then re-registering with same name."""
        config1 = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("server", config1)

        unregister_plugin_config("server")

        # Should be able to register again with same name
        config2 = RPCPluginConfig(plugin_server_port=9000)
        register_plugin_config("server", config2)

        retrieved = get_plugin_config("server")
        assert retrieved.plugin_server_port == 9000

    def test_multiple_updates_to_same_config(self) -> None:
        """Test multiple consecutive updates to the same config."""
        config = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("server", config)

        update_plugin_config("server", {"plugin_server_port": 9000})
        assert get_plugin_config("server").plugin_server_port == 9000

        update_plugin_config("server", {"plugin_server_port": 9999})
        assert get_plugin_config("server").plugin_server_port == 9999

        update_plugin_config("server", {"plugin_server_host": "updated.com"})
        # Port should still be 9999, host should be updated
        retrieved = get_plugin_config("server")
        assert retrieved.plugin_server_port == 9999
        assert retrieved.plugin_server_host == "updated.com"


class TestConfigManagerIntegration:
    """Test integration with the underlying Foundation ConfigManager."""

    def setup_method(self) -> None:
        """Clear configs before each test."""
        clear_plugin_configs()

    def teardown_method(self) -> None:
        """Clear configs after each test."""
        clear_plugin_configs()

    def test_manager_singleton_behavior(self) -> None:
        """Test that the config manager is a singleton."""
        # Register a config
        config = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("test", config)

        # Get manager multiple times
        manager1 = get_plugin_config_manager()
        manager2 = get_plugin_config_manager()

        # Should be the same instance
        assert manager1 is manager2

        # Should both see the registered config
        assert manager1.get("test") is not None
        assert manager2.get("test") is not None

    def test_direct_manager_access(self) -> None:
        """Test accessing the manager directly."""
        manager = get_plugin_config_manager()
        config = RPCPluginConfig(plugin_server_port=8080)

        # Register directly through manager
        manager.register("direct", config=config)

        # Should be accessible through helper functions
        retrieved = get_plugin_config("direct")
        assert retrieved is not None
        assert retrieved.plugin_server_port == 8080

    def test_manager_operations_are_consistent(self) -> None:
        """Test that manager operations maintain consistency."""
        config = RPCPluginConfig(plugin_server_port=8080)
        register_plugin_config("test", config)

        # Operations should be consistent
        assert "test" in list_plugin_configs()
        assert get_plugin_config("test") is not None
        assert len(export_all_plugin_configs()) == 1

        unregister_plugin_config("test")

        # After unregister, all operations should reflect removal
        assert "test" not in list_plugin_configs()
        assert get_plugin_config("test") is None
        assert len(export_all_plugin_configs()) == 0
