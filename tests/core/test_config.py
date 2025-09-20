# tests/core/test_config.py

"""
Foundation-based configuration tests for RPC Plugin.

Tests the modern Foundation-based config system with direct attribute access,
automatic type conversion, and clean environment variable loading.
"""

import os
import pytest
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    configure,
    rpcplugin_config,
)
from provide.foundation.errors.config import ValidationError


@pytest.fixture(autouse=True)
def reset_global_config():
    """Reset global config to defaults before each test."""
    global rpcplugin_config
    rpcplugin_config.__dict__.clear()
    fresh_config = RPCPluginConfig.from_env()
    rpcplugin_config.__dict__.update(fresh_config.__dict__)
    
    yield
    
    # Reset after test as well
    rpcplugin_config.__dict__.clear()
    fresh_config = RPCPluginConfig.from_env()
    rpcplugin_config.__dict__.update(fresh_config.__dict__)


class TestFoundationConfigIntegration:
    """Test Foundation config integration with RPC plugin."""
    
    def test_direct_attribute_access(self):
        """Test direct attribute access works with defaults."""
        config = RPCPluginConfig.from_env()
        
        # Test basic attributes
        assert config.plugin_magic_cookie_value == "test_cookie_value"
        assert config.plugin_handshake_timeout == 10.0
        assert config.plugin_auto_mtls is True
        assert config.plugin_log_level == "INFO"
        
        # Test list attributes
        assert config.plugin_protocol_versions == [1]
        assert config.plugin_server_transports == ["unix", "tcp"]
    
    def test_environment_variable_loading(self, monkeypatch):
        """Test Foundation automatically loads from environment variables."""
        # Set environment variables
        monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_VALUE", "test-env-cookie")
        monkeypatch.setenv("PLUGIN_HANDSHAKE_TIMEOUT", "15.5")
        monkeypatch.setenv("PLUGIN_AUTO_MTLS", "false")
        monkeypatch.setenv("PLUGIN_LOG_LEVEL", "DEBUG")
        
        # Create fresh config instance
        config = RPCPluginConfig.from_env()
        
        # Verify environment values loaded
        assert config.plugin_magic_cookie_value == "test-env-cookie"
        assert config.plugin_handshake_timeout == 15.5
        assert config.plugin_auto_mtls is False
        assert config.plugin_log_level == "DEBUG"
    
    def test_automatic_list_int_conversion(self, monkeypatch):
        """Test Foundation automatically converts comma-separated strings to list[int]."""
        monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "2,3,4,5")
        
        config = RPCPluginConfig.from_env()
        
        assert config.plugin_protocol_versions == [2, 3, 4, 5]
        assert all(isinstance(v, int) for v in config.plugin_protocol_versions)
    
    def test_automatic_list_str_conversion(self, monkeypatch):
        """Test Foundation automatically converts comma-separated strings to list[str]."""
        monkeypatch.setenv("PLUGIN_SERVER_TRANSPORTS", "unix,tcp")
        
        config = RPCPluginConfig.from_env()
        
        assert config.plugin_server_transports == ["unix", "tcp"]
        assert all(isinstance(v, str) for v in config.plugin_server_transports)
    
    def test_boolean_conversion(self, monkeypatch):
        """Test Foundation automatically converts boolean strings."""
        test_cases = [
            ("true", True),
            ("false", False),
            ("True", True),
            ("False", False),
            ("1", True),
            ("0", False),
            ("yes", True),
            ("no", False),
        ]
        
        for env_value, expected in test_cases:
            monkeypatch.setenv("PLUGIN_AUTO_MTLS", env_value)
            config = RPCPluginConfig.from_env()
            assert config.plugin_auto_mtls is expected


class TestHelperMethods:
    """Test config helper methods work with Foundation attributes."""
    
    def test_helper_methods_use_attributes(self):
        """Test helper methods return correct attribute values."""
        config = RPCPluginConfig.from_env()
        
        # Test helper methods match direct attributes
        assert config.magic_cookie_key() == config.plugin_magic_cookie_key
        assert config.magic_cookie_value() == config.plugin_magic_cookie_value
        assert config.handshake_timeout() == config.plugin_handshake_timeout
        assert config.connection_timeout() == config.plugin_connection_timeout
        assert config.server_transports() == config.plugin_server_transports
        assert config.client_transports() == config.plugin_client_transports
        assert config.protocol_versions() == config.plugin_protocol_versions
        
        # Test additional helper methods
        assert config.auto_mtls_enabled() == config.plugin_auto_mtls
        assert config.rate_limit_enabled() == config.plugin_rate_limit_enabled


class TestValidation:
    """Test Foundation field validation works properly."""
    
    def test_protocol_version_validation(self, monkeypatch):
        """Test protocol version validation rejects invalid values."""
        monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "8,9,10")  # Invalid versions

        with pytest.raises(ValueError) as exc_info:
            RPCPluginConfig.from_env()

        assert "Protocol version must be between 1 and 7" in str(exc_info.value)
    
    def test_log_level_validation(self, monkeypatch):
        """Test log level validation rejects invalid values."""
        monkeypatch.setenv("PLUGIN_LOG_LEVEL", "INVALID_LEVEL")

        with pytest.raises(ValueError) as exc_info:
            RPCPluginConfig.from_env()

        assert "INVALID_LEVEL" in str(exc_info.value)
    
    def test_transport_validation(self, monkeypatch):
        """Test transport validation rejects invalid combinations."""
        monkeypatch.setenv("PLUGIN_SERVER_TRANSPORTS", "invalid,transport")

        with pytest.raises(ValueError) as exc_info:
            RPCPluginConfig.from_env()
        
        assert "Invalid transport" in str(exc_info.value)


class TestConfigureFunction:
    """Test the configure() helper function works with Foundation config."""
    
    def test_configure_basic_options(self):
        """Test configure() updates config attributes directly."""
        # Call configure with test values
        configure(
            magic_cookie="test-configured-cookie",
            protocol_version=2,
            handshake_timeout=20.0,
            auto_mtls=False,
        )
        
        # Verify global config was updated
        assert rpcplugin_config.plugin_magic_cookie_value == "test-configured-cookie"
        assert rpcplugin_config.plugin_core_version == 2
        assert rpcplugin_config.plugin_protocol_versions == [2]
        assert rpcplugin_config.plugin_handshake_timeout == 20.0
        assert rpcplugin_config.plugin_auto_mtls is False
    
    def test_configure_transports(self):
        """Test configure() sets both server and client transports."""
        configure(transports=["tcp"])
        
        assert rpcplugin_config.plugin_server_transports == ["tcp"]
        assert rpcplugin_config.plugin_client_transports == ["tcp"]


class TestGlobalConfigInstance:
    """Test the global rpcplugin_config instance."""
    
    def test_global_instance_exists(self):
        """Test global config instance is available."""
        assert rpcplugin_config is not None
        assert isinstance(rpcplugin_config, RPCPluginConfig)
    
    def test_global_instance_has_defaults(self):
        """Test global instance has expected default values."""
        fresh_config = RPCPluginConfig.from_env()
        assert fresh_config.plugin_magic_cookie_value == "test_cookie_value"
        assert fresh_config.plugin_handshake_timeout == 10.0
        assert fresh_config.plugin_protocol_versions == [1]


# 🐍🔌🧪✨ Foundation-powered tests