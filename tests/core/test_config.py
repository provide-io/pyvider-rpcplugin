# tests/rpcplugin/test_config.py

import os

import pytest
from unittest.mock import patch, mock_open, call

from pyvider.rpcplugin.config import (
    fetch_env_variable,
    validate_config_value,
    get_config,
    RPCPluginConfig,
    configure,
    ConfigError,
    CONFIG_SCHEMA,
)


# Tests for fetch_env_variable
def test_fetch_env_variable_from_os_environ(monkeypatch):
    """Test fetching a string variable from os.environ."""
    key = "PLUGIN_MAGIC_COOKIE_VALUE"
    expected_value = "test-cookie-from-env"
    monkeypatch.setenv(key, expected_value)
    meta = CONFIG_SCHEMA[key]

    assert fetch_env_variable(key, meta) == expected_value


def test_fetch_env_variable_default_value(monkeypatch):
    """Test fetching a variable using its default value."""
    key = "PLUGIN_LOG_LEVEL"  # This key has a default in CONFIG_SCHEMA
    monkeypatch.delenv(key, raising=False) # Ensure it's not set

    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == meta["default"]


def test_fetch_env_variable_none_default(monkeypatch):
    """Test fetching a variable that has a default of None."""
    key = "PLUGIN_SERVER_ENDPOINT"  # Default is None
    monkeypatch.delenv(key, raising=False)
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) is None


def test_fetch_env_variable_type_conversion_int(monkeypatch):
    """Test type conversion to int."""
    key = "PLUGIN_CORE_VERSION"
    monkeypatch.setenv(key, "123")
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == 123


def test_fetch_env_variable_type_conversion_bool_true(monkeypatch):
    """Test type conversion to bool (True variants)."""
    key = "PLUGIN_AUTO_MTLS"
    meta = CONFIG_SCHEMA[key]
    for true_val in ["true", "YES", "1", "oN"]:
        monkeypatch.setenv(key, true_val)
        assert fetch_env_variable(key, meta) is True


def test_fetch_env_variable_type_conversion_bool_false(monkeypatch):
    """Test type conversion to bool (False variants)."""
    key = "PLUGIN_AUTO_MTLS"
    meta = CONFIG_SCHEMA[key]
    for false_val in ["false", "NO", "0", "oFF", "anyotherstring"]:
        monkeypatch.setenv(key, false_val)
        assert fetch_env_variable(key, meta) is False

    # Test with actual boolean default if env var is missing
    monkeypatch.delenv(key, raising=False)
    # Temporarily modify meta for this specific default test case
    original_default = meta["default"]
    meta["default"] = False
    assert fetch_env_variable(key, meta) is False
    meta["default"] = True
    assert fetch_env_variable(key, meta) is True
    meta["default"] = original_default  # restore


def test_fetch_env_variable_type_conversion_list_str(monkeypatch):
    """Test type conversion to list[str]."""
    key = "PLUGIN_SERVER_TRANSPORTS"
    monkeypatch.setenv(key, "unix, tcp , http")  # Note spaces
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == ["unix", "tcp", "http"]


def test_fetch_env_variable_type_conversion_list_int(monkeypatch):
    """Test type conversion to list[int]."""
    key = "PLUGIN_PROTOCOL_VERSIONS"
    monkeypatch.setenv(key, "1, 2 , 5")  # Note spaces
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == [1, 2, 5]

    # Test with actual list default
    monkeypatch.delenv(key, raising=False)
    meta = CONFIG_SCHEMA[key]  # Use original meta with list default
    assert fetch_env_variable(key, meta) == meta["default"]


def test_fetch_env_variable_invalid_type_conversion(monkeypatch):
    """Test error handling for invalid type conversion (e.g., int from non-int string)."""
    key = "PLUGIN_CORE_VERSION"  # Expects int
    monkeypatch.setenv(key, "not-an-int")
    meta = CONFIG_SCHEMA[key]

    with pytest.raises(
        ConfigError,
        match=f"Invalid value format for configuration key '{key}'.*Expected type 'int'",
    ):
        fetch_env_variable(key, meta)


# Tests for validate_config_value
def test_validate_config_value_valid():
    """Test validate_config_value with various valid inputs."""
    key = "PLUGIN_LOG_LEVEL"  # Has valid_values
    meta = CONFIG_SCHEMA[key]
    assert validate_config_value(key, "INFO", meta) is True

    key_no_valid_values = "PLUGIN_MAGIC_COOKIE_VALUE"  # No valid_values list
    meta_no_valid_values = CONFIG_SCHEMA[key_no_valid_values]
    assert (
        validate_config_value(key_no_valid_values, "any-cookie", meta_no_valid_values)
        is True
    )

    key_required = "PLUGIN_MAGIC_COOKIE"  # Is required
    meta_required = CONFIG_SCHEMA[key_required]
    assert validate_config_value(key_required, "a-cookie", meta_required) is True


def test_validate_config_value_missing_required():
    """Test validate_config_value raises ValueError for missing required value."""
    key = "PLUGIN_MAGIC_COOKIE_KEY"  # Is required
    meta = CONFIG_SCHEMA[key]
    with pytest.raises(
        ConfigError, match=f"Missing required configuration key: '{key}'"
    ):
        validate_config_value(key, None, meta)


def test_validate_config_value_none_for_not_required():
    """Test validate_config_value passes for None if not required."""
    key = "PLUGIN_SERVER_ENDPOINT"  # Not required, default is None
    meta = CONFIG_SCHEMA[key]
    assert validate_config_value(key, None, meta) is True


def test_validate_config_value_invalid_choice():
    """Test validate_config_value raises ValueError for value not in valid_values."""
    key = "PLUGIN_LOG_LEVEL"
    meta = CONFIG_SCHEMA[key]
    invalid_level = "TRACE"
    expected_message = f"Invalid value '{invalid_level}' provided for configuration key '{key}'.*Allowed values are:.*{meta['valid_values']}"
    with pytest.raises(ConfigError, match=expected_message):
        validate_config_value(key, invalid_level, meta)


# Tests for get_config
@patch("pyvider.rpcplugin.config.validate_config_value")
@patch("pyvider.rpcplugin.config.fetch_env_variable")
def test_get_config_success(mock_fetch, mock_validate):
    """Test get_config successfully builds config dictionary."""
    mock_fetch.side_effect = lambda key, meta: f"fetched_value_for_{key}"
    mock_validate.return_value = True

    config = get_config()

    assert len(config) == len(CONFIG_SCHEMA)
    for key, meta_val in CONFIG_SCHEMA.items():
        mock_fetch.assert_any_call(key, meta_val)
        mock_validate.assert_any_call(key, f"fetched_value_for_{key}", meta_val)
        assert config[key] == f"fetched_value_for_{key}"


@patch("pyvider.rpcplugin.config.validate_config_value")
@patch("pyvider.rpcplugin.config.fetch_env_variable")
def test_get_config_fetch_raises_error(mock_fetch, mock_validate):
    """Test get_config when fetch_env_variable raises an error."""
    error_key = "PLUGIN_MAGIC_COOKIE_VALUE"
    mock_fetch.side_effect = (
        lambda key, meta: (_ for _ in ()).throw(ValueError("Fetch failed"))
        if key == error_key
        else "ok"
    )

    # FIX: Expect ConfigError as get_config wraps the exception
    with pytest.raises(ConfigError, match="Unexpected validation or fetch error for PLUGIN_MAGIC_COOKIE_VALUE: Fetch failed"):
        get_config()

    for call_args in mock_validate.call_args_list:
        assert call_args[0][0] != error_key


@patch("pyvider.rpcplugin.config.validate_config_value")
@patch("pyvider.rpcplugin.config.fetch_env_variable")
def test_get_config_validate_raises_error(mock_fetch, mock_validate):
    """Test get_config when validate_config_value raises an error."""
    error_key = "PLUGIN_LOG_LEVEL"
    mock_fetch.return_value = "fetched_value"
    mock_validate.side_effect = (
        lambda key, value, meta: (_ for _ in ()).throw(ValueError("Validate failed"))
        if key == error_key
        else True
    )

    # FIX: Expect ConfigError as get_config wraps the exception
    with pytest.raises(ConfigError, match="Unexpected validation or fetch error for PLUGIN_LOG_LEVEL: Validate failed"):
        get_config()

    mock_fetch.assert_any_call(error_key, CONFIG_SCHEMA[error_key])
    mock_validate.assert_any_call(error_key, "fetched_value", CONFIG_SCHEMA[error_key])


# Tests for RPCPluginConfig
def test_rpcpluginconfig_singleton():
    """Test RPCPluginConfig is a singleton."""
    instance1 = RPCPluginConfig.instance()
    instance2 = RPCPluginConfig.instance()
    assert instance1 is instance2
    RPCPluginConfig._instance = None
    instance3 = RPCPluginConfig.instance()
    assert instance1 is not instance3
    assert instance3 is RPCPluginConfig.instance()


@patch("pyvider.rpcplugin.config.get_config")
def test_rpcpluginconfig_initialization(mock_get_config):
    """Test RPCPluginConfig initialization loads config via get_config."""
    expected_config = {"TEST_KEY": "test_value"}
    mock_get_config.return_value = expected_config

    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()

    mock_get_config.assert_called_once()
    assert config_manager.config == expected_config


@patch("pyvider.rpcplugin.config.get_config")
def test_rpcpluginconfig_initialization_error(mock_get_config):
    """Test RPCPluginConfig initialization re-raises errors from get_config."""
    mock_get_config.side_effect = ValueError("Init failed")

    RPCPluginConfig._instance = None
    with pytest.raises(ValueError, match="Init failed"):
        RPCPluginConfig.instance()
    mock_get_config.assert_called_once()


def test_rpcpluginconfig_get_existing_key():
    """Test get() method for an existing key."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "PLUGIN_MAGIC_COOKIE_VALUE"
    expected_value = CONFIG_SCHEMA[key]["default"]
    assert config_manager.get(key) == expected_value


def test_rpcpluginconfig_get_non_existing_key_with_default():
    """Test get() method for a non-existing key with a provided default."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    default_val = "my_custom_default"
    assert config_manager.get("NON_EXISTENT_KEY_XYZ", default_val) == default_val


def test_rpcpluginconfig_get_non_existing_key_no_default():
    """Test get() method for a non-existing key without a default (should be None)."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    assert config_manager.get("NON_EXISTENT_KEY_ABC") is None


def test_rpcpluginconfig_get_list():
    """Test get_list() method."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "PLUGIN_SERVER_TRANSPORTS"
    expected_list = CONFIG_SCHEMA[key]["default"]
    assert config_manager.get_list(key) == expected_list

    config_manager.set(key, "single_value")
    assert config_manager.get_list(key) == ["single_value"]

    assert config_manager.get_list("NON_EXISTENT_LIST_KEY") == []


def test_rpcpluginconfig_set_known_key():
    """Test set() method for a known key from CONFIG_SCHEMA."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "PLUGIN_LOG_LEVEL"
    new_value = "DEBUG"
    config_manager.set(key, new_value)
    assert config_manager.get(key) == new_value


def test_rpcpluginconfig_set_unknown_key_plugin_prefix():
    """Test set() method for an unknown key that starts with PLUGIN_."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "PLUGIN_MY_CUSTOM_SETTING"
    value = "custom_value"
    config_manager.set(key, value)
    assert config_manager.get(key) == value


def test_rpcpluginconfig_set_unknown_key_no_prefix_raises_error():
    """Test set() method for an unknown key without PLUGIN_ prefix raises KeyError."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "MY_OTHER_CUSTOM_SETTING"
    value = "another_value"
    with pytest.raises(
        ConfigError, match=f"Attempted to set an unknown configuration key: '{key}'."
    ):
        config_manager.set(key, value)


def test_rpcpluginconfig_helper_methods():
    """Test various helper methods of RPCPluginConfig."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()

    config_manager.config["PLUGIN_MAGIC_COOKIE_KEY"] = "TestCookieKey"
    config_manager.config["PLUGIN_MAGIC_COOKIE_VALUE"] = "TestCookieValue123"
    config_manager.config["PLUGIN_SERVER_TRANSPORTS"] = ["test_unix", "test_tcp"]
    config_manager.config["PLUGIN_SERVER_ENDPOINT"] = "/tmp/test.sock"
    config_manager.config["PLUGIN_CLIENT_TRANSPORTS"] = ["test_tcp"]
    config_manager.config["PLUGIN_CLIENT_ENDPOINT"] = "localhost:1234"
    config_manager.config["PLUGIN_AUTO_MTLS"] = True
    config_manager.config["PLUGIN_HANDSHAKE_TIMEOUT"] = 15.5
    config_manager.config["PLUGIN_CONNECTION_TIMEOUT"] = 35.0

    assert config_manager.magic_cookie_key() == "TestCookieKey"
    assert config_manager.magic_cookie_value() == "TestCookieValue123"
    assert config_manager.server_transports() == ["test_unix", "test_tcp"]
    assert config_manager.server_endpoint() == "/tmp/test.sock"
    assert config_manager.client_transports() == ["test_tcp"]
    assert config_manager.client_endpoint() == "localhost:1234"
    assert config_manager.auto_mtls_enabled() is True
    assert config_manager.handshake_timeout() == 15.5
    assert config_manager.connection_timeout() == 35.0

    config_manager.config["PLUGIN_AUTO_MTLS"] = False
    assert config_manager.auto_mtls_enabled() is False


# Tests for configure function
@patch("pyvider.rpcplugin.config.rpcplugin_config.set")
def test_configure_all_options(mock_rpc_set):
    """Test configure function with all its defined parameters."""
    configure(
        magic_cookie="test-cookie",
        protocol_version=5,
        transports=["unix", "tcp"],
        auto_mtls=True,
        handshake_timeout=20.0,
        connection_timeout=60.0,
        server_cert="path/to/server.crt",
        server_key="path/to/server.key",
        client_cert="path/to/client.crt",
        client_key="path/to/client.key",
        UNKNOWN_OPTION_FOR_KWARGS="some_value",
    )

    expected_calls = [
        call("PLUGIN_MAGIC_COOKIE_VALUE", "test-cookie"),
        call("PLUGIN_MAGIC_COOKIE", "test-cookie"),
        call("PLUGIN_PROTOCOL_VERSIONS", [5]),
        call("PLUGIN_SERVER_TRANSPORTS", ["unix", "tcp"]),
        call("PLUGIN_CLIENT_TRANSPORTS", ["unix", "tcp"]),
        call("PLUGIN_AUTO_MTLS", "true"),
        call("PLUGIN_HANDSHAKE_TIMEOUT", 20.0),
        call("PLUGIN_CONNECTION_TIMEOUT", 60.0),
        call("PLUGIN_SERVER_CERT", "path/to/server.crt"),
        call("PLUGIN_SERVER_KEY", "path/to/server.key"),
        call("PLUGIN_CLIENT_CERT", "path/to/client.crt"),
        call("PLUGIN_CLIENT_KEY", "path/to/client.key"),
        call("PLUGIN_UNKNOWN_OPTION_FOR_KWARGS", "some_value"),
    ]

    mock_rpc_set.assert_has_calls(expected_calls, any_order=True)
    assert mock_rpc_set.call_count == len(expected_calls)


@patch("pyvider.rpcplugin.config.rpcplugin_config.set")
def test_configure_minimal_options(mock_rpc_set):
    """Test configure function with only a few options."""
    configure(magic_cookie="minimal-cookie", auto_mtls=False)

    expected_calls = [
        call("PLUGIN_MAGIC_COOKIE_VALUE", "minimal-cookie"),
        call("PLUGIN_MAGIC_COOKIE", "minimal-cookie"),
        call("PLUGIN_AUTO_MTLS", "false"),
    ]
    mock_rpc_set.assert_has_calls(expected_calls, any_order=True)
    assert mock_rpc_set.call_count == len(expected_calls)


@patch("pyvider.rpcplugin.config.rpcplugin_config.set")
@patch("pyvider.rpcplugin.config.logger.warning")
def test_configure_unsupported_protocol_version(mock_log_warning, mock_rpc_set):
    """Test configure logs a warning for unsupported protocol_version."""
    unsupported_version = 99
    configure(protocol_version=unsupported_version)

    mock_log_warning.assert_called_once_with(
        f"⚙️⚠️ Unsupported protocol version: {unsupported_version}",
        extra={"supported": CONFIG_SCHEMA["SUPPORTED_PROTOCOL_VERSIONS"]["default"]},
    )
    mock_rpc_set.assert_any_call("PLUGIN_PROTOCOL_VERSIONS", [unsupported_version])


def test_configure_invalid_transport_type():
    """Test configure raises ValueError for invalid transport type."""
    with pytest.raises(
        ConfigError,
        match=r"Unknown transport type specified: 'bogus_transport'.*Valid transport types are:.*",
    ):
        configure(transports=["unix", "bogus_transport"])
