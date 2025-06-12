# tests/rpcplugin/test_config.py

import os
import re  # Added for re.escape
import pytest
from unittest.mock import patch, mock_open, call
from pathlib import Path

from pyvider.rpcplugin.config import (
    fetch_env_variable,
    validate_config_value,
    get_config,
    RPCPluginConfig,
    configure,
    load_config_from_file,
    CONFIG_SCHEMA,  # Import for direct use in tests
)

# Ensure logger is active for testing log captures if necessary
# logger.enable("pyvider.rpcplugin.config") # Removed due to AttributeError


# Tests for fetch_env_variable
def test_fetch_env_variable_from_os_environ():
    """Test fetching a string variable from os.environ."""
    key = "PLUGIN_MAGIC_COOKIE_VALUE"
    expected_value = "test-cookie-from-env"
    os.environ[key] = expected_value
    meta = CONFIG_SCHEMA[key]

    assert fetch_env_variable(key, meta) == expected_value


def test_fetch_env_variable_default_value():
    """Test fetching a variable using its default value."""
    key = "PLUGIN_LOG_LEVEL"  # This key has a default in CONFIG_SCHEMA
    # Ensure it's not in os.environ for this test
    if key in os.environ:
        del os.environ[key]

    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == meta["default"]


def test_fetch_env_variable_none_default():
    """Test fetching a variable that has a default of None."""
    key = "PLUGIN_SERVER_ENDPOINT"  # Default is None
    if key in os.environ:
        del os.environ[key]
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) is None


def test_fetch_env_variable_type_conversion_int():
    """Test type conversion to int."""
    key = "PLUGIN_CORE_VERSION"
    os.environ[key] = "123"
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == 123


def test_fetch_env_variable_type_conversion_bool_true():
    """Test type conversion to bool (True variants)."""
    key = "PLUGIN_AUTO_MTLS"
    meta = CONFIG_SCHEMA[key]
    for true_val in ["true", "YES", "1", "oN"]:
        os.environ[key] = true_val
        assert fetch_env_variable(key, meta) is True


def test_fetch_env_variable_type_conversion_bool_false():
    """Test type conversion to bool (False variants)."""
    key = "PLUGIN_AUTO_MTLS"
    meta = CONFIG_SCHEMA[key]
    for false_val in ["false", "NO", "0", "oFF", "anyotherstring"]:
        os.environ[key] = false_val
        assert fetch_env_variable(key, meta) is False

    # Test with actual boolean default if env var is missing
    if key in os.environ:
        del os.environ[key]
    # Temporarily modify meta for this specific default test case
    original_default = meta["default"]
    meta["default"] = False
    assert fetch_env_variable(key, meta) is False
    meta["default"] = True
    assert fetch_env_variable(key, meta) is True
    meta["default"] = original_default  # restore


def test_fetch_env_variable_type_conversion_list_str():
    """Test type conversion to list[str]."""
    key = "PLUGIN_SERVER_TRANSPORTS"
    os.environ[key] = "unix, tcp , http"  # Note spaces
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == ["unix", "tcp", "http"]


def test_fetch_env_variable_type_conversion_list_int():
    """Test type conversion to list[int]."""
    key = "PLUGIN_PROTOCOL_VERSIONS"
    os.environ[key] = "1, 2 , 5"  # Note spaces
    meta = CONFIG_SCHEMA[key]
    assert fetch_env_variable(key, meta) == [1, 2, 5]

    # Test with actual list default
    if key in os.environ:
        del os.environ[key]
    meta = CONFIG_SCHEMA[key]  # Use original meta with list default
    assert fetch_env_variable(key, meta) == meta["default"]


@patch("builtins.open", new_callable=mock_open, read_data="file-content")
def test_fetch_env_variable_file_based_value(mock_file_open):
    """Test fetching a variable from a file path (file://)."""
    key = "PLUGIN_SERVER_CERT"
    file_path_str = "/fake/cert.pem"
    os.environ[key] = f"file://{file_path_str}"
    meta = CONFIG_SCHEMA[key]  # type: str

    assert fetch_env_variable(key, meta) == "file-content"
    mock_file_open.assert_called_once_with(file_path_str, "r", encoding="utf-8")


@patch("builtins.open", side_effect=IOError("File not found"))
def test_fetch_env_variable_file_based_value_read_error(mock_file_open):
    """Test error handling when file reading fails for file:// path."""
    key = "PLUGIN_SERVER_KEY"
    file_path_str = "/fake/key.pem"
    os.environ[key] = f"file://{file_path_str}"
    meta = CONFIG_SCHEMA[key]

    with pytest.raises(
        ValueError, match=f"Failed to read file for {key}: {file_path_str}"
    ):
        fetch_env_variable(key, meta)
    mock_file_open.assert_called_once_with(file_path_str, "r", encoding="utf-8")


def test_fetch_env_variable_invalid_type_conversion():
    """Test error handling for invalid type conversion (e.g., int from non-int string)."""
    key = "PLUGIN_CORE_VERSION"  # Expects int
    os.environ[key] = "not-an-int"
    meta = CONFIG_SCHEMA[key]

    with pytest.raises(
        ValueError, match=f"Invalid format for {key}. Expected int, got: not-an-int"
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
    # meta["required"] is True
    with pytest.raises(ValueError, match=f"Missing required configuration: {key}"):
        validate_config_value(key, None, meta)


def test_validate_config_value_none_for_not_required():
    """Test validate_config_value passes for None if not required."""
    key = "PLUGIN_SERVER_ENDPOINT"  # Not required, default is None
    meta = CONFIG_SCHEMA[key]
    # meta["required"] is False
    assert validate_config_value(key, None, meta) is True


def test_validate_config_value_invalid_choice():
    """Test validate_config_value raises ValueError for value not in valid_values."""
    key = "PLUGIN_LOG_LEVEL"  # Has valid_values: ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    meta = CONFIG_SCHEMA[key]
    invalid_level = "TRACE"
    # Escape special characters in the expected message for regex matching
    expected_message = f"Invalid value for {key}: {invalid_level}. Valid values: {str(meta['valid_values']).replace('[', '\\[').replace(']', '\\]')}"
    with pytest.raises(ValueError, match=expected_message):
        validate_config_value(key, invalid_level, meta)


# Tests for get_config
@patch("pyvider.rpcplugin.config.validate_config_value")
@patch("pyvider.rpcplugin.config.fetch_env_variable")
def test_get_config_success(mock_fetch, mock_validate):
    """Test get_config successfully builds config dictionary."""
    # Make fetch_env_variable return a unique value for each key
    mock_fetch.side_effect = lambda key, meta: f"fetched_value_for_{key}"
    # Make validate_config_value always return True
    mock_validate.return_value = True

    config = get_config()

    assert len(config) == len(CONFIG_SCHEMA)
    for (
        key,
        meta_val,
    ) in CONFIG_SCHEMA.items():  # renamed meta to meta_val to avoid conflict
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

    with pytest.raises(ValueError, match="Fetch failed"):
        get_config()

    # Ensure validate is not called for the key that failed fetching
    for call_args in mock_validate.call_args_list:
        assert call_args[0][0] != error_key


@patch("pyvider.rpcplugin.config.validate_config_value")
@patch("pyvider.rpcplugin.config.fetch_env_variable")
def test_get_config_validate_raises_error(mock_fetch, mock_validate):
    """Test get_config when validate_config_value raises an error."""
    error_key = "PLUGIN_LOG_LEVEL"
    mock_fetch.return_value = "fetched_value"  # Generic fetched value
    mock_validate.side_effect = (
        lambda key, value, meta: (_ for _ in ()).throw(ValueError("Validate failed"))
        if key == error_key
        else True
    )

    with pytest.raises(ValueError, match="Validate failed"):
        get_config()

    # Ensure fetch was called for the error key, and validate was also called for it
    mock_fetch.assert_any_call(error_key, CONFIG_SCHEMA[error_key])
    mock_validate.assert_any_call(error_key, "fetched_value", CONFIG_SCHEMA[error_key])


# Tests for RPCPluginConfig
# from unittest.mock import call # Already imported if needed, or ensure it is
def test_rpcpluginconfig_singleton():
    """Test RPCPluginConfig is a singleton."""
    instance1 = RPCPluginConfig.instance()
    instance2 = RPCPluginConfig.instance()
    assert instance1 is instance2
    # Reset for other tests that might rely on a fresh instance via fixture
    RPCPluginConfig._instance = None
    instance3 = RPCPluginConfig.instance()
    # After reset, instance1 is the old singleton. instance3 is the new one.
    # The fixture should handle resetting _instance to None before each test,
    # so instance1 here would be the one created by the first call in *this* test.
    # If the fixture ran *before* this test, instance1 would be a new one.
    # The key is that consecutive calls to .instance() without _instance = None yield same obj.
    assert (
        instance1 is not instance3
    )  # This checks if the reset mechanism works as expected for testing
    assert instance3 is RPCPluginConfig.instance()  # New singleton established


@patch("pyvider.rpcplugin.config.get_config")
def test_rpcpluginconfig_initialization(mock_get_config):
    """Test RPCPluginConfig initialization loads config via get_config."""
    expected_config = {"TEST_KEY": "test_value"}
    mock_get_config.return_value = expected_config

    # Ensure singleton is reset for this test if not already by fixture
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
    RPCPluginConfig._instance = None  # Ensure fresh instance
    config_manager = RPCPluginConfig.instance()  # Will load default schema-based config
    # Use a key we know has a default in CONFIG_SCHEMA
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
    key = "PLUGIN_SERVER_TRANSPORTS"  # Default is ["unix", "tcp"]
    expected_list = CONFIG_SCHEMA[key]["default"]
    assert config_manager.get_list(key) == expected_list

    # Test with a non-list value, should be wrapped in a list
    config_manager.set(key, "single_value")
    assert config_manager.get_list(key) == ["single_value"]

    # Test with an empty list default if key doesn't exist
    assert config_manager.get_list("NON_EXISTENT_LIST_KEY") == []


def test_rpcpluginconfig_set_known_key():
    """Test set() method for a known key from CONFIG_SCHEMA."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "PLUGIN_LOG_LEVEL"
    new_value = "DEBUG"  # Must be a valid value if schema has valid_values
    # Temporarily remove valid_values to allow any string for this specific set test,
    # or ensure the new_value is in valid_values. Let's assume it's valid.
    config_manager.set(key, new_value)
    assert config_manager.get(key) == new_value


def test_rpcpluginconfig_set_unknown_key_plugin_prefix():
    """Test set() method for an unknown key that starts with PLUGIN_."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "PLUGIN_MY_CUSTOM_SETTING"
    value = "custom_value"
    # Should not raise KeyError
    config_manager.set(key, value)
    assert config_manager.get(key) == value


def test_rpcpluginconfig_set_unknown_key_no_prefix_raises_error():
    """Test set() method for an unknown key without PLUGIN_ prefix raises KeyError."""
    RPCPluginConfig._instance = None
    config_manager = RPCPluginConfig.instance()
    key = "MY_OTHER_CUSTOM_SETTING"
    value = "another_value"
    with pytest.raises(
        KeyError, match=f"Unknown configuration key: {key}"
    ):  # Removed suffix
        config_manager.set(key, value)


def test_rpcpluginconfig_helper_methods():
    """Test various helper methods of RPCPluginConfig."""
    RPCPluginConfig._instance = None
    # Instance is created here, loading from defaults or actual env vars if any (cleared by fixture)
    config_manager = RPCPluginConfig.instance()

    # Directly set values in the already loaded config for testing helper methods' logic
    # This avoids re-triggering the full load/validation which might fail if env vars are set to invalid values
    # according to the schema's `valid_values`.
    config_manager.config["PLUGIN_MAGIC_COOKIE_KEY"] = "TestCookieKey"
    config_manager.config["PLUGIN_MAGIC_COOKIE_VALUE"] = "TestCookieValue123"
    # For list types, ensure the helper correctly processes what .get() returns
    config_manager.config["PLUGIN_SERVER_TRANSPORTS"] = [
        "test_unix",
        "test_tcp",
    ]  # Already a list
    config_manager.config["PLUGIN_SERVER_ENDPOINT"] = "/tmp/test.sock"
    config_manager.config["PLUGIN_CLIENT_TRANSPORTS"] = ["test_tcp"]  # Already a list
    config_manager.config["PLUGIN_CLIENT_ENDPOINT"] = "localhost:1234"
    # For boolean helpers, .get() will return the already-converted boolean from fetch_env_variable
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

    # Test auto_mtls_enabled with boolean False
    config_manager.config["PLUGIN_AUTO_MTLS"] = False
    assert config_manager.auto_mtls_enabled() is False

    # Test a helper where the underlying value might be a string needing conversion by the helper itself (if any)
    # Example: If a helper was to parse a complex string from config, that would be tested here.
    # In this case, the helpers directly return values that should already be in correct type due to initial load.


# Tests for configure function
@patch("pyvider.rpcplugin.config.rpcplugin_config.set")
def test_configure_all_options(mock_rpc_set):
    """Test configure function with all its defined parameters."""
    configure(
        magic_cookie="test-cookie",
        protocol_version=5,  # A supported version
        transports=["unix", "tcp"],
        auto_mtls=True,
        handshake_timeout=20.0,
        connection_timeout=60.0,
        server_cert="path/to/server.crt",
        server_key="path/to/server.key",
        client_cert="path/to/client.crt",
        client_key="path/to/client.key",
        # Test **kwargs
        UNKNOWN_OPTION_FOR_KWARGS="some_value",
    )

    expected_calls = [
        # magic_cookie
        call("PLUGIN_MAGIC_COOKIE_VALUE", "test-cookie"),
        call("PLUGIN_MAGIC_COOKIE", "test-cookie"),
        # protocol_version
        call("PLUGIN_PROTOCOL_VERSIONS", [5]),
        # transports
        call("PLUGIN_SERVER_TRANSPORTS", ["unix", "tcp"]),
        call("PLUGIN_CLIENT_TRANSPORTS", ["unix", "tcp"]),
        # auto_mtls
        call("PLUGIN_AUTO_MTLS", "true"),  # Note: bool converted to string
        # timeouts
        call("PLUGIN_HANDSHAKE_TIMEOUT", 20.0),
        call("PLUGIN_CONNECTION_TIMEOUT", 60.0),
        # certs
        call("PLUGIN_SERVER_CERT", "path/to/server.crt"),
        call("PLUGIN_SERVER_KEY", "path/to/server.key"),
        call("PLUGIN_CLIENT_CERT", "path/to/client.crt"),
        call("PLUGIN_CLIENT_KEY", "path/to/client.key"),
        # **kwargs
        call("PLUGIN_UNKNOWN_OPTION_FOR_KWARGS", "some_value"),
    ]

    # Check if all expected calls were made, order might not be guaranteed by dict iteration in configure
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
        ValueError, match="Unknown transport type: bogus_transport. Valid types: .*"
    ):
        configure(transports=["unix", "bogus_transport"])


# Tests for load_config_from_file
try:
    import yaml  # For testing YAML loading

    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False


@patch("pyvider.rpcplugin.config.Path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_load_config_from_env_file(
    mock_file_open, mock_path_exists
):  # Renamed mock_file to mock_file_open for clarity
    """Test loading configuration from a .env file."""
    mock_path_exists.return_value = True

    env_content = "MY_VAR_1=env_value1_final_attempt\nPLUGIN_LOG_LEVEL=WARNING\n"
    mock_file_open.return_value.__enter__.return_value.read.return_value = env_content

    key_to_test = "MY_VAR_1"
    original_value = os.environ.get(key_to_test)
    if key_to_test in os.environ:
        del os.environ[key_to_test]

    try:
        load_config_from_file(Path("test.env"))

        mock_path_exists.assert_called_once()
        mock_file_open.assert_called_once_with(Path("test.env"), "r", encoding="utf-8")

        assert os.environ.get(key_to_test) == "env_value1_final_attempt"
        assert RPCPluginConfig.instance().get("PLUGIN_LOG_LEVEL") == "WARNING"

    finally:
        if original_value is not None:
            os.environ[key_to_test] = original_value
        elif key_to_test in os.environ:
            del os.environ[key_to_test]
        # Schema keys are reset by the fixture


@patch("pyvider.rpcplugin.config.Path.exists")
@patch("builtins.open", new_callable=mock_open)
@patch("json.load")
def test_load_config_from_json_file(mock_json_load, mock_file, mock_path_exists):
    """Test loading configuration from a .json file."""
    mock_path_exists.return_value = True
    # Use PLUGIN_CORE_VERSION as it's an int type in CONFIG_SCHEMA
    json_data = {
        "MY_JSON_VAR": "json_value",
        "PLUGIN_CORE_VERSION": 123,
        "PLUGIN_LIST_VAR": [1, "a"],
        "PLUGIN_DICT_VAR": {"k": "v"},
    }
    mock_json_load.return_value = json_data

    # Fixture handles schema keys in os.environ and RPCPluginConfig instance.
    # Manage non-schema keys locally if needed.
    original_non_schema_env = {
        "MY_JSON_VAR": os.environ.get("MY_JSON_VAR"),
        "PLUGIN_LIST_VAR": os.environ.get(
            "PLUGIN_LIST_VAR"
        ),  # Assuming these are not in schema
        "PLUGIN_DICT_VAR": os.environ.get(
            "PLUGIN_DICT_VAR"
        ),  # Assuming these are not in schema
    }
    keys_to_clear_locally = ["MY_JSON_VAR", "PLUGIN_LIST_VAR", "PLUGIN_DICT_VAR"]
    for k_to_clear in keys_to_clear_locally:
        if k_to_clear in os.environ:
            del os.environ[k_to_clear]

    try:
        load_config_from_file(Path("test.json"))

        mock_path_exists.assert_called_once()
        mock_file.assert_called_once_with(Path("test.json"), "r", encoding="utf-8")
        mock_json_load.assert_called_once_with(
            mock_file.return_value.__enter__.return_value
        )

        # Assertions for os.environ (raw stringified values)
        assert os.environ["MY_JSON_VAR"] == "json_value"
        assert (
            os.environ["PLUGIN_CORE_VERSION"] == "123"
        )  # JSON numbers are stringified for env
        assert os.environ["PLUGIN_LIST_VAR"] == '[1, "a"]'  # JSON lists are stringified
        assert (
            os.environ["PLUGIN_DICT_VAR"] == '{"k": "v"}'
        )  # JSON dicts are stringified

        # Assertions for RPCPluginConfig.instance().get() (schema-processed values)
        assert (
            RPCPluginConfig.instance().get("PLUGIN_CORE_VERSION") == 123
        )  # Check type conversion
        # For MY_JSON_VAR, if not in schema, this would be None or a default.
        # Let's assume MY_JSON_VAR is not a schema key and is tested via os.environ only,
        # or add it to schema if it needs to be retrieved via .get().
        # For now, the main fix is using a valid schema key for the typed assertion.
        # For example, if PLUGIN_LIST_VAR was list_str in schema:
        # assert RPCPluginConfig.instance().get("PLUGIN_LIST_VAR") == ["1", "a"]

    finally:
        # Restore non-schema environment variables
        for key, value in original_non_schema_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]
        # Schema keys are reset by the fixture


@patch("pyvider.rpcplugin.config.Path.exists")
@patch("builtins.open", new_callable=mock_open)
# Removed broad @patch('yaml.safe_load')
def test_load_config_from_yaml_file(
    mock_file, mock_path_exists
):  # Removed mock_yaml_load from params
    """Test loading configuration from a .yaml file."""
    if not YAML_AVAILABLE:
        pytest.skip("PyYAML not installed")

    mock_path_exists.return_value = True

    nested_dict_val = {"sub_key": "sub_val_yaml_v2"}
    yaml_data_source = {  # This is what the mocked safe_load (for config loading) will return
        "PLUGIN_AUTO_MTLS": False,
        "PLUGIN_NESTED_TEST_KEY": nested_dict_val,
    }

    key_to_test = "PLUGIN_NESTED_TEST_KEY"
    original_plugin_nested_test_key_val = os.environ.get(key_to_test)
    if key_to_test in os.environ:  # Explicitly delete for clean state
        del os.environ[key_to_test]

    try:
        # Patch yaml.safe_load only for the duration of load_config_from_file call
        with patch(
            "yaml.safe_load", return_value=yaml_data_source
        ) as mock_yaml_load_for_function:
            load_config_from_file(Path("test.yaml"))
            mock_yaml_load_for_function.assert_called_once_with(
                mock_file.return_value.__enter__.return_value
            )

        mock_path_exists.assert_called_once()
        mock_file.assert_called_once_with(Path("test.yaml"), "r", encoding="utf-8")

        # Check os.environ directly after load_config_from_file
        assert os.environ.get("PLUGIN_AUTO_MTLS") == "False"

        # This is what should be in the environment variable: the dict dumped to a YAML string
        expected_env_var_content = yaml.dump(nested_dict_val).strip()
        assert os.environ.get(key_to_test) == expected_env_var_content

        # Now, test that parsing this env var string yields the original dict
        # This uses the *real* yaml.safe_load, not the mocked one
        env_var_value = os.environ.get(key_to_test)
        assert env_var_value is not None, (
            f"{key_to_test} was not set in os.environ as expected"
        )

        loaded_nested_val_from_env = yaml.safe_load(env_var_value)
        assert loaded_nested_val_from_env == nested_dict_val

        # Check RPCPluginConfig for the schema key
        assert RPCPluginConfig.instance().get("PLUGIN_AUTO_MTLS") is False
        # PLUGIN_NESTED_TEST_KEY is not a schema key

    finally:
        # Restore PLUGIN_NESTED_TEST_KEY specifically
        if original_plugin_nested_test_key_val is not None:
            os.environ[key_to_test] = original_plugin_nested_test_key_val
        elif key_to_test in os.environ:  # If set by test but not originally present
            del os.environ[key_to_test]
        # Schema keys are reset by the fixture


def test_load_config_file_not_found():
    """Test load_config_from_file raises error if file not found."""
    with patch("pyvider.rpcplugin.config.Path.exists", return_value=False):
        with pytest.raises(
            ValueError, match="Configuration file not found: non_existent.cfg"
        ):
            load_config_from_file(Path("non_existent.cfg"))


def test_load_config_unsupported_format():
    """Test load_config_from_file raises error for unsupported file format."""
    with patch("pyvider.rpcplugin.config.Path.exists", return_value=True):
        with pytest.raises(
            ValueError,
            match="Unsupported file format: .txt. Supported formats: .env, .json, .yaml, .yml",
        ):
            load_config_from_file(Path("test.txt"))


@patch("pyvider.rpcplugin.config.Path.exists", return_value=True)
@patch("builtins.open", side_effect=IOError("Read error!"))
def test_load_config_file_read_error(mock_open_call, mock_exists_call):
    """Test error handling when reading a config file fails (e.g. .env)."""
    file_path = Path("test_error.env")
    # The error message from _load_dotenv_file is "Error loading .env file: {path}. Original error: {original_error_str}"
    # The error message from load_config_from_file is "Error loading configuration from {path}: {inner_exception_message}"
    # So the final message contains both, with the IOError being the cause of the innermost ValueError.
    # The direct message of the innermost ValueError is "Error loading .env file: {path}. Original error: Read error!"
    # The direct message of the outermost ValueError is "Error loading configuration from {path}: {message_of_innermost_ValueError}"
    # where message_of_innermost_ValueError is "Error loading .env file: {path}. Original error: Read error!"
    # The prompt asks to correct `expected_msg` to not include "Original error: Read error!"
    # This implies we should match the message of the ValueError raised from _load_dotenv_file directly,
    # or that the outer wrapper's message does not include the "Original error:..." part of its cause.
    # Let's re-check load_config_from_file: `raise ValueError(f"Error loading configuration from {path}: {e}") from e`
    # Here `e` is the exception from `_load_dotenv_file`. The message of `e` is `f"Error loading {path.suffix} file: {path}. Original error: {original_io_error}"`
    # So, the full message of the *outer* exception is indeed:
    # "Error loading configuration from {path}: Error loading .env file: {path}. Original error: Read error!"
    #
    # If the subtask wants to match *only* "Error loading configuration from {path}: Error loading .env file: {path}",
    # this means the "Original error: Read error!" part is not included in the str(e) for the outer exception,
    # or we should match a substring.
    # Given: `raise ValueError(f"Error loading configuration from {path}: {e}") from e`
    # `str(ValueError(f"message: {e}"))` will include `str(e)`.
    # `str(ValueError(f"Error loading .env file: {path}. Original error: {IOError('Read error!')}"))`
    # becomes "Error loading .env file: test_error.env. Original error: Read error!"
    # So the full outer message is "Error loading configuration from test_error.env: Error loading .env file: test_error.env. Original error: Read error!"
    #
    # The message of e_dotenv: "Error loading .env file: {path}. Original error: Read error!" (No, this was wrong)
    # The message of e_dotenv (from _load_dotenv_file) is "Error loading .env file: {path}"
    # The message of e_outer (from load_config_from_file) is "Error loading configuration from {path}: {message_of_e_dotenv}"
    # So the final message string for the outermost exception is:
    # "Error loading configuration from {file_path}: Error loading .env file: {file_path}"
    # The "Original error: Read error!" is the message of e_io, which is the __cause__ of e_dotenv.

    expected_msg = f"Error loading configuration from {str(file_path)}: Error loading .env file: {str(file_path)}"
    with pytest.raises(ValueError, match=re.escape(expected_msg)):
        load_config_from_file(file_path)
    mock_open_call.assert_called_once_with(file_path, "r", encoding="utf-8")


# 🐍🧪⚙️
