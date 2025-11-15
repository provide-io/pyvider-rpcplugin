# tests/core/test_defaults_validation.py
import pytest
import os
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    CONFIG_SCHEMA,
    validate_config_value,
    ConfigError,
)
from pyvider.telemetry import logger

ORIGINAL_ENV_BACKUP = {}


def backup_env_vars(keys_to_backup):
    for key in keys_to_backup:
        if key in os.environ:
            ORIGINAL_ENV_BACKUP[key] = os.environ[key]
        else:
            ORIGINAL_ENV_BACKUP[key] = None  # Mark as was not present


def restore_env_vars():
    for key, value in ORIGINAL_ENV_BACKUP.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:  # If it was None (not present) and now is, remove it
            del os.environ[key]
    ORIGINAL_ENV_BACKUP.clear()


def clear_plugin_env_vars_for_test():
    # Backup before clearing, only schema keys
    keys_in_schema = list(CONFIG_SCHEMA.keys())
    backup_env_vars(keys_in_schema)

    cleared_keys = []
    for key in keys_in_schema:
        if key in os.environ:
            del os.environ[key]
            cleared_keys.append(key)
    if cleared_keys:
        logger.debug(f"Fixture cleared PLUGIN_ env vars: {', '.join(cleared_keys)}")


def force_reinit_config_for_test():
    RPCPluginConfig._instance = None
    return RPCPluginConfig.instance()


@pytest.fixture(autouse=True)  # Autouse to apply to all tests in the module
def auto_clean_rpc_config_env():
    # Original env vars for schema keys are backed up by clear_plugin_env_vars_for_test
    clear_plugin_env_vars_for_test()
    # Force re-init after clearing env. This instance can be used by tests if needed,
    # but tests might also call force_reinit_config_for_test() themselves after further env changes.
    RPCPluginConfig._instance = None
    _ = RPCPluginConfig.instance()  # Initial instance creation with cleared env

    yield  # Test runs here

    restore_env_vars()  # Restore original env vars
    RPCPluginConfig._instance = None  # Final cleanup of singleton for other modules
    _ = (
        RPCPluginConfig.instance()
    )  # Re-init with restored env for subsequent modules/tests


def test_default_value_fallbacks():
    # Config instance is already re-initialized by auto_clean_rpc_config_env
    # Call force_reinit again to be absolutely sure it reflects the state after fixture setup
    config = force_reinit_config_for_test()

    logger.info("--- Testing Default Value Fallbacks ---")
    default_cookie = CONFIG_SCHEMA["PLUGIN_MAGIC_COOKIE_VALUE"]["default"]
    actual_cookie = config.magic_cookie_value()
    assert actual_cookie == default_cookie, (
        f"Default magic_cookie_value: expected '{default_cookie}', got '{actual_cookie}'"
    )
    logger.info(f"Default magic_cookie_value: OK ('{actual_cookie}')")

    default_auto_mtls_str = CONFIG_SCHEMA["PLUGIN_AUTO_MTLS"]["default"]
    default_auto_mtls_bool = default_auto_mtls_str.lower() in ("true", "yes", "1", "on")
    actual_auto_mtls = config.auto_mtls_enabled()
    assert actual_auto_mtls == default_auto_mtls_bool, (
        f"Default auto_mtls_enabled: expected {default_auto_mtls_bool}, got {actual_auto_mtls}"
    )
    logger.info(f"Default auto_mtls_enabled: OK ({actual_auto_mtls})")

    default_handshake_timeout = float(
        CONFIG_SCHEMA["PLUGIN_HANDSHAKE_TIMEOUT"]["default"]
    )
    actual_handshake_timeout = config.handshake_timeout()
    assert actual_handshake_timeout == default_handshake_timeout, (
        f"Default handshake_timeout: expected {default_handshake_timeout}, got {actual_handshake_timeout}"
    )
    logger.info(f"Default handshake_timeout: OK ({actual_handshake_timeout})")

    default_log_level = CONFIG_SCHEMA["PLUGIN_LOG_LEVEL"]["default"]
    actual_log_level = config.get("PLUGIN_LOG_LEVEL")
    assert actual_log_level == default_log_level, (
        f"Default PLUGIN_LOG_LEVEL: expected '{default_log_level}', got '{actual_log_level}'"
    )
    logger.info(f"Default PLUGIN_LOG_LEVEL: OK ('{actual_log_level}')")
    logger.info("--- Default Value Fallbacks Test: PASSED ---")


def test_invalid_handshake_timeout_type(monkeypatch):
    logger.info("Testing invalid type for PLUGIN_HANDSHAKE_TIMEOUT...")
    # Env is clean due to autouse fixture. Set specific var for this test.
    monkeypatch.setenv("PLUGIN_HANDSHAKE_TIMEOUT", "not-a-float")

    # Expect ConfigError (subclass of ValueError)
    with (
        pytest.raises(ConfigError) as excinfo
    ):  # Changed from ValueError to ConfigError for more specificity if desired
        force_reinit_config_for_test()  # This will trigger validation during RPCPluginConfig init

    assert (
        "Invalid value format for configuration key 'PLUGIN_HANDSHAKE_TIMEOUT'"
        in str(excinfo.value)
    )
    logger.info(
        f"Successfully caught ConfigError for invalid float type. Error: {str(excinfo.value)}"
    )


def test_invalid_log_level_enum(monkeypatch):
    logger.info("Testing invalid enum for PLUGIN_LOG_LEVEL...")
    monkeypatch.setenv("PLUGIN_LOG_LEVEL", "NOT_A_VALID_LOG_LEVEL")

    with pytest.raises(
        ConfigError
    ) as excinfo:  # Changed from ValueError to ConfigError
        force_reinit_config_for_test()

    assert (
        "Invalid value 'NOT_A_VALID_LOG_LEVEL' provided for configuration key 'PLUGIN_LOG_LEVEL'"
        in str(excinfo.value)
    )
    logger.info(
        f"Successfully caught ConfigError for invalid log level enum. Error: {str(excinfo.value)}"
    )


def test_missing_required_value_direct_call():
    key_to_test_required = "PLUGIN_MAGIC_COOKIE_VALUE"
    logger.info(
        f"Testing validate_config_value directly for missing required value: {key_to_test_required}"
    )

    # This test is specifically for the validate_config_value function's behavior
    # when a value is None for a required key.
    # Note: The exception raised by validate_config_value itself is ConfigError.
    with pytest.raises(
        ConfigError
    ) as excinfo:  # Changed from ValueError to ConfigError
        validate_config_value(
            key_to_test_required, None, CONFIG_SCHEMA[key_to_test_required]
        )

    assert f"Missing required configuration key: '{key_to_test_required}'" in str(
        excinfo.value
    )
    logger.info(
        f"Successfully caught ConfigError for missing required value via direct call. Error: {str(excinfo.value)}"
    )
