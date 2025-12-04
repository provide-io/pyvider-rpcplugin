# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import pytest
import os
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    ConfigError,
    rpcplugin_config,
)
from tests.conftest import get_all_env_vars
from provide.foundation import logger

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
    # Backup before clearing, using metadata-driven discovery
    env_keys = get_all_env_vars()
    keys_to_clear = [key for key in env_keys if key]  # Filter out None values
    backup_env_vars(keys_to_clear)

    cleared_keys = []
    for key in keys_to_clear:
        if key in os.environ:
            del os.environ[key]
            cleared_keys.append(key)
    if cleared_keys:
        logger.debug(f"Fixture cleared PLUGIN_ env vars: {', '.join(cleared_keys)}")


def force_reinit_config_for_test():
    # Foundation config doesn't use singleton pattern
    # Just return a fresh config instance from environment
    return RPCPluginConfig.from_env()


@pytest.fixture(autouse=True)  # Autouse to apply to all tests in the module
def auto_clean_rpc_config_env():
    # Clean environment before test
    clear_plugin_env_vars_for_test()
    # Foundation config doesn't need singleton management
    
    yield  # Test runs here

    # Restore environment after test
    restore_env_vars()


def test_default_value_fallbacks():
    # Config instance is already re-initialized by auto_clean_rpc_config_env
    # Call force_reinit again to be absolutely sure it reflects the state after fixture setup
    config = force_reinit_config_for_test()

    logger.info("--- Testing Default Value Fallbacks ---")
    
    # Test magic cookie value default (from field default)
    expected_cookie = "test_cookie_value"  # From field definition
    actual_cookie = config.plugin_magic_cookie_value
    assert actual_cookie == expected_cookie, (
        f"Default magic_cookie_value: expected '{expected_cookie}', got '{actual_cookie}'"
    )
    logger.info(f"Default magic_cookie_value: OK ('{actual_cookie}')")

    # Test auto_mtls default (from field default)
    expected_auto_mtls = True  # From field definition
    actual_auto_mtls = config.plugin_auto_mtls
    assert actual_auto_mtls == expected_auto_mtls, (
        f"Default plugin_auto_mtls: expected {expected_auto_mtls}, got {actual_auto_mtls}"
    )
    logger.info(f"Default plugin_auto_mtls: OK ({actual_auto_mtls})")

    # Test handshake timeout default (from field definition)
    expected_handshake_timeout = 10.0  # From field definition
    actual_handshake_timeout = config.plugin_handshake_timeout
    assert actual_handshake_timeout == expected_handshake_timeout, (
        f"Default handshake_timeout: expected {expected_handshake_timeout}, got {actual_handshake_timeout}"
    )
    logger.info(f"Default handshake_timeout: OK ({actual_handshake_timeout})")

    # Test log level default (from field definition)
    expected_log_level = "INFO"  # From field definition
    actual_log_level = config.plugin_log_level
    assert actual_log_level == expected_log_level, (
        f"Default plugin_log_level: expected '{expected_log_level}', got '{actual_log_level}'"
    )
    logger.info(f"Default plugin_log_level: OK ('{actual_log_level}')")
    logger.info("--- Default Value Fallbacks Test: PASSED ---")


def test_invalid_handshake_timeout_type(monkeypatch):
    logger.info("Testing invalid type for PLUGIN_HANDSHAKE_TIMEOUT...")
    # Env is clean due to autouse fixture. Set specific var for this test.
    monkeypatch.setenv("PLUGIN_HANDSHAKE_TIMEOUT", "not-a-float")

    # Expect Foundation ValidationError when config loads invalid value
    with pytest.raises(Exception) as excinfo:  # Foundation's config loading should fail
        force_reinit_config_for_test()  # This will trigger validation during RPCPluginConfig init

    # The error should indicate invalid float conversion
    error_str = str(excinfo.value)
    assert "PLUGIN_HANDSHAKE_TIMEOUT" in error_str or "float" in error_str.lower(), (
        f"Expected timeout validation error, got: {error_str}"
    )
    logger.info(
        f"Successfully caught validation error for invalid float type. Error: {error_str}"
    )


def test_invalid_log_level_enum(monkeypatch):
    logger.info("Testing invalid enum for PLUGIN_LOG_LEVEL...")
    monkeypatch.setenv("PLUGIN_LOG_LEVEL", "NOT_A_VALID_LOG_LEVEL")

    # Foundation's validate_choice should reject invalid log levels
    with pytest.raises(Exception) as excinfo:  # Foundation ValidationError expected
        force_reinit_config_for_test()

    error_str = str(excinfo.value)
    assert "NOT_A_VALID_LOG_LEVEL" in error_str or "log" in error_str.lower(), (
        f"Expected log level validation error, got: {error_str}"
    )
    logger.info(
        f"Successfully caught validation error for invalid log level enum. Error: {error_str}"
    )


def test_foundation_field_validation_integration():
    """Test that Foundation's field validation is working properly."""
    logger.info("Testing Foundation field validation integration...")
    
    # Test that creating a config instance with no env vars uses defaults
    config = force_reinit_config_for_test()
    
    # Verify required fields have their defaults
    assert config.plugin_magic_cookie_value == "test_cookie_value"
    assert config.plugin_handshake_timeout == 10.0
    assert config.plugin_auto_mtls == True
    assert config.plugin_log_level == "INFO"
    
    logger.info("Foundation field validation integration: OK")

# 🐍🔌📞🔚
