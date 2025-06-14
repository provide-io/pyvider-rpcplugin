from pyvider.rpcplugin.config import RPCPluginConfig, get_config, CONFIG_SCHEMA
from pyvider.telemetry import logger
import os

# Store original environment state for a subset of keys we might modify
# to ensure other tests or parts of the system aren't affected long-term.
# For this test, we mostly care about clearing and setting specific PLUGIN_ vars.
ORIGINAL_ENV_BACKUP = {}

def backup_env_vars(keys):
    for key in keys:
        if key in os.environ:
            ORIGINAL_ENV_BACKUP[key] = os.environ[key]

def restore_env_vars():
    for key, value in ORIGINAL_ENV_BACKUP.items():
        os.environ[key] = value
    # Clear any keys set during tests that weren't originally present
    # This is tricky if we don't know all keys that might be set.
    # For now, explicit del in tests is better.

def clear_plugin_env_vars():
    """Clears environment variables that correspond to CONFIG_SCHEMA keys."""
    cleared_keys = []
    for key in CONFIG_SCHEMA.keys():
        if key in os.environ:
            if key not in ORIGINAL_ENV_BACKUP: # Back up if not already
                ORIGINAL_ENV_BACKUP[key] = os.environ[key]
            del os.environ[key]
            cleared_keys.append(key)
    if cleared_keys:
        logger.debug(f"Cleared environment variables for test: {', '.join(cleared_keys)}")

def force_reinit_config() -> RPCPluginConfig:
    """Forces re-initialization of the RPCPluginConfig singleton."""
    RPCPluginConfig._instance = None
    return RPCPluginConfig.instance()

# Backup any relevant vars at the start if they exist from parent environment
# For this test, we are mostly concerned with ensuring schema defaults are applied,
# so clearing is more important than backup/restore for *testing defaults*.
# However, for validation tests where we set env vars, cleanup is good.

logger.info("--- Testing Default Value Fallbacks ---")
clear_plugin_env_vars() # Clear all known PLUGIN_ env vars
config = force_reinit_config() # Re-init with a clean slate (should use schema defaults)

# Test specific defaults
default_cookie = CONFIG_SCHEMA["PLUGIN_MAGIC_COOKIE_VALUE"]["default"]
actual_cookie = config.magic_cookie_value()
assert actual_cookie == default_cookie, f"Default magic_cookie_value mismatch: expected '{default_cookie}', got '{actual_cookie}'"
logger.info(f"Default magic_cookie_value: OK ('{actual_cookie}')")

default_auto_mtls_str = CONFIG_SCHEMA["PLUGIN_AUTO_MTLS"]["default"]
default_auto_mtls_bool = default_auto_mtls_str.lower() in ("true", "yes", "1", "on")
actual_auto_mtls = config.auto_mtls_enabled()
assert actual_auto_mtls == default_auto_mtls_bool, f"Default auto_mtls_enabled mismatch: expected {default_auto_mtls_bool}, got {actual_auto_mtls}"
logger.info(f"Default auto_mtls_enabled: OK ({actual_auto_mtls})")

default_handshake_timeout = float(CONFIG_SCHEMA["PLUGIN_HANDSHAKE_TIMEOUT"]["default"])
actual_handshake_timeout = config.handshake_timeout()
assert actual_handshake_timeout == default_handshake_timeout, f"Default handshake_timeout mismatch: expected {default_handshake_timeout}, got {actual_handshake_timeout}"
logger.info(f"Default handshake_timeout: OK ({actual_handshake_timeout})")

default_log_level = CONFIG_SCHEMA["PLUGIN_LOG_LEVEL"]["default"]
actual_log_level = config.get("PLUGIN_LOG_LEVEL")
assert actual_log_level == default_log_level, f"Default PLUGIN_LOG_LEVEL mismatch: expected '{default_log_level}', got '{actual_log_level}'"
logger.info(f"Default PLUGIN_LOG_LEVEL: OK ('{actual_log_level}')")

logger.info("--- Default Value Fallbacks Test: PASSED ---")


logger.info("--- Testing Configuration Validation ---")

# Test Invalid Value Type for PLUGIN_HANDSHAKE_TIMEOUT (expects float)
logger.info("Testing invalid type for PLUGIN_HANDSHAKE_TIMEOUT...")
# Ensure a clean slate for this specific variable, then set the bad one
clear_plugin_env_vars() # Clears all, so subsequent get_config() would use defaults
os.environ["PLUGIN_HANDSHAKE_TIMEOUT"] = "not-a-float"
expected_error_raised = False
try:
    force_reinit_config() # This will call get_config() which calls fetch_env_variable
    logger.error("Validation error NOT caught for invalid float type (PLUGIN_HANDSHAKE_TIMEOUT)!", extra={"test_status": "failed"})
except ValueError as e:
    logger.info(f"Successfully caught ValueError for invalid float type (PLUGIN_HANDSHAKE_TIMEOUT).", extra={"error_message": str(e), "test_status": "passed"})
    assert "Invalid format for PLUGIN_HANDSHAKE_TIMEOUT" in str(e), f"Error message mismatch: {str(e)}"
    expected_error_raised = True
except Exception as e:
    logger.error(f"Caught UNEXPECTED exception for invalid float type: {type(e).__name__}", extra={"error_message": str(e), "test_status": "failed"})
assert expected_error_raised, "ValueError was not raised for invalid float type as expected."
if "PLUGIN_HANDSHAKE_TIMEOUT" in os.environ: # Clean up
    del os.environ["PLUGIN_HANDSHAKE_TIMEOUT"]


# Test Invalid Enum Value for PLUGIN_LOG_LEVEL (str with valid_values)
logger.info("Testing invalid enum for PLUGIN_LOG_LEVEL...")
clear_plugin_env_vars() # Clear env again
os.environ["PLUGIN_LOG_LEVEL"] = "NOT_A_VALID_LOG_LEVEL"
expected_error_raised = False
try:
    force_reinit_config()
    logger.error("Validation error NOT caught for invalid log level enum (PLUGIN_LOG_LEVEL)!", extra={"test_status": "failed"})
except ValueError as e:
    logger.info(f"Successfully caught ValueError for invalid log level enum (PLUGIN_LOG_LEVEL).", extra={"error_message": str(e), "test_status": "passed"})
    assert "Invalid value for PLUGIN_LOG_LEVEL" in str(e), f"Error message mismatch: {str(e)}"
    expected_error_raised = True
except Exception as e:
    logger.error(f"Caught UNEXPECTED exception for invalid enum: {type(e).__name__}", extra={"error_message": str(e), "test_status": "failed"})
assert expected_error_raised, "ValueError was not raised for invalid enum value as expected."
if "PLUGIN_LOG_LEVEL" in os.environ: # Clean up
    del os.environ["PLUGIN_LOG_LEVEL"]


# Test Required Value (PLUGIN_MAGIC_COOKIE_VALUE) missing (by trying to set it to None via env - though fetch_env_variable has a default)
# A better test for required is if a default was None and env var was also not set.
# Most "required" fields in CONFIG_SCHEMA have defaults.
# Let's test PLUGIN_MAGIC_COOKIE_KEY as it's required and its default is "PLUGIN_MAGIC_COOKIE"
logger.info("Testing missing required value for PLUGIN_MAGIC_COOKIE_KEY (by setting empty string)...")
clear_plugin_env_vars()
# Setting to empty string, which might not be valid if schema implies non-empty
# fetch_env_variable uses the default if os.getenv returns None.
# To truly test missing, we'd need to modify schema or ensure default is None.
# For now, let's test setting it to an empty string, which should be caught by some validation if applicable,
# or it will just use the default if empty string is not explicitly handled before default application.
# The "required" check in validate_config_value is for value being None.
# If we set os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "", fetch_env_variable will return "".
# validate_config_value will see value="" (not None), so it passes the "required" check.
# This part of the test might not be effective for "missing" unless the default is None.
# The schema for PLUGIN_MAGIC_COOKIE_KEY has a default, so it will never be None from env var unset.
# Instead, let's focus on type/enum for now as "missing required" is harder to simulate here without schema change.
# Forcing a None value directly to test validate_config_value's required check:
config_instance_for_direct_validation = force_reinit_config() # Get a fresh config
key_to_test_required = "PLUGIN_MAGIC_COOKIE_VALUE" # This is required and has a default
original_value_for_key = config_instance_for_direct_validation.get(key_to_test_required)

logger.info(f"Temporarily setting {key_to_test_required} to None directly in internal config dict for validation test.")
config_instance_for_direct_validation.config[key_to_test_required] = None
expected_error_raised = False
try:
    # Now, if get_config() were called again, or if we manually validate this.
    # Let's manually call validate_config_value on this modified config state.
    # This is a bit artificial as get_config() normally populates this.
    from pyvider.rpcplugin.config import validate_config_value
    validate_config_value(key_to_test_required, None, CONFIG_SCHEMA[key_to_test_required])
    logger.error(f"Validation error NOT caught for missing required value ({key_to_test_required})!", extra={"test_status": "failed"})
except ValueError as e:
    logger.info(f"Successfully caught ValueError for missing required value ({key_to_test_required}).", extra={"error_message": str(e), "test_status": "passed"})
    assert f"Missing required configuration: {key_to_test_required}" in str(e), f"Error message mismatch: {str(e)}"
    expected_error_raised = True
except Exception as e:
    logger.error(f"Caught UNEXPECTED exception for missing required: {type(e).__name__}", extra={"error_message": str(e), "test_status": "failed"})
assert expected_error_raised, "ValueError was not raised for missing required value as expected."
# Restore the original value or re-init
config_instance_for_direct_validation.config[key_to_test_required] = original_value_for_key


logger.info("--- Configuration Validation Test: PASSED (for tested scenarios) ---")

# Restore original environment variables that might have been backed up
restore_env_vars()
# Final re-init to clear any test-specific settings from the global singleton
force_reinit_config()

logger.info("Finished defaults and validation tests.")
