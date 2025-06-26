import os
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    rpcplugin_config,
    configure,
    CONFIG_SCHEMA,
)
from pyvider.telemetry import logger

# Backup original environment variables that might be modified by tests
ORIGINAL_ENV_BACKUP = {}


def backup_env_vars(keys_to_backup):
    for key in keys_to_backup:
        if key in os.environ:
            ORIGINAL_ENV_BACKUP[key] = os.environ[key]
        elif key in ORIGINAL_ENV_BACKUP:
            # If key was already backed up and then deleted from os.environ by a test,
            # ensure its backed-up state reflects it's "not set" for subsequent restores.
            # This might be overly cautious depending on test structure.
            del ORIGINAL_ENV_BACKUP[key]


def restore_env_vars(keys_to_restore):
    for key in keys_to_restore:
        if key in ORIGINAL_ENV_BACKUP:
            os.environ[key] = ORIGINAL_ENV_BACKUP[key]
        elif key in os.environ:  # If it was set during test but not originally present
            del os.environ[key]


def reinit_config():
    """Just re-initializes RPCPluginConfig, assuming os.environ is already set as desired."""
    RPCPluginConfig._instance = None
    return RPCPluginConfig.instance()


def clear_all_known_plugin_env_vars():
    """Clears all environment variables that correspond to CONFIG_SCHEMA keys."""
    cleared_keys = []
    # Make sure CONFIG_SCHEMA is available (it's imported)
    for key in CONFIG_SCHEMA.keys():
        if key in os.environ:
            # Backup before deleting if not already backed up for this session
            if key not in ORIGINAL_ENV_BACKUP:
                ORIGINAL_ENV_BACKUP[key] = os.environ[key]
            del os.environ[key]
            cleared_keys.append(key)
    if cleared_keys:
        logger.debug(
            f"Cleared known PLUGIN_ environment variables: {', '.join(cleared_keys)}"
        )


# --- Test Part 1: configure() precedence over environment variables ---
logger.info("--- Testing configure() precedence over environment variables ---")
env_var_key = "PLUGIN_HANDSHAKE_TIMEOUT"
env_var_val_str = "25.5"
configure_val = 15.0
schema_default_val = float(CONFIG_SCHEMA[env_var_key]["default"])

# Backup the state of env_var_key if it exists from a parent environment
backup_env_vars([env_var_key])
# Clear all plugin vars to ensure a very clean slate before setting our test var
clear_all_known_plugin_env_vars()

# 1. Set specific environment variable for this test
os.environ[env_var_key] = env_var_val_str
logger.debug(f"Set {env_var_key}={os.environ[env_var_key]} in environment for test.")

# 2. Initialize config and verify it reflects the environment variable
config = reinit_config()
loaded_env_val = config.handshake_timeout()
assert loaded_env_val == float(env_var_val_str), (
    f"Config should reflect env var. Expected {float(env_var_val_str)}, got {loaded_env_val}"
)
logger.info(f"Config correctly loaded from env: {env_var_key}={loaded_env_val}")

# 3. Call configure() to override the value
# configure() uses short names for its direct args
short_name_for_configure = "handshake_timeout"
logger.debug(f"Calling configure({short_name_for_configure}={configure_val})")
configure(handshake_timeout=configure_val)

# rpcplugin_config is the global singleton instance, which configure() updates
updated_config_val = rpcplugin_config.handshake_timeout()
assert updated_config_val == configure_val, (
    f"configure() should override env var. Expected {configure_val}, got {updated_config_val}"
)
logger.info(
    f"configure() correctly overrode env var: {env_var_key}={updated_config_val}"
)

# 4. Verify environment variable itself is unchanged by configure()
assert os.environ[env_var_key] == env_var_val_str, (
    f"Environment variable should remain unchanged. Expected {env_var_val_str}, got {os.environ[env_var_key]}"
)
logger.info(
    f"Environment variable correctly unchanged: {env_var_key}={os.environ[env_var_key]}"
)

# 5. Cleanup for this part
del os.environ[env_var_key]  # Remove the one we set for the test

# Restore original environment variables that were present before this script ran
# And ensure config is reset based on that restored (or cleared) environment
restore_env_vars(list(ORIGINAL_ENV_BACKUP.keys()))  # Restore all backed up
clear_all_known_plugin_env_vars()  # Clear again to ensure clean state for next test section
reinit_config()
logger.info("--- Test `configure()` precedence: PASSED ---")


# --- Test Part 2: Re-verify Type Conversion for Environment Variables ---
logger.info("--- Re-verifying Type Conversion for Environment Variables ---")

# Boolean conversion for PLUGIN_AUTO_MTLS
key_auto_mtls = "PLUGIN_AUTO_MTLS"
backup_env_vars([key_auto_mtls])  # Backup current state if any
clear_all_known_plugin_env_vars()  # Ensure no other vars interfere

os.environ[key_auto_mtls] = "false"
logger.debug(f"Set {key_auto_mtls}={os.environ[key_auto_mtls]} in environment.")
config = reinit_config()
actual_auto_mtls = config.auto_mtls_enabled()
assert actual_auto_mtls is False, (
    f"{key_auto_mtls} type conversion failed. Expected False, got {actual_auto_mtls}"
)
logger.info(f"{key_auto_mtls} type conversion to boolean: OK (False)")
del os.environ[key_auto_mtls]
restore_env_vars([key_auto_mtls])
clear_all_known_plugin_env_vars()
reinit_config()


# list_int conversion for PLUGIN_PROTOCOL_VERSIONS
key_protocol_versions = "PLUGIN_PROTOCOL_VERSIONS"
backup_env_vars([key_protocol_versions])
clear_all_known_plugin_env_vars()

os.environ[key_protocol_versions] = "2,3,4"
logger.debug(
    f"Set {key_protocol_versions}={os.environ[key_protocol_versions]} in environment."
)
config = reinit_config()
expected_list_int = [2, 3, 4]
actual_list_int = config.get(key_protocol_versions)
assert actual_list_int == expected_list_int, (
    f"{key_protocol_versions} type conversion failed. Expected {expected_list_int}, got {actual_list_int}"
)
logger.info(
    f"{key_protocol_versions} type conversion to list_int: OK ({actual_list_int})"
)
del os.environ[key_protocol_versions]
restore_env_vars([key_protocol_versions])
clear_all_known_plugin_env_vars()  # Final clear for a clean end state
reinit_config()


logger.info("--- Type Conversion Test: PASSED ---")
logger.info("Finished environment variable precedence and type conversion tests.")
