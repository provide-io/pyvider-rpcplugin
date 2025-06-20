import pytest
import json
import yaml
import os
from pathlib import Path

from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    rpcplugin_config,
    load_config_from_file,
    ConfigError
)

# Ensure a clean state for rpcplugin_config before each test
# by directly manipulating the singleton instance used by the module.
# This is more direct than relying on `configure()` which might have side effects
# or might not fully reset if the underlying os.environ was manipulated by a previous test.
@pytest.fixture(autouse=True)
def reset_config_singleton_and_env():
    # Backup and clear relevant env vars
    env_backup = {}
    # Consider all keys from CONFIG_SCHEMA if it's accessible here, or a common set.
    # For now, focusing on keys used in these tests.
    test_keys = ["PLUGIN_MAGIC_COOKIE_VALUE", "PLUGIN_AUTO_MTLS", "PLUGIN_HANDSHAKE_TIMEOUT", "PLUGIN_LOG_LEVEL", "PLUGIN_UNKNOWN_OPTION"]
    for key in test_keys:
        if key in os.environ:
            env_backup[key] = os.environ[key]
            del os.environ[key]
        else:
            env_backup[key] = None # Mark as was not present

    RPCPluginConfig._instance = None # Reset singleton before test
    yield
    RPCPluginConfig._instance = None # Reset singleton after test

    # Restore env vars
    for key, value in env_backup.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ: # If it was set during test but originally None (not in backup)
            del os.environ[key]


def test_load_from_json(tmp_path: Path):
    """Test loading configuration from a JSON file."""
    RPCPluginConfig._instance = None # Ensure fresh load
    json_data = {
        "PLUGIN_MAGIC_COOKIE_VALUE": "json_cookie",
        "PLUGIN_AUTO_MTLS": "false", # JSON booleans are true/false, not strings "true"/"false"
        "PLUGIN_HANDSHAKE_TIMEOUT": 22.2
    }
    json_file = tmp_path / "test_config.json"
    with open(json_file, "w") as f:
        json.dump(json_data, f)

    load_config_from_file(str(json_file))

    # Use the global rpcplugin_config instance for assertions
    assert rpcplugin_config.magic_cookie_value() == "json_cookie"
    assert rpcplugin_config.auto_mtls_enabled() is False
    assert rpcplugin_config.handshake_timeout() == 22.2

def test_load_from_yaml(tmp_path: Path):
    """Test loading configuration from a YAML file."""
    RPCPluginConfig._instance = None # Ensure fresh load
    yaml_data = {
        "PLUGIN_MAGIC_COOKIE_VALUE": "yaml_cookie",
        "PLUGIN_AUTO_MTLS": True, # YAML booleans can be True/False
        "PLUGIN_LOG_LEVEL": "DEBUG"
    }
    yaml_file = tmp_path / "test_config.yaml"
    with open(yaml_file, "w") as f:
        yaml.dump(yaml_data, f)

    load_config_from_file(str(yaml_file))

    assert rpcplugin_config.magic_cookie_value() == "yaml_cookie"
    assert rpcplugin_config.auto_mtls_enabled() is True
    assert rpcplugin_config.get("PLUGIN_LOG_LEVEL") == "DEBUG"

def test_load_from_dotenv(tmp_path: Path):
    """Test loading configuration from a .env file."""
    RPCPluginConfig._instance = None # Ensure fresh load
    env_content = "PLUGIN_MAGIC_COOKIE_VALUE=dotenv_cookie\nPLUGIN_AUTO_MTLS=false\nPLUGIN_UNKNOWN_OPTION=dotenv_unknown"
    env_file = tmp_path / "test_config.env"
    with open(env_file, "w") as f:
        f.write(env_content)

    load_config_from_file(str(env_file))

    assert rpcplugin_config.magic_cookie_value() == "dotenv_cookie"
    assert rpcplugin_config.auto_mtls_enabled() is False
    # Check if unknown options are loaded (current implementation of _load_dotenv_file does load them into os.environ)
    # The RPCPluginConfig.get method will only return schema-defined keys or PLUGIN_* prefixed keys
    # So, to check if it was loaded into environ, we check os.environ directly.
    # However, the test should ideally check behavior through the config object if possible.
    # If PLUGIN_UNKNOWN_OPTION is loaded by load_config_from_file into the config object (if it starts with PLUGIN_), test it.
    # Based on current RPCPluginConfig.set logic, it should be loaded if it starts with PLUGIN_
    assert rpcplugin_config.get("PLUGIN_UNKNOWN_OPTION") == "dotenv_unknown"
    # Clean up env var if it was set by load_dotenv_file to avoid interference
    if "PLUGIN_UNKNOWN_OPTION" in os.environ:
        del os.environ["PLUGIN_UNKNOWN_OPTION"]
