import pytest
import os
from pathlib import Path
from pyvider.rpcplugin.config import load_config_from_file, ConfigError, RPCPluginConfig

@pytest.fixture(autouse=True)
def reset_config_singleton_and_env_malformed():
    # Backup and clear relevant env vars
    env_backup = {}
    test_keys = ["PLUGIN_MAGIC_COOKIE_VALUE", "PLUGIN_AUTO_MTLS", "PLUGIN_HANDSHAKE_TIMEOUT", "PLUGIN_LOG_LEVEL"]
    for key in test_keys:
        if key in os.environ:
            env_backup[key] = os.environ[key]
            del os.environ[key]
        else:
            env_backup[key] = None

    RPCPluginConfig._instance = None
    yield
    RPCPluginConfig._instance = None

    for key, value in env_backup.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:
            del os.environ[key]

def test_load_malformed_json(tmp_path: Path):
    """Test loading a malformed JSON configuration file."""
    RPCPluginConfig._instance = None # Ensure fresh load attempt
    malformed_json_content = '{"PLUGIN_MAGIC_COOKIE_VALUE": "json_cookie", "PLUGIN_AUTO_MTLS": ' # Missing value and closing brace
    malformed_json_file = tmp_path / "malformed.json"
    with open(malformed_json_file, "w") as f:
        f.write(malformed_json_content)

    with pytest.raises(ConfigError, match="Failed to decode JSON configuration file"):
        load_config_from_file(str(malformed_json_file))

def test_load_malformed_yaml(tmp_path: Path):
    """Test loading a malformed YAML configuration file."""
    RPCPluginConfig._instance = None
    # Example of malformed YAML: inconsistent indentation or unsupported characters
    malformed_yaml_content = "PLUGIN_MAGIC_COOKIE_VALUE: yaml_cookie\n  PLUGIN_AUTO_MTLS: true\nPLUGIN_LOG_LEVEL: DEBUG" # Intentionally bad indent for LOG_LEVEL
    malformed_yaml_file = tmp_path / "malformed.yaml"
    with open(malformed_yaml_file, "w") as f:
        f.write(malformed_yaml_content)

    with pytest.raises(ConfigError, match="Failed to parse YAML configuration file"):
        load_config_from_file(str(malformed_yaml_file))

def test_load_malformed_dotenv(tmp_path: Path):
    """Test loading a malformed .env configuration file."""
    RPCPluginConfig._instance = None
    malformed_env_content = "PLUGIN_MAGIC_COOKIE_VALUE_NO_EQUALS_HERE" # Line without '='
    malformed_env_file = tmp_path / "malformed.env"
    with open(malformed_env_file, "w") as f:
        f.write(malformed_env_content)

    # The error message for malformed .env lines was "Error parsing .env file.*Malformed line:.*"
    # Let's make it more specific if possible, or use a general "Failed to parse .env"
    with pytest.raises(ConfigError, match=r"Error parsing .env file.*Malformed line:.*PLUGIN_MAGIC_COOKIE_VALUE_NO_EQUALS_HERE"):
        load_config_from_file(str(malformed_env_file))

def test_load_non_existent_file(tmp_path: Path):
    """Test loading a non-existent configuration file."""
    RPCPluginConfig._instance = None
    non_existent_file = tmp_path / "non_existent_config.cfg"

    with pytest.raises(ConfigError, match=f"Configuration file not found: {str(non_existent_file)}"):
        load_config_from_file(str(non_existent_file))

def test_load_unsupported_file_type(tmp_path: Path):
    """Test loading an unsupported configuration file type."""
    RPCPluginConfig._instance = None
    unsupported_content = "some_data"
    unsupported_file = tmp_path / "config.txt" # .txt is not supported
    with open(unsupported_file, "w") as f:
        f.write(unsupported_content)

    with pytest.raises(ConfigError, match=r"Unsupported configuration file type: \.txt"):
        load_config_from_file(str(unsupported_file))
