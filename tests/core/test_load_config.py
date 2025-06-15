from pyvider.rpcplugin import configure, RPCPluginConfig
# from pyvider.rpcplugin.config import load_config_from_file
import os

def print_config(source_file=None):
    config = RPCPluginConfig.instance() # Consistently get the singleton instance
    print(f"--- Configuration from: {source_file if source_file else 'Defaults/Env Vars'} ---")
    print(f"Magic Cookie: {config.magic_cookie_value()}")
    print(f"Auto mTLS: {config.auto_mtls_enabled()}")      # Corrected method name
    print(f"Handshake Timeout: {config.handshake_timeout()}")  # Corrected method name
    # Add other relevant config options if necessary
    print("--------------------\n")

# Reset to defaults before starting tests
configure()
print_config("Initial Defaults")

# Test JSON
configure() # Reset to defaults
# load_config_from_file("test_config.json")
print_config("test_config.json")

# Test YAML
configure() # Reset to defaults
# load_config_from_file("test_config.yaml")
print_config("test_config.yaml")

# Test .env
configure() # Reset to defaults

# Clear relevant env vars first to ensure .env file is the source of truth for these values
# These should be the actual keys that get stored in os.environ by the JSON/YAML loaders
# and that are defined in CONFIG_SCHEMA.
original_env = {}
keys_to_clear = [
    "PLUGIN_MAGIC_COOKIE_VALUE",
    "PLUGIN_AUTO_MTLS",
    "PLUGIN_HANDSHAKE_TIMEOUT",
    # PYVIDER_UNKNOWN_OPTION is not used by config system,
    # but good to clear if it was set by .env previously by mistake
    "PYVIDER_UNKNOWN_OPTION",
    "PLUGIN_UNKNOWN_OPTION" # If any file accidentally wrote this
]

for key in keys_to_clear:
    if key in os.environ:
        original_env[key] = os.environ.pop(key)

# Load .env file. This populates os.environ and updates the RPCPluginConfig singleton.
# load_config_from_file("test_config.env")
print_config("test_config.env")

# Restore original environment variables and reset config to that state (or defaults if none were stored)
for key, value in original_env.items():
    os.environ[key] = value
configure() # Re-evaluate config based on potentially restored env vars or defaults.

print("Finished config loading tests.")
