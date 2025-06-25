# examples/example_utils.py
"""
Utility functions for pyvider-rpcplugin examples to ensure consistent
configuration and behavior, especially regarding environment variables
and magic cookies.
"""

import os
from typing import Any

from pyvider.rpcplugin import configure as rpcplugin_configure
from pyvider.rpcplugin.config import rpcplugin_config as global_rpcplugin_config

# --- Default Configuration Values ---
DEFAULT_MAGIC_COOKIE_KEY = "PYVIDER_PLUGIN_MAGIC_COOKIE"
DEFAULT_MAGIC_COOKIE_VALUE = "pyvider-rpcplugin-secure-cookie-v1"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_PROTOCOL_VERSIONS = [1]
DEFAULT_SERVER_TRANSPORTS = ["unix", "tcp"]
DEFAULT_CLIENT_TRANSPORTS = ["unix", "tcp"]
DEFAULT_AUTO_MTLS = False  # Keep examples simple by default
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_CONNECTION_TIMEOUT = 30.0


def get_example_config(**overrides: Any) -> dict[str, Any]:
    """
    Provides a consistent base configuration for examples, allowing overrides.

    This helps ensure that examples run with predictable settings and are
    less affected by external environment variables, especially for
    critical parameters like magic cookies.

    Args:
        **overrides: Specific configuration keys and values to override
                     the defaults.

    Returns:
        A dictionary of configuration parameters.
    """
    config = {
        "PLUGIN_MAGIC_COOKIE_KEY": DEFAULT_MAGIC_COOKIE_KEY,
        "PLUGIN_MAGIC_COOKIE_VALUE": DEFAULT_MAGIC_COOKIE_VALUE,
        "PLUGIN_LOG_LEVEL": DEFAULT_LOG_LEVEL,
        "PLUGIN_PROTOCOL_VERSIONS": DEFAULT_PROTOCOL_VERSIONS,
        "PLUGIN_SERVER_TRANSPORTS": DEFAULT_SERVER_TRANSPORTS,
        "PLUGIN_CLIENT_TRANSPORTS": DEFAULT_CLIENT_TRANSPORTS,
        "PLUGIN_AUTO_MTLS": DEFAULT_AUTO_MTLS,
        "PLUGIN_HANDSHAKE_TIMEOUT": DEFAULT_HANDSHAKE_TIMEOUT,
        "PLUGIN_CONNECTION_TIMEOUT": DEFAULT_CONNECTION_TIMEOUT,
        # Ensure the actual magic cookie env var is also set if not overridden
        DEFAULT_MAGIC_COOKIE_KEY: DEFAULT_MAGIC_COOKIE_VALUE,
    }

    # Apply overrides
    for key, value in overrides.items():
        config[key] = value
        # If the override is for the cookie key or value, update the actual cookie env var too
        if key == "PLUGIN_MAGIC_COOKIE_KEY" and "PLUGIN_MAGIC_COOKIE_VALUE" not in overrides:
            # Update the actual cookie env var name if key changes, retain default value
            old_key = config.pop(DEFAULT_MAGIC_COOKIE_KEY, None) # remove old one if it exists
            config[value] = config.get("PLUGIN_MAGIC_COOKIE_VALUE", DEFAULT_MAGIC_COOKIE_VALUE)
        elif key == "PLUGIN_MAGIC_COOKIE_VALUE":
            cookie_key_to_use = config.get("PLUGIN_MAGIC_COOKIE_KEY", DEFAULT_MAGIC_COOKIE_KEY)
            config[cookie_key_to_use] = value


    # Special handling: if PLUGIN_MAGIC_COOKIE_KEY is overridden,
    # the actual env var key needs to change.
    # And if PLUGIN_MAGIC_COOKIE_VALUE is overridden, its value needs to change.
    current_cookie_key = config["PLUGIN_MAGIC_COOKIE_KEY"]
    current_cookie_value = config["PLUGIN_MAGIC_COOKIE_VALUE"]

    # Remove the default key if it's different and was added
    if current_cookie_key != DEFAULT_MAGIC_COOKIE_KEY and DEFAULT_MAGIC_COOKIE_KEY in config:
        del config[DEFAULT_MAGIC_COOKIE_KEY]

    config[current_cookie_key] = current_cookie_value


    return config


def configure_for_example(**overrides: Any) -> None:
    """
    Configures the pyvider-rpcplugin using a consistent base setup
    for examples.

    This function calls `pyvider.rpcplugin.configure()` with a set of
    standard defaults suitable for most examples, ensuring that critical
    settings like magic cookies are explicitly managed rather than relying
    on potentially conflicting ambient environment variables.

    It's recommended to call this at the beginning of an example script
    or within specific example functions that require isolated configuration.

    Args:
        **overrides: Specific configuration keys and values to override
                     the defaults provided by `get_example_config`.
                     For example, to enable mTLS:
                     `configure_for_example(PLUGIN_AUTO_MTLS=True)`
    """
    example_cfg_params = get_example_config(**overrides)

    # The `configure` function primarily looks at keys starting with "PLUGIN_"
    # Other keys in example_cfg_params (like the actual magic cookie key)
    # are more for direct environment variable setting if needed by the
    # client launch logic, which will be handled separately.

    plugin_specific_config = {
        k: v for k, v in example_cfg_params.items() if k.startswith("PLUGIN_")
    }
    rpcplugin_configure(**plugin_specific_config)

    # Additionally, ensure the global config singleton reflects these values
    # for any direct rpcplugin_config.get() calls within the library
    # that might occur before a server/client fully initializes its own config copy.
    for key, value in plugin_specific_config.items():
        try:
            global_rpcplugin_config.set(key, value)
        except Exception:
            # Silently ignore if a key is not directly settable or known,
            # as `configure` is the primary mechanism.
            pass


def clear_plugin_env_vars() -> None:
    """
    Unsets all environment variables starting with "PLUGIN_" to ensure
    a clean environment for examples. This is useful to run before
    `configure_for_example` if there's a concern about ambient environment
    variables interfering.
    """
    plugin_vars = [var for var in os.environ if var.startswith("PLUGIN_")]
    for var in plugin_vars:
        del os.environ[var]

    # Also clear the default magic cookie key if it's set
    if DEFAULT_MAGIC_COOKIE_KEY in os.environ:
        del os.environ[DEFAULT_MAGIC_COOKIE_KEY]

# Example usage (typically not run directly from here):
if __name__ == "__main__":
    print("Example Utils - Default Config:")
    print(get_example_config())

    print("\nExample Utils - Config with mTLS override:")
    print(get_example_config(PLUGIN_AUTO_MTLS=True, PLUGIN_LOG_LEVEL="DEBUG"))

    print("\nConfiguring for example (default):")
    configure_for_example()
    # print(f"RPC Plugin Config Log Level: {rpcplugin_config.log_level()}")
    # print(f"RPC Plugin Config MCK: {rpcplugin_config.magic_cookie_key()}")
    # print(f"RPC Plugin Config MCV: {rpcplugin_config.magic_cookie_value()}")


    print("\nConfiguring for example (with overrides):")
    configure_for_example(PLUGIN_AUTO_MTLS=True, PLUGIN_LOG_LEVEL="DEBUG", PLUGIN_MAGIC_COOKIE_VALUE="override_cookie")
    # print(f"RPC Plugin Config Log Level: {rpcplugin_config.log_level()}")
    # print(f"RPC Plugin Config MCK: {rpcplugin_config.magic_cookie_key()}")
    # print(f"RPC Plugin Config MCV: {rpcplugin_config.magic_cookie_value()}")
    # print(f"Actual cookie in env from get_example_config: {os.environ.get(rpcplugin_config.magic_cookie_key())}")


    # Demonstrate clearing
    # os.environ["PLUGIN_FOO"] = "bar"
    # os.environ[DEFAULT_MAGIC_COOKIE_KEY] = "baz"
    # print(f"\nBefore clear: PLUGIN_FOO={os.environ.get('PLUGIN_FOO')}, {DEFAULT_MAGIC_COOKIE_KEY}={os.environ.get(DEFAULT_MAGIC_COOKIE_KEY)}")
    # clear_plugin_env_vars()
    # print(f"After clear: PLUGIN_FOO={os.environ.get('PLUGIN_FOO')}, {DEFAULT_MAGIC_COOKIE_KEY}={os.environ.get(DEFAULT_MAGIC_COOKIE_KEY)}")
