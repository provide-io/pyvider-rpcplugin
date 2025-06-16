"""Configuration management for Pyvider RPC Plugin.

This module provides a configuration system for the Pyvider RPC Plugin framework,
allowing for environment-based and programmatic configuration. It includes:

1. A configuration schema with default values and validation
2. Environment variable reading with appropriate type conversion
3. A singleton configuration object for global access
4. Simplified configuration helpers for common settings

Usage:
    # Get a configuration value
    from pyvider.rpcplugin import rpcplugin_config
    cookie_value = rpcplugin_config.get("PLUGIN_MAGIC_COOKIE")

    # Set a configuration value
    rpcplugin_config.set("PLUGIN_AUTO_MTLS", "true")

    # Use the simplified configuration helper
    from pyvider.rpcplugin import configure
    configure(
        magic_cookie="my-plugin-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],
        auto_mtls=True,
    )
"""

import os
# from pathlib import Path # Removed Path
from typing import Any, Literal, cast, get_args  # Added Callable back

from pyvider.telemetry import logger


class ConfigError(ValueError):
    """Custom exception for configuration-related errors."""
    # Add more context if needed, e.g. error_code, hint
    def __init__(self, message: str, hint: str | None = None, code: int | None = None):
        super().__init__(message)
        self.message = message # Add this line
        self.hint = hint
        self.code = code

    def __str__(self) -> str:
        base_message = super().__str__()
        if self.hint:
            return f"{base_message} Hint: {self.hint}"
        return base_message


# Define supported protocol versions
SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]

# Define supported transport types
TRANSPORT_TYPES = Literal["unix", "tcp"]

# Configuration Schema: Defines environment variables, requirements, defaults, and descriptions
# This provides a single source of truth for all configuration options
CONFIG_SCHEMA: dict[str, dict[str, Any]] = {
    "SUPPORTED_PROTOCOL_VERSIONS": {
        "required": True,
        "default": SUPPORTED_PROTOCOL_VERSIONS,
        "description": "The Plugin Protocol Versions that `rpcplugin` will support.",
        "type": "list_int",
    },
    "PLUGIN_CORE_VERSION": {
        "required": True,
        "default": 1,
        "description": "The core RPC Plugin version. This rarely changes.",
        "type": "int",
    },
    "PLUGIN_LOG_LEVEL": {
        "required": False,
        "default": "INFO",
        "description": "Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
        "type": "str",
        "valid_values": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    },
    "PLUGIN_MAGIC_COOKIE_KEY": {
        "required": True,
        "default": "PLUGIN_MAGIC_COOKIE",
        "description": "Environment variable name for the magic cookie value.",
        "type": "str",
    },
    "PLUGIN_MAGIC_COOKIE_VALUE": {
        "required": True,
        "default": "rpcplugin-default-cookie",
        "description": "The expected magic cookie value for validation.",
        "type": "str",
    },
    "PLUGIN_MAGIC_COOKIE": {
        "required": True,
        "default": "rpcplugin-default-cookie",
        "description": "The actual cookie provided by the client.",
        "type": "str",
    },
    "PLUGIN_PROTOCOL_VERSIONS": {
        "required": True,
        "default": [1],
        "description": "List of supported protocol versions.",
        "type": "list_int",
    },
    "PLUGIN_SERVER_TRANSPORTS": {
        "required": True,
        "default": ["unix", "tcp"],
        "description": "List of transports supported by the server.",
        "type": "list_str",
        "valid_values": [["unix"], ["tcp"], ["unix", "tcp"], ["tcp", "unix"]],
    },
    "PLUGIN_SERVER_ENDPOINT": {
        "required": False,
        "default": None,
        "description": "Server endpoint for connection (host:port for TCP, path for Unix).",
        "type": "str",
    },
    "PLUGIN_AUTO_MTLS": {
        "required": True,
        "default": "true",
        "description": "Flag to enable automatic mTLS (true/false).",
        "type": "bool",
    },
    "PLUGIN_SERVER_CERT": {
        "required": False,
        "default": None,
        "description": "Server certificate in PEM format or 'file://<path>' to read from a file.",
        "type": "str",
    },
    "PLUGIN_SERVER_KEY": {
        "required": False,
        "default": None,
        "description": "Server private key in PEM format or 'file://<path>' to read from a file.",
        "type": "str",
    },
    "PLUGIN_SERVER_ROOT_CERTS": {
        "required": False,
        "default": None,
        "description": "Root certificates for server in PEM format or 'file://<path>'.",
        "type": "str",
    },
    "PLUGIN_CLIENT_TRANSPORTS": {
        "required": True,
        "default": ["unix", "tcp"],
        "description": "List of transports supported by the client.",
        "type": "list_str",
        "valid_values": [["unix"], ["tcp"], ["unix", "tcp"], ["tcp", "unix"]],
    },
    "PLUGIN_CLIENT_ENDPOINT": {
        "required": False,
        "default": None,
        "description": "Client endpoint for connection.",
        "type": "str",
    },
    "PLUGIN_CLIENT_CERT": {
        "required": False,
        "default": None,
        "description": "Client certificate in PEM format or 'file://<path>' to read from a file.",
        "type": "str",
    },
    "PLUGIN_CLIENT_KEY": {
        "required": False,
        "default": None,
        "description": "Client private key in PEM format or 'file://<path>' to read from a file.",
        "type": "str",
    },
    "PLUGIN_CLIENT_ROOT_CERTS": {
        "required": False,
        "default": None,
        "description": "Root certificates for client in PEM format or 'file://<path>'.",
        "type": "str",
    },
    "PLUGIN_HANDSHAKE_TIMEOUT": {
        "required": False,
        "default": 10.0,
        "description": "Timeout in seconds for handshake operations.",
        "type": "float",
    },
    "PLUGIN_CONNECTION_TIMEOUT": {
        "required": False,
        "default": 30.0,
        "description": "Timeout in seconds for connection operations.",
        "type": "float",
    },
    "PLUGIN_SHOW_EMOJI_MATRIX": {
        "required": False,
        "default": "true",
        "description": "Show emoji matrix in logs for better visual tracking.",
        "type": "bool",
    },
    "PLUGIN_CLIENT_RETRY_ENABLED": {
        "required": False,
        "default": "true", # Retries enabled by default
        "description": "Enable automatic retries for client connection and handshake failures.",
        "type": "bool",
    },
    "PLUGIN_CLIENT_MAX_RETRIES": {
        "required": False,
        "default": 3, # Number of retry attempts (e.g., 3 retries means 1 initial attempt + 3 retries = 4 total attempts)
        "description": "Maximum number of retry attempts for client operations.",
        "type": "int",
    },
    "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": {
        "required": False,
        "default": 500, # Initial delay in milliseconds
        "description": "Initial backoff delay in milliseconds before the first retry.",
        "type": "int",
    },
    "PLUGIN_CLIENT_MAX_BACKOFF_MS": {
        "required": False,
        "default": 5000, # Maximum delay in milliseconds (e.g., 5 seconds)
        "description": "Maximum backoff delay in milliseconds between retries.",
        "type": "int",
    },
    "PLUGIN_CLIENT_RETRY_JITTER_MS": {
        "required": False,
        "default": 100, # Max jitter in milliseconds to add/subtract
        "description": "Maximum jitter in milliseconds to apply to backoff delays to prevent thundering herd.",
        "type": "int",
    },
    "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": {
        "required": False,
        "default": 60, # Total time in seconds to keep retrying before giving up
        "description": "Total timeout in seconds for the entire retry sequence for a client operation.",
        "type": "int", # Or float, but int is fine for seconds
    },
}


def fetch_env_variable(key: str, meta: dict[str, Any]) -> Any:
    """
    Fetches and processes an environment variable based on schema metadata.

    This function:
    1. Reads the variable from environment or uses default
    2. Handles file-based values (file://) by reading from the file
    3. Converts to the correct type based on schema information

    Args:
        key: The configuration key to fetch
        meta: Metadata about the configuration value

    Returns:
        The processed configuration value

    Raises:
        ConfigError: If file reading fails or type conversion fails
    """
    # Get raw value from environment or default
    value = os.getenv(key, meta["default"])
    # logger.debug(f"⚙️🔍✅ Reading config {key}: raw value = {value}") # lots of logs

    # Return None for None values
    if value is None:
        return None

    # Handle file-based values
    if isinstance(value, str) and value.startswith("file://"):
        file_path = value[7:]
        try:
            logger.debug(f"⚙️📂🚀 Reading file for {key}: {file_path}")
            with open(file_path, "r", encoding="utf-8") as f:
                value = f.read().strip()
                logger.debug(f"⚙️📂✅ Successfully read file for {key}")
        except Exception as e:
            logger.error(
                f"⚙️📂❌ Failed to read file for {key}: {file_path}",
                extra={"error": str(e)},
            )
            raise ConfigError(message=f"Failed to read configuration file specified for '{key}'. Path: {file_path}", hint="Ensure the file exists, is accessible, and has correct read permissions.") from e

    # Type conversion based on schema type
    try:
        # Using match/case for type conversion
        type_string = meta["type"]
        if type_string == "str":
            return value
        elif type_string == "int":
            if isinstance(value, int):
                return value
            return int(value)
        elif type_string == "float":
            if isinstance(value, float):
                return value
            return float(value)
        elif type_string == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ("true", "yes", "1", "on")
            return bool(value)
        elif type_string == "list_str":
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                return [v.strip() for v in value.split(",")]
            return list(value)
        elif type_string == "list_int":
            if isinstance(value, list) and all(isinstance(x, int) for x in value):
                return value
            if isinstance(value, list):
                return [int(v) for v in value]
            if isinstance(value, str):
                return [int(v.strip()) for v in value.split(",")]
            return [int(value)]
        else:
            logger.warning(
                f"⚙️⚠️ Unknown type {type_string} for {key}, returning raw value"
            )
            return value

    except (ValueError, TypeError) as e:
        logger.error(f"⚙️❌ Type conversion failed for {key}", extra={"error": str(e)})
        raise ConfigError(message=f"Invalid value format for configuration key '{key}'. Expected type '{meta['type']}', but received value '{value}'.", hint=f"Please check the value of '{key}' (currently '{value}') and ensure it conforms to the expected type ({meta['type']}).") from e


def validate_config_value(key: str, value: Any, meta: dict[str, Any]) -> bool:
    """
    Validates a configuration value against schema requirements.

    Args:
        key: The configuration key
        value: The value to validate
        meta: Schema metadata for the key

    Returns:
        True if valid, False otherwise

    Raises:
        ConfigError: For validation failures
    """
    logger.debug(f"⚙️🔍🚀 Validating config {key} = {value}")

    # Required check
    if meta.get("required", False) and value is None:
        logger.error(f"⚙️❌ Missing required configuration: {key}")
        raise ConfigError(message=f"Missing required configuration key: '{key}'. Description: {meta['description']}", hint=f"Please provide a value for the required configuration key '{key}'. This setting is essential for the plugin's operation.")

    # If value is None, no further validation needed
    if value is None:
        return True

    # Check valid_values if defined
    if "valid_values" in meta and value not in meta["valid_values"]:
        logger.error(
            f"⚙️❌ Invalid value for {key}: {value}",
            extra={"valid_values": meta["valid_values"]},
        )
        raise ConfigError(message=f"Invalid value '{value}' provided for configuration key '{key}'.", hint=f"The value '{value}' is not a valid option for '{key}'. Allowed values are: {meta['valid_values']}. Please choose one of these.")

    # logger.debug(f"⚙️🔍✅ Config {key} validation passed") # lots of logs
    return True


def get_config() -> dict[str, Any]:
    """
    Retrieves all configuration values from environment, applying defaults and validation.

    Returns:
        Dictionary of configuration key-value pairs

    Raises:
        ConfigError: For invalid configuration
    """
    config = {}
    logger.debug("⚙️🔄 Building configuration from environment and defaults")

    for key, meta in CONFIG_SCHEMA.items():
        try:
            value = fetch_env_variable(key, meta)
            validate_config_value(key, value, meta)
            config[key] = value
        except ConfigError: # Re-raise ConfigError directly
            raise
        except ValueError as e: # Should ideally not happen if fetch/validate use ConfigError
            logger.error(f"⚙️❌ Unexpected ValueError for {key}", extra={"error": str(e)})
            raise ConfigError(message=f"Unexpected validation or fetch error for {key}: {e}") from e


    logger.debug(f"⚙️✅ Configuration complete with {len(config)} values")
    return config


class RPCPluginConfig:
    """
    Configuration manager for Pyvider RPC Plugin.

    This class provides a singleton pattern for accessing configuration values,
    with methods for getting and setting values. It loads configuration from
    environment variables and defaults on initialization.

    Attributes:
        config: Dictionary of configuration values
    """

    _instance = None

    def __init__(self):
        """Initialize the configuration from environment and defaults."""
        self.config = {}
        try:
            self.config = get_config()
            logger.debug("⚙️✅ RPCPluginConfig initialized with environment variables")
        except Exception as e: # Catches ConfigError from get_config or other init issues
            logger.error(
                "⚙️❌ Error initializing RPCPluginConfig", extra={"error": str(e)}
            )
            raise # Re-raise the original error (could be ConfigError or other)

    @classmethod
    def instance(cls) -> "RPCPluginConfig":
        """
        Get or create the singleton instance.

        Returns:
            The singleton RPCPluginConfig instance
        """
        if cls._instance is None:
            cls._instance = cls()
            logger.debug("⚙️🔄 Created new RPCPluginConfig singleton instance")
        return cls._instance

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a configuration value.

        Args:
            key: The configuration key
            default: Default value if key doesn't exist

        Returns:
            The configuration value or default
        """
        value = self.config.get(key, default)
        logger.debug(f"⚙️📖 Getting config {key} = {value}")
        return value

    def get_list(self, key: str) -> list[Any]:
        """
        Retrieve a configuration value as a list.

        Args:
            key: The configuration key

        Returns:
            The configuration value as a list
        """
        value = self.get(key, [])
        if not isinstance(value, list):
            value = [value]
        logger.debug(f"⚙️📖 Getting list config {key} = {value}")
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value dynamically.

        Args:
            key: The configuration key
            value: The value to set

        Raises:
            ConfigError: If key is not in CONFIG_SCHEMA and not a 'PLUGIN_' prefixed dynamic key.
        """
        if key not in CONFIG_SCHEMA and not key.startswith("PLUGIN_"):
            logger.warning(f"⚙️⚠️ Setting unknown config key: {key}")
            raise ConfigError(message=f"Attempted to set an unknown configuration key: '{key}'.", hint="Ensure the configuration key is spelled correctly. It should be a predefined schema key or a dynamic key starting with 'PLUGIN_'.")

        logger.debug(f"⚙️📝 Updating config {key} -> {value}")
        self.config[key] = value

    def magic_cookie_key(self) -> str:
        """
        Get the configured magic cookie key.

        Returns:
            The magic cookie key
        """
        return cast(str, self.get("PLUGIN_MAGIC_COOKIE_KEY"))

    def magic_cookie_value(self) -> str:
        """
        Get the expected magic cookie value.

        Returns:
            The magic cookie value
        """
        return cast(str, self.get("PLUGIN_MAGIC_COOKIE_VALUE"))

    def server_transports(self) -> list[str]:
        """
        Get the list of transports supported by the server.

        Returns:
            List of transport names
        """
        return cast(list[str], self.get_list("PLUGIN_SERVER_TRANSPORTS"))

    def server_endpoint(self) -> str | None:
        """
        Get the server endpoint configuration.

        Returns:
            The server endpoint or None
        """
        return cast(str | None, self.get("PLUGIN_SERVER_ENDPOINT"))

    def client_transports(self) -> list[str]:
        """
        Get the list of transports supported by the client.

        Returns:
            List of transport names
        """
        return cast(list[str], self.get_list("PLUGIN_CLIENT_TRANSPORTS"))

    def client_endpoint(self) -> str | None:
        """
        Get the client endpoint configuration.

        Returns:
            The client endpoint or None
        """
        return cast(str | None, self.get("PLUGIN_CLIENT_ENDPOINT"))

    def auto_mtls_enabled(self) -> bool:
        """
        Check if auto mTLS is enabled.

        Returns:
            True if enabled, False otherwise
        """
        return cast(bool, self.get("PLUGIN_AUTO_MTLS"))

    def handshake_timeout(self) -> float:
        """
        Get the handshake timeout in seconds.

        Returns:
            Timeout in seconds
        """
        return cast(float, self.get("PLUGIN_HANDSHAKE_TIMEOUT"))

    def connection_timeout(self) -> float:
        """
        Get the connection timeout in seconds.

        Returns:
            Timeout in seconds
        """
        return cast(float, self.get("PLUGIN_CONNECTION_TIMEOUT"))


# Global singleton instance
rpcplugin_config = RPCPluginConfig.instance()


def configure(
    magic_cookie: str | None = None,
    protocol_version: int | None = None,
    transports: list[str | TRANSPORT_TYPES] | None = None,
    auto_mtls: bool | None = None,
    handshake_timeout: float | None = None,
    connection_timeout: float | None = None,
    server_cert: str | None = None,
    server_key: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    **kwargs: Any,
) -> None:
    """
    Configure Pyvider RPC plugin with simplified options.

    This function provides a more user-friendly way to configure the plugin system
    compared to setting individual environment variables. It handles type conversion
    and validation automatically.

    Args:
        magic_cookie: The plugin magic cookie for handshake validation
        protocol_version: The protocol version to use
        transports: List of supported transports (e.g. ["unix", "tcp"])
        auto_mtls: Enable/disable automatic mTLS
        handshake_timeout: Timeout in seconds for handshake operations
        connection_timeout: Timeout in seconds for connection operations
        server_cert: Server certificate in PEM format or file:// path
        server_key: Server private key in PEM format or file:// path
        client_cert: Client certificate in PEM format or file:// path
        client_key: Client private key in PEM format or file:// path
        **kwargs: Any additional configuration options

    Raises:
        ConfigError: For invalid configuration values (e.g. unknown transport type)
    """
    logger.debug("⚙️🔄 Running simplified configuration")

    # Magic cookie configuration
    if magic_cookie is not None:
        rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_VALUE", magic_cookie)
        rpcplugin_config.set("PLUGIN_MAGIC_COOKIE", magic_cookie)
        logger.debug(f"⚙️📝 Set magic cookie: {magic_cookie}")

    # Protocol version configuration
    if protocol_version is not None:
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            logger.warning(
                f"⚙️⚠️ Unsupported protocol version: {protocol_version}",
                extra={"supported": SUPPORTED_PROTOCOL_VERSIONS},
            )
        rpcplugin_config.set("PLUGIN_PROTOCOL_VERSIONS", [protocol_version])
        logger.debug(f"⚙️📝 Set protocol version: {protocol_version}")

    # Transport configuration
    if transports is not None:
        # Validate transport types
        for transport in transports:
            if transport not in get_args(TRANSPORT_TYPES):
                logger.error(
                    f"⚙️❌ Unknown transport type: {transport}",
                    extra={"valid": get_args(TRANSPORT_TYPES)},
                )
                raise ConfigError(message=f"Unknown transport type specified: '{transport}'.", hint=f"Valid transport types are: {list(get_args(TRANSPORT_TYPES))}. Please use one of these.")

        rpcplugin_config.set("PLUGIN_SERVER_TRANSPORTS", transports)
        rpcplugin_config.set("PLUGIN_CLIENT_TRANSPORTS", transports)
        logger.debug(f"⚙️📝 Set transports: {transports}")

    # Auto mTLS configuration
    if auto_mtls is not None:
        rpcplugin_config.set("PLUGIN_AUTO_MTLS", "true" if auto_mtls else "false")
        logger.debug(f"⚙️📝 Set auto mTLS: {auto_mtls}")

    # Timeout configurations
    if handshake_timeout is not None:
        rpcplugin_config.set("PLUGIN_HANDSHAKE_TIMEOUT", handshake_timeout)
        logger.debug(f"⚙️📝 Set handshake timeout: {handshake_timeout}s")

    if connection_timeout is not None:
        rpcplugin_config.set("PLUGIN_CONNECTION_TIMEOUT", connection_timeout)
        logger.debug(f"⚙️📝 Set connection timeout: {connection_timeout}s")

    # Certificate configurations
    if server_cert is not None:
        rpcplugin_config.set("PLUGIN_SERVER_CERT", server_cert)
        logger.debug("⚙️📝 Set server certificate")

    if server_key is not None:
        rpcplugin_config.set("PLUGIN_SERVER_KEY", server_key)
        logger.debug("⚙️📝 Set server key")

    if client_cert is not None:
        rpcplugin_config.set("PLUGIN_CLIENT_CERT", client_cert)
        logger.debug("⚙️📝 Set client certificate")

    if client_key is not None:
        rpcplugin_config.set("PLUGIN_CLIENT_KEY", client_key)
        logger.debug("⚙️📝 Set client key")

    # Set any additional options
    for key, value in kwargs.items():
        config_key = f"PLUGIN_{key.upper()}"
        rpcplugin_config.set(config_key, value)
        logger.debug(f"⚙️📝 Set additional config {config_key} = {value}")

    logger.debug("⚙️✅ Configuration completed successfully")
