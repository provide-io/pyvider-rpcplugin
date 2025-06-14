"""Configuration management for Pyvider RPC Plugin.

This module provides a configuration system for the Pyvider RPC Plugin framework,
allowing for both environment-based and programmatic configuration. It includes:

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
from pathlib import Path
from typing import Any, Literal, cast, get_args  # Removed Dict, List, Optional


from pyvider.telemetry import logger

# Define supported protocol versions
SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]

# Define supported transport types
TRANSPORT_TYPES = Literal["unix", "tcp"]

# Key mappings for JSON/YAML files to CONFIG_SCHEMA keys
# This helps use shorter, more user-friendly keys in JSON/YAML
KEY_MAPPINGS: dict[str, str] = {
    "magic_cookie": "PLUGIN_MAGIC_COOKIE_VALUE",
    "magic_cookie_value": "PLUGIN_MAGIC_COOKIE_VALUE", # Allow full name too
    "auto_mtls": "PLUGIN_AUTO_MTLS",
    "handshake_timeout": "PLUGIN_HANDSHAKE_TIMEOUT",
    "connection_timeout": "PLUGIN_CONNECTION_TIMEOUT",
    "log_level": "PLUGIN_LOG_LEVEL",
    "server_transports": "PLUGIN_SERVER_TRANSPORTS",
    "client_transports": "PLUGIN_CLIENT_TRANSPORTS",
    "server_endpoint": "PLUGIN_SERVER_ENDPOINT",
    "client_endpoint": "PLUGIN_CLIENT_ENDPOINT",
    "server_cert": "PLUGIN_SERVER_CERT",
    "server_key": "PLUGIN_SERVER_KEY",
    "server_root_certs": "PLUGIN_SERVER_ROOT_CERTS",
    "client_cert": "PLUGIN_CLIENT_CERT",
    "client_key": "PLUGIN_CLIENT_KEY",
    "client_root_certs": "PLUGIN_CLIENT_ROOT_CERTS",
    "protocol_versions": "PLUGIN_PROTOCOL_VERSIONS",
    "show_emoji_matrix": "PLUGIN_SHOW_EMOJI_MATRIX",
    # Direct CONFIG_SCHEMA keys can also be used in files, so this map is for convenience
}

DOTENV_KEY_MAPPINGS: dict[str, str] = {
    "PYVIDER_MAGIC_COOKIE": "PLUGIN_MAGIC_COOKIE_VALUE",
    "PYVIDER_AUTO_MTLS": "PLUGIN_AUTO_MTLS",
    "PYVIDER_HANDSHAKE_TIMEOUT": "PLUGIN_HANDSHAKE_TIMEOUT",
    "PYVIDER_CONNECTION_TIMEOUT": "PLUGIN_CONNECTION_TIMEOUT",
    "PYVIDER_LOG_LEVEL": "PLUGIN_LOG_LEVEL",
    "PYVIDER_SERVER_TRANSPORTS": "PLUGIN_SERVER_TRANSPORTS",
    "PYVIDER_CLIENT_TRANSPORTS": "PLUGIN_CLIENT_TRANSPORTS",
    "PYVIDER_SERVER_ENDPOINT": "PLUGIN_SERVER_ENDPOINT",
    "PYVIDER_CLIENT_ENDPOINT": "PLUGIN_CLIENT_ENDPOINT",
    "PYVIDER_SERVER_CERT": "PLUGIN_SERVER_CERT",
    "PYVIDER_SERVER_KEY": "PLUGIN_SERVER_KEY",
    "PYVIDER_SERVER_ROOT_CERTS": "PLUGIN_SERVER_ROOT_CERTS",
    "PYVIDER_CLIENT_CERT": "PLUGIN_CLIENT_CERT",
    "PYVIDER_CLIENT_KEY": "PLUGIN_CLIENT_KEY",
    "PYVIDER_CLIENT_ROOT_CERTS": "PLUGIN_CLIENT_ROOT_CERTS",
    "PYVIDER_PROTOCOL_VERSIONS": "PLUGIN_PROTOCOL_VERSIONS",
    "PYVIDER_SHOW_EMOJI_MATRIX": "PLUGIN_SHOW_EMOJI_MATRIX",
}

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
        ValueError: If file reading fails or type conversion fails
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
            raise ValueError(f"Failed to read file for {key}: {file_path}") from e

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
        raise ValueError(
            f"Invalid format for {key}. Expected {meta['type']}, got: {value}"
        ) from e


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
        ValueError: For validation failures
    """
    logger.debug(f"⚙️🔍🚀 Validating config {key} = {value}")

    # Required check
    if meta.get("required", False) and value is None:
        logger.error(f"⚙️❌ Missing required configuration: {key}")
        raise ValueError(
            f"Missing required configuration: {key}. {meta['description']}"
        )

    # If value is None, no further validation needed
    if value is None:
        return True

    # Check valid_values if defined
    if "valid_values" in meta and value not in meta["valid_values"]:
        logger.error(
            f"⚙️❌ Invalid value for {key}: {value}",
            extra={"valid_values": meta["valid_values"]},
        )
        raise ValueError(
            f"Invalid value for {key}: {value}. Valid values: {meta['valid_values']}"
        )

    # logger.debug(f"⚙️🔍✅ Config {key} validation passed") # lots of logs
    return True


def get_config() -> dict[str, Any]:
    """
    Retrieves all configuration values from environment, applying defaults and validation.

    Returns:
        Dictionary of configuration key-value pairs

    Raises:
        ValueError: For invalid configuration
    """
    config = {}
    logger.debug("⚙️🔄 Building configuration from environment and defaults")

    for key, meta in CONFIG_SCHEMA.items():
        try:
            value = fetch_env_variable(key, meta)
            validate_config_value(key, value, meta)
            config[key] = value
        except ValueError as e:
            logger.error(f"⚙️❌ Configuration error for {key}", extra={"error": str(e)})
            raise

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
        except Exception as e:
            logger.error(
                "⚙️❌ Error initializing RPCPluginConfig", extra={"error": str(e)}
            )
            raise

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
            KeyError: If key is not in CONFIG_SCHEMA
        """
        if key not in CONFIG_SCHEMA and not key.startswith("PLUGIN_"):
            logger.warning(f"⚙️⚠️ Setting unknown config key: {key}")
            raise KeyError(f"Unknown configuration key: {key}")

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
        ValueError: For invalid configuration values
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
                raise ValueError(
                    f"Unknown transport type: {transport}. Valid types: {get_args(TRANSPORT_TYPES)}"
                )

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


def load_config_from_file(config_file: str | Path) -> None:
    """
    Load configuration from a file.

    The file can be:
    - A .env file with KEY=VALUE pairs
    - A JSON file with configuration in JSON format
    - A YAML file with configuration in YAML format

    Args:
        config_file: Path to the configuration file

    Raises:
        ValueError: If the file format is not supported or loading fails
    """
    path = Path(config_file) if isinstance(config_file, str) else config_file

    if not path.exists():
        logger.error(f"⚙️❌ Configuration file not found: {path}")
        raise ValueError(f"Configuration file not found: {path}")

    logger.debug(f"⚙️📂🚀 Loading configuration from {path}")

    try:
        # Using match/case for file type handling
        suffix = path.suffix.lower()
        if suffix == ".env":
            _load_dotenv_file(path)
        elif suffix == ".json":
            _load_json_file(path)
        elif suffix in (".yaml", ".yml"):
            _load_yaml_file(path)
        else:
            logger.error(f"⚙️❌ Unsupported file format: {suffix}")
            raise ValueError(
                f"Unsupported file format: {suffix}. Supported formats: .env, .json, .yaml, .yml"
            )

        # Reload configuration from environment
        rpcplugin_config.config = get_config()
        logger.debug(f"⚙️📂✅ Successfully loaded configuration from {path}")

    except Exception as e:
        logger.error(
            f"⚙️📂❌ Error loading configuration from {path}", extra={"error": str(e)}
        )
        raise ValueError(f"Error loading configuration from {path}: {e}") from e


def _load_dotenv_file(path: Path) -> None:
    """
    Load configuration from a .env file.

    Args:
        path: Path to the .env file

    Raises:
        ValueError: If loading fails
    """
    logger.debug(f"⚙️📂🚀 Loading .env file: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        for line in content.splitlines():  # Process lines from full content
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Remove quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            if value.startswith("'") and value.endswith("'"):
                value = value[1:-1]

            # Original key from .env file
            os.environ[key] = value
            logger.debug(f"⚙️📂✅ Set environment variable from .env: {key}='{value}'")

            # Additionally, if this key is a PYVIDER_ alias, also set the canonical PLUGIN_ version
            mapped_plugin_key = DOTENV_KEY_MAPPINGS.get(key)
            if mapped_plugin_key and mapped_plugin_key != key and mapped_plugin_key in CONFIG_SCHEMA:
                 os.environ[mapped_plugin_key] = value
                 logger.debug(f"⚙️📂✅ Also set mapped schema key: {mapped_plugin_key}='{value}' for original .env key '{key}'")

    except Exception as e:
        logger.error(f"⚙️📂❌ Error loading .env file: {path}", extra={"error": str(e)})
        raise ValueError(f"Error loading .env file: {path}") from e


def _load_json_file(path: Path) -> None:
    """
    Load configuration from a JSON file.

    Args:
        path: Path to the JSON file

    Raises:
        ValueError: If loading fails
    """
    logger.debug(f"⚙️📂🚀 Loading JSON file: {path}")

    try:
        import json

        with open(path, "r", encoding="utf-8") as f:
            config_data = json.load(f)

        for key, value in config_data.items():
            stringified_value = ""
            # Determine schema key for type-aware stringification if possible
            # Check direct key match in schema, then check if key is an alias in KEY_MAPPINGS
            schema_key_for_type_lookup = key
            if key not in CONFIG_SCHEMA: # If original key is not a direct schema key
                mapped_key = KEY_MAPPINGS.get(key)
                if mapped_key and mapped_key in CONFIG_SCHEMA: # Check if it's an alias for a schema key
                    schema_key_for_type_lookup = mapped_key

            if schema_key_for_type_lookup in CONFIG_SCHEMA:
                meta = CONFIG_SCHEMA[schema_key_for_type_lookup]
                if meta["type"] == "list_str" or meta["type"] == "list_int":
                    if isinstance(value, list):
                        stringified_value = ",".join(map(str, value))
                    else:
                        stringified_value = str(value)
                elif meta["type"] == "bool":
                    stringified_value = "true" if value else "false"
                else: # str, int, float
                    stringified_value = str(value)
            else: # Key is not in schema, directly or via mapping - use generic stringification
                if isinstance(value, (list, dict)):
                    stringified_value = json.dumps(value) # Use json.dumps for lists/dicts not in schema
                elif isinstance(value, bool):
                    stringified_value = "true" if value else "false"
                else:
                    stringified_value = str(value)

            # Set the original key from the JSON file into os.environ
            os.environ[key] = stringified_value
            logger.debug(f"⚙️📂✅ Set environment variable from JSON (original key): {key}='{stringified_value}'")

            # Handle mapped schema keys if the original key was an alias
            mapped_schema_key = KEY_MAPPINGS.get(key)
            if mapped_schema_key and mapped_schema_key != key and mapped_schema_key in CONFIG_SCHEMA:
                # The stringified_value was already determined based on the target schema type if 'key' mapped to it.
                # So, we can reuse stringified_value here if schema_key_for_type_lookup was indeed mapped_schema_key.
                # If 'key' was a direct schema key AND ALSO an alias for a DIFFERENT schema key (unlikely/confusing setup),
                # then this re-set might use stringification rules of the first schema key found.
                # For simplicity here, we assume stringified_value is appropriate.
                os.environ[mapped_schema_key] = stringified_value
                logger.debug(f"⚙️📂✅ Also set mapped schema key from JSON: {mapped_schema_key}='{stringified_value}' for original key '{key}'")

    except Exception as e:
        logger.error(f"⚙️📂❌ Error loading JSON file: {path}", extra={"error": str(e)})
        raise ValueError(f"Error loading JSON file: {path}") from e


def _load_yaml_file(path: Path) -> None:
    """
    Load configuration from a YAML file.

    Args:
        path: Path to the YAML file

    Raises:
        ValueError: If loading fails or PyYAML is not installed
    """
    logger.debug(f"⚙️📂🚀 Loading YAML file: {path}")

    try:
        try:
            import yaml
        except ImportError:
            logger.error("⚙️📂❌ PyYAML is required for YAML configuration")
            raise ValueError(
                "PyYAML is required for YAML configuration. Install with 'pip install PyYAML'"
            )

        with open(path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f)

        # Ensure json is imported for json.dumps fallback if not already at the top
        import json

        for key, value in config_data.items():
            stringified_value = ""
            # Determine schema key for type-aware stringification if possible
            schema_key_for_type_lookup = key
            if key not in CONFIG_SCHEMA:
                mapped_key = KEY_MAPPINGS.get(key)
                if mapped_key and mapped_key in CONFIG_SCHEMA:
                    schema_key_for_type_lookup = mapped_key

            if schema_key_for_type_lookup in CONFIG_SCHEMA:
                meta = CONFIG_SCHEMA[schema_key_for_type_lookup]
                if meta["type"] == "list_str" or meta["type"] == "list_int":
                    if isinstance(value, list):
                        stringified_value = ",".join(map(str, value))
                    else:
                        stringified_value = str(value)
                elif meta["type"] == "bool":
                    stringified_value = "true" if value else "false"
                else: # str, int, float
                    stringified_value = str(value)
            else: # Key is not in schema, directly or via mapping
                if isinstance(value, (list, dict)):
                    stringified_value = json.dumps(value) # Use json.dumps for consistency
                elif isinstance(value, bool):
                    stringified_value = "true" if value else "false"
                else:
                    stringified_value = str(value)

            # Set the original key from the YAML file into os.environ
            os.environ[key] = stringified_value
            logger.debug(f"⚙️📂✅ Set environment variable from YAML (original key): {key}='{stringified_value}'")

            # Handle mapped schema keys if the original key was an alias
            mapped_schema_key = KEY_MAPPINGS.get(key)
            if mapped_schema_key and mapped_schema_key != key and mapped_schema_key in CONFIG_SCHEMA:
                os.environ[mapped_schema_key] = stringified_value
                logger.debug(f"⚙️📂✅ Also set mapped schema key from YAML: {mapped_schema_key}='{stringified_value}' for original key '{key}'")

    except Exception as e:
        logger.error(f"⚙️📂❌ Error loading YAML file: {path}", extra={"error": str(e)})
        raise ValueError(f"Error loading YAML file: {path}") from e


# Initialize all the things
if __name__ == "__main__":
    # This branch is not normally executed but can be used for testing
    config = rpcplugin_config
    logger.info(f"⚙️ Configuration loaded with {len(config.config)} values")
    for key, value in sorted(config.config.items()):
        logger.info(f"⚙️ {key} = {value}")
