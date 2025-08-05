#
# src/pyvider/rpcplugin/config.py
#

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
from typing import Any, Literal, cast, get_args

from pyvider.telemetry import logger

from .exception import ConfigError

# Define supported protocol versions
SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]

# Define supported transport types
TRANSPORT_TYPES = Literal["unix", "tcp"]

# Configuration Schema: Defines environment variables, requirements, defaults,
# and descriptions
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
        "default": "test_cookie_value",
        "description": "The expected magic cookie value for validation.",
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
        "description": (
            "Server endpoint for connection (host:port for TCP, path for Unix)."
        ),
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
        "description": (
            "Server certificate in PEM format or 'file://<path>' to read from a file."
        ),
        "type": "str",
    },
    "PLUGIN_SERVER_KEY": {
        "required": False,
        "default": None,
        "description": (
            "Server private key in PEM format or 'file://<path>' to read from a file."
        ),
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
        "description": (
            "Client certificate in PEM format or 'file://<path>' to read from a file."
        ),
        "type": "str",
    },
    "PLUGIN_CLIENT_KEY": {
        "required": False,
        "default": None,
        "description": (
            "Client private key in PEM format or 'file://<path>' to read from a file."
        ),
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
        "default": "true",
        "description": (
            "Enable automatic retries for client connection and handshake failures."
        ),
        "type": "bool",
    },
    "PLUGIN_CLIENT_MAX_RETRIES": {
        "required": False,
        "default": 3,
        "description": "Maximum number of retry attempts for client operations.",
        "type": "int",
    },
    "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": {
        "required": False,
        "default": 500,
        "description": "Initial backoff delay in milliseconds before the first retry.",
        "type": "int",
    },
    "PLUGIN_CLIENT_MAX_BACKOFF_MS": {
        "required": False,
        "default": 5000,
        "description": "Maximum backoff delay in milliseconds between retries.",
        "type": "int",
    },
    "PLUGIN_CLIENT_RETRY_JITTER_MS": {
        "required": False,
        "default": 100,
        "description": (
            "Maximum jitter in milliseconds to apply to backoff delays to prevent "
            "thundering herd."
        ),
        "type": "int",
    },
    "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": {
        "required": False,
        "default": 60,
        "description": (
            "Total timeout in seconds for the entire retry sequence for a client "
            "operation."
        ),
        "type": "int",
    },
    "PLUGIN_SHUTDOWN_FILE_PATH": {
        "required": False,
        "default": None,
        "description": (
            "Path to a file that, if created, will trigger a graceful server shutdown."
        ),
        "type": "str",
    },
    "PLUGIN_RATE_LIMIT_ENABLED": {
        "required": False,
        "default": "false",
        "description": "Enable or disable server-side rate limiting.",
        "type": "bool",
    },
    "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": {
        "required": False,
        "default": 100.0,
        "description": "Maximum allowed requests per second on average for the server.",
        "type": "float",
    },
    "PLUGIN_RATE_LIMIT_BURST_CAPACITY": {
        "required": False,
        "default": 200.0,
        "description": "Maximum number of requests allowed in a burst for the server.",
        "type": "float",
    },
    "PLUGIN_HEALTH_SERVICE_ENABLED": {
        "required": False,
        "default": "true",
        "description": "Enable or disable the standard gRPC health checking service.",
        "type": "bool",
    },
}


def fetch_env_variable(key: str, meta: dict[str, Any]) -> Any:
    """
    Fetches and processes an environment variable based on schema metadata.
    """
    value = os.getenv(key, meta["default"])

    if value is None:
        return None

    if isinstance(value, str) and value.startswith("file://"):
        file_path = value[7:]
        try:
            logger.debug(f"⚙️📂🚀 Reading file for {key}: {file_path}")
            with open(file_path, encoding="utf-8") as f:
                value = f.read().strip()
                logger.debug(f"⚙️📂✅ Successfully read file for {key}")
        except Exception as e:
            logger.error(
                f"⚙️📂❌ Failed to read file for {key}: {file_path}",
                extra={"error": str(e)},
            )
            raise ConfigError(
                message=(
                    f"Failed to read configuration file specified for '{key}'. "
                    f"Path: {file_path}"
                ),
                hint=(
                    "Ensure the file exists, is accessible, and has correct read "
                    "permissions."
                ),
            ) from e

    return _convert_value_to_schema_type(value, meta["type"], key)


def _convert_value_to_schema_type(
    value: Any, type_string: str, key_for_error: str
) -> Any:
    """
    Converts a value to the type specified by type_string.
    Raises ConfigError if conversion fails.
    """
    if value is None and type_string not in (
        "str",
        "list_str",
        "list_int",
    ):  # Allow None only if not string/list like
        # For types like bool, int, float, None should not be converted to 0 or False by default
        # unless the original value was explicitly "0" or "false" string.
        # If the schema default is None, fetch_env_variable would return None before this.
        # If a string "None" is passed, it will fail specific conversions below, which is intended.
        return None

    try:
        if type_string == "str":
            return (
                str(value) if value is not None else None
            )  # Keep None as None for strings if that's the input
        elif type_string == "int":
            return int(value)
        elif type_string == "float":
            return float(value)
        elif type_string == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ("true", "yes", "1", "on")
            return bool(value)  # General fallback, e.g., int 0 becomes False
        elif type_string == "list_str":
            if value is None:
                return []  # Default to empty list if None
            if isinstance(value, list):
                return [str(v) for v in value]
            if isinstance(value, str):
                return [v.strip() for v in value.split(",")]
            if isinstance(value, (tuple, set)):
                return [str(v) for v in value]
            return [str(value)]  # Single item to list
        elif type_string == "list_int":
            if value is None:
                return []  # Default to empty list if None
            if isinstance(value, list) and all(isinstance(x, int) for x in value):
                return value  # Already correctly typed
            if isinstance(value, list):
                return [int(v) for v in value]
            if isinstance(value, str):
                # Handle empty string for list_int as empty list
                if not value.strip():
                    return []
                return [int(v.strip()) for v in value.split(",")]
            if isinstance(value, (tuple, set)):
                return [int(v) for v in value]
            return [int(value)]  # Single item to list
        else:
            logger.warning(
                f"⚙️⚠️ Unknown type {type_string} for {key_for_error}, returning raw value"
            )
            return value
    except (ValueError, TypeError) as e:
        logger.error(
            f"⚙️❌ Type conversion failed for {key_for_error}", extra={"error": str(e)}
        )
        raise ConfigError(
            message=(
                f"Invalid value format for configuration key '{key_for_error}'. Expected "
                f"type '{type_string}', but received value '{value}'."
            ),
            hint=(
                f"Please check the value of '{key_for_error}' (currently '{value}') and "
                f"ensure it conforms to the expected type ({type_string})."
            ),
        ) from e


def validate_config_value(key: str, value: Any, meta: dict[str, Any]) -> bool:
    """
    Validates a configuration value against schema requirements.
    """
    logger.debug(f"⚙️🔍🚀 Validating config {key} = {value}")

    if meta.get("required", False) and value is None:
        logger.error(f"⚙️❌ Missing required configuration: {key}")
        raise ConfigError(
            message=(
                f"Missing required configuration key: '{key}'. "
                f"Description: {meta['description']}"
            ),
            hint=(
                f"Please provide a value for the required configuration key '{key}'. "
                "This setting is essential for the plugin's operation."
            ),
        )

    if value is None:
        return True

    if "valid_values" in meta and value not in meta["valid_values"]:
        logger.error(
            f"⚙️❌ Invalid value for {key}: {value}",
            extra={"valid_values": meta["valid_values"]},
        )
        raise ConfigError(
            message=f"Invalid value '{value}' provided for configuration key '{key}'.",
            hint=(
                f"The value '{value}' is not a valid option for '{key}'. "
                f"Allowed values are: {meta['valid_values']}. Please choose one of "
                "these."
            ),
        )

    return True


def get_config() -> dict[str, Any]:
    """
    Retrieves all configuration values from environment, applying defaults and
    validation.
    """
    config = {}
    logger.debug("⚙️🔄 Building configuration from environment and defaults")

    for key, meta in CONFIG_SCHEMA.items():
        try:
            value = fetch_env_variable(key, meta)
            validate_config_value(key, value, meta)
            config[key] = value
        except ConfigError:
            raise
        except ValueError as e:
            logger.error(
                f"⚙️❌ Unexpected ValueError for {key}", extra={"error": str(e)}
            )
            raise ConfigError(
                message=f"Unexpected validation or fetch error for {key}: {e}"
            ) from e

    logger.debug(f"⚙️✅ Configuration complete with {len(config)} values")
    return config


class RPCPluginConfig:
    """
    Configuration manager for Pyvider RPC Plugin.
    """

    _instance = None

    def __init__(self) -> None:  # Added return type hint
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
        """
        if cls._instance is None:
            cls._instance = cls()
            logger.debug("⚙️🔄 Created new RPCPluginConfig singleton instance")
        return cls._instance

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a configuration value.
        """
        value = self.config.get(key, default)
        logger.debug(f"⚙️📖 Getting config {key} = {value}")
        return value

    def get_list(self, key: str) -> list[Any]:
        """
        Retrieve a configuration value as a list.
        """
        value = self.get(key, [])
        if not isinstance(value, list):
            value = [value]
        logger.debug(f"⚙️📖 Getting list config {key} = {value}")
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value dynamically.
        """
        if key not in CONFIG_SCHEMA and not key.startswith("PLUGIN_"):
            logger.warning(f"⚙️⚠️ Setting unknown config key: {key}")
            raise ConfigError(
                message=f"Attempted to set an unknown configuration key: '{key}'.",
                hint=(
                    "Ensure the configuration key is spelled correctly. It should be "
                    "a predefined schema key or a dynamic key starting with 'PLUGIN_'."
                ),
            )

        logger.debug(f"⚙️📝 Updating config {key} -> {value}")

        meta = CONFIG_SCHEMA.get(key)
        processed_value = value
        if meta:
            try:
                processed_value = _convert_value_to_schema_type(
                    value, meta["type"], key
                )
            except ConfigError as e:
                # Re-raise with "during set" context if the original error was from conversion
                if "Invalid value format" in e.message:
                    raise ConfigError(
                        message=(
                            f"Invalid value format for configuration key '{key}' during "
                            f"set. Expected type '{meta['type']}', but received value "
                            f"'{value}'."
                        ),
                        hint=e.hint,  # Preserve original hint
                        code=e.code,  # Preserve original code
                    ) from e
                raise  # Re-raise other ConfigErrors as is
        # If not in schema (e.g. dynamic PLUGIN_ prefixed key), keep value as is.

        self.config[key] = processed_value
        logger.debug(
            f"⚙️📝 Stored processed config {key} -> {processed_value} "
            f"(type: {type(processed_value)})"
        )

    def magic_cookie_key(self) -> str:
        return cast(str, self.get("PLUGIN_MAGIC_COOKIE_KEY"))

    def magic_cookie_value(self) -> str:
        return cast(str, self.get("PLUGIN_MAGIC_COOKIE_VALUE"))

    def server_transports(self) -> list[str]:
        return cast(list[str], self.get_list("PLUGIN_SERVER_TRANSPORTS"))

    def server_endpoint(self) -> str | None:
        return cast(str | None, self.get("PLUGIN_SERVER_ENDPOINT"))

    def client_transports(self) -> list[str]:
        return cast(list[str], self.get_list("PLUGIN_CLIENT_TRANSPORTS"))

    def client_endpoint(self) -> str | None:
        return cast(str | None, self.get("PLUGIN_CLIENT_ENDPOINT"))

    def auto_mtls_enabled(self) -> bool:
        return cast(bool, self.get("PLUGIN_AUTO_MTLS"))

    def handshake_timeout(self) -> float:
        return cast(float, self.get("PLUGIN_HANDSHAKE_TIMEOUT"))

    def connection_timeout(self) -> float:
        return cast(float, self.get("PLUGIN_CONNECTION_TIMEOUT"))

    def shutdown_file_path(self) -> str | None:
        return cast(str | None, self.get("PLUGIN_SHUTDOWN_FILE_PATH"))

    def rate_limit_enabled(self) -> bool:
        return cast(bool, self.get("PLUGIN_RATE_LIMIT_ENABLED"))

    def rate_limit_requests_per_second(self) -> float:
        return cast(float, self.get("PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND"))

    def rate_limit_burst_capacity(self) -> float:
        return cast(float, self.get("PLUGIN_RATE_LIMIT_BURST_CAPACITY"))

    def health_service_enabled(self) -> bool:
        return cast(bool, self.get("PLUGIN_HEALTH_SERVICE_ENABLED"))


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
    """
    logger.debug("⚙️🔄 Running simplified configuration")

    if magic_cookie is not None:
        rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_VALUE", magic_cookie)
        logger.debug(f"⚙️📝 Set magic cookie value: {magic_cookie}")

    if protocol_version is not None:
        if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            logger.warning(
                f"⚙️⚠️ Unsupported protocol version: {protocol_version}",
                extra={"supported": SUPPORTED_PROTOCOL_VERSIONS},
            )
        rpcplugin_config.set("PLUGIN_PROTOCOL_VERSIONS", [protocol_version])
        logger.debug(f"⚙️📝 Set protocol version: {protocol_version}")

    if transports is not None:
        for transport in transports:
            if transport not in get_args(TRANSPORT_TYPES):
                logger.error(
                    f"⚙️❌ Unknown transport type: {transport}",
                    extra={"valid": get_args(TRANSPORT_TYPES)},
                )
                raise ConfigError(
                    message=f"Unknown transport type specified: '{transport}'.",
                    hint=(
                        "Valid transport types are: "
                        f"{list(get_args(TRANSPORT_TYPES))}. Please use one of these."
                    ),
                )

        rpcplugin_config.set("PLUGIN_SERVER_TRANSPORTS", transports)
        rpcplugin_config.set("PLUGIN_CLIENT_TRANSPORTS", transports)
        logger.debug(f"⚙️📝 Set transports: {transports}")

    if auto_mtls is not None:
        rpcplugin_config.set("PLUGIN_AUTO_MTLS", "true" if auto_mtls else "false")
        logger.debug(f"⚙️📝 Set auto mTLS: {auto_mtls}")

    if handshake_timeout is not None:
        rpcplugin_config.set("PLUGIN_HANDSHAKE_TIMEOUT", handshake_timeout)
        logger.debug(f"⚙️📝 Set handshake timeout: {handshake_timeout}s")

    if connection_timeout is not None:
        rpcplugin_config.set("PLUGIN_CONNECTION_TIMEOUT", connection_timeout)
        logger.debug(f"⚙️📝 Set connection timeout: {connection_timeout}s")

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

    for key, value in kwargs.items():
        config_key = f"PLUGIN_{key.upper()}"
        rpcplugin_config.set(config_key, value)
        logger.debug(f"⚙️📝 Set additional config {config_key} = {value}")

    logger.debug("⚙️✅ Configuration completed successfully")


# 🐍🏗️🔌
