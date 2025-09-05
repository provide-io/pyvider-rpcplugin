"""Configuration management for Pyvider RPC Plugin.

This module provides a Foundation-based configuration system for the Pyvider RPC Plugin framework.
Uses provide.foundation for modern async configuration loading, multi-source support, and validation.

Usage:
    # Get a configuration value
    from pyvider.rpcplugin import rpcplugin_config
    cookie_value = rpcplugin_config.get("plugin_magic_cookie_value")

    # Use helper methods
    transports = rpcplugin_config.server_transports()
    timeout = rpcplugin_config.handshake_timeout()

    # Use the simplified configuration helper
    from pyvider.rpcplugin import configure
    configure(
        magic_cookie="my-plugin-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],
        auto_mtls=True,
    )
"""

from typing import Any, Literal

from attrs import define
from provide.foundation import logger
from provide.foundation.config import (
    BaseConfig,
    EnvConfig,
    field,
    validate_choice,
    validate_non_negative,
    validate_positive,
    validate_range,
)
from provide.foundation.errors.config import ValidationError

from .exception import ConfigError

# Define supported protocol versions
SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]

# Define supported transport types
TRANSPORT_TYPES = Literal["unix", "tcp"]


# RPC-specific validators
def validate_transport_list(instance, attribute, value):
    """
    Validate transport list for RPC plugin.
    
    Valid combinations: ["unix"], ["tcp"], ["unix", "tcp"], ["tcp", "unix"]
    """
    valid_transports = {"unix", "tcp"}
    valid_combinations = [
        ["unix"], 
        ["tcp"], 
        ["unix", "tcp"], 
        ["tcp", "unix"]
    ]
    
    if not isinstance(value, list):
        raise ValidationError(
            f"Transport list must be a list, got {type(value).__name__}"
        )
    
    # Check individual transports are valid
    for transport in value:
        if transport not in valid_transports:
            raise ValidationError(
                f"Invalid transport '{transport}'. Must be one of: {valid_transports}"
            )
    
    # Check combination is valid
    if value not in valid_combinations:
        raise ValidationError(
            f"Invalid transport combination {value}. "
            f"Must be one of: {valid_combinations}"
        )


def validate_protocol_version_list(instance, attribute, value):
    """
    Validate protocol version list for RPC plugin.
    
    Each version must be an integer between 1 and 7 (inclusive).
    """
    if not isinstance(value, list):
        raise ValidationError(
            f"Protocol version list must be a list, got {type(value).__name__}"
        )
    
    for version in value:
        if not isinstance(version, int):
            raise ValidationError(
                f"Protocol version must be an integer, got {type(version).__name__} for {version}"
            )
        
        if not (1 <= version <= 7):
            raise ValidationError(
                f"Protocol version must be between 1 and 7, got {version}"
            )


@define(slots=True, repr=False)
class RPCPluginConfig(EnvConfig):
    """
    Foundation-based configuration for Pyvider RPC Plugin.
    
    Uses provide.foundation config system with full async support,
    multi-source loading, and comprehensive validation.
    """
    
    # Supported protocol versions (reference)
    supported_protocol_versions: list[int] = field(
        factory=lambda: [1, 2, 3, 4, 5, 6, 7],
        description="List of supported protocol versions",
        env_var="SUPPORTED_PROTOCOL_VERSIONS",
    )
    
    # Core configuration
    plugin_core_version: int = field(
        default=1,
        validator=validate_range(1, 7),
        description="Core protocol version to use",
        env_var="PLUGIN_CORE_VERSION",
    )
    
    plugin_log_level: str = field(
        default="INFO",
        validator=validate_choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
        description="Logging level for the plugin",
        env_var="PLUGIN_LOG_LEVEL",
    )
    
    # Magic cookie configuration
    plugin_magic_cookie_key: str = field(
        default="PLUGIN_MAGIC_COOKIE",
        description="Environment variable name for the magic cookie value",
        env_var="PLUGIN_MAGIC_COOKIE_KEY",
    )
    
    plugin_magic_cookie_value: str = field(
        default="test_cookie_value",
        description="Magic cookie value for plugin authentication",
        env_var="PLUGIN_MAGIC_COOKIE_VALUE",
        sensitive=True,
    )
    
    # Protocol configuration
    plugin_protocol_versions: list[int] = field(
        factory=lambda: [1],
        validator=validate_protocol_version_list,
        description="List of protocol versions supported by this plugin",
        env_var="PLUGIN_PROTOCOL_VERSIONS",
    )
    
    # Server configuration
    plugin_server_transports: list[str] = field(
        factory=lambda: ["unix", "tcp"],
        validator=validate_transport_list,
        description="List of transports supported by the server",
        env_var="PLUGIN_SERVER_TRANSPORTS",
    )
    
    plugin_server_endpoint: str | None = field(
        default=None,
        description="Server endpoint for connection",
        env_var="PLUGIN_SERVER_ENDPOINT",
    )
    
    # mTLS Server configuration
    plugin_auto_mtls: bool = field(
        default=True,
        description="Enable automatic mutual TLS",
        env_var="PLUGIN_AUTO_MTLS",
    )
    
    plugin_server_cert: str | None = field(
        default=None,
        description="Server certificate (PEM format or file:// path)",
        env_var="PLUGIN_SERVER_CERT",
        sensitive=True,
    )
    
    plugin_server_key: str | None = field(
        default=None,
        description="Server private key (PEM format or file:// path)",
        env_var="PLUGIN_SERVER_KEY",
        sensitive=True,
    )
    
    plugin_server_root_certs: str | None = field(
        default=None,
        description="Server root certificates (PEM format or file:// path)",
        env_var="PLUGIN_SERVER_ROOT_CERTS",
        sensitive=True,
    )
    
    # Client configuration
    plugin_client_transports: list[str] = field(
        factory=lambda: ["unix", "tcp"],
        validator=validate_transport_list,
        description="List of transports supported by the client",
        env_var="PLUGIN_CLIENT_TRANSPORTS",
    )
    
    plugin_client_endpoint: str | None = field(
        default=None,
        description="Client endpoint for connection",
        env_var="PLUGIN_CLIENT_ENDPOINT",
    )
    
    plugin_client_cert: str | None = field(
        default=None,
        description="Client certificate (PEM format or file:// path)",
        env_var="PLUGIN_CLIENT_CERT",
        sensitive=True,
    )
    
    plugin_client_key: str | None = field(
        default=None,
        description="Client private key (PEM format or file:// path)",
        env_var="PLUGIN_CLIENT_KEY",
        sensitive=True,
    )
    
    plugin_client_root_certs: str | None = field(
        default=None,
        description="Client root certificates (PEM format or file:// path)",
        env_var="PLUGIN_CLIENT_ROOT_CERTS",
        sensitive=True,
    )
    
    # Timeout configuration
    plugin_handshake_timeout: float = field(
        default=10.0,
        validator=validate_range(0.1, 300.0),
        description="Timeout for plugin handshake in seconds",
        env_var="PLUGIN_HANDSHAKE_TIMEOUT",
    )
    
    plugin_connection_timeout: float = field(
        default=30.0,
        validator=validate_range(0.1, 3600.0),
        description="Timeout for connection establishment in seconds",
        env_var="PLUGIN_CONNECTION_TIMEOUT",
    )
    
    # UI configuration
    plugin_show_emoji_matrix: bool = field(
        default=True,
        description="Show emoji matrix in logs",
        env_var="PLUGIN_SHOW_EMOJI_MATRIX",
    )
    
    # Retry configuration
    plugin_client_retry_enabled: bool = field(
        default=True,
        description="Enable client retry mechanism",
        env_var="PLUGIN_CLIENT_RETRY_ENABLED",
    )
    
    plugin_client_max_retries: int = field(
        default=3,
        validator=validate_non_negative,
        description="Maximum number of retry attempts",
        env_var="PLUGIN_CLIENT_MAX_RETRIES",
    )
    
    plugin_client_initial_backoff_ms: int = field(
        default=500,
        validator=validate_positive,
        description="Initial backoff time in milliseconds",
        env_var="PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
    )
    
    plugin_client_max_backoff_ms: int = field(
        default=5000,
        validator=validate_positive,
        description="Maximum backoff time in milliseconds",
        env_var="PLUGIN_CLIENT_MAX_BACKOFF_MS",
    )
    
    plugin_client_retry_jitter_ms: int = field(
        default=100,
        validator=validate_non_negative,
        description="Retry jitter in milliseconds",
        env_var="PLUGIN_CLIENT_RETRY_JITTER_MS",
    )
    
    plugin_client_retry_total_timeout_s: int = field(
        default=60,
        validator=validate_positive,
        description="Total retry timeout in seconds",
        env_var="PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S",
    )
    
    # Shutdown configuration
    plugin_shutdown_file_path: str | None = field(
        default=None,
        description="Path to shutdown signal file",
        env_var="PLUGIN_SHUTDOWN_FILE_PATH",
    )
    
    # Rate limiting configuration
    plugin_rate_limit_enabled: bool = field(
        default=False,
        description="Enable rate limiting",
        env_var="PLUGIN_RATE_LIMIT_ENABLED",
    )
    
    plugin_rate_limit_requests_per_second: float = field(
        default=100.0,
        validator=validate_positive,
        description="Rate limit in requests per second",
        env_var="PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND",
    )
    
    plugin_rate_limit_burst_capacity: float = field(
        default=200.0,
        validator=validate_positive,
        description="Rate limit burst capacity",
        env_var="PLUGIN_RATE_LIMIT_BURST_CAPACITY",
    )
    
    # Health service configuration
    plugin_health_service_enabled: bool = field(
        default=True,
        description="Enable health service",
        env_var="PLUGIN_HEALTH_SERVICE_ENABLED",
    )
    
    # Compatibility API methods
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key name.
        
        Supports both old SCHEMA keys and new field names.
        """
        # Handle old schema key names for backward compatibility during transition
        key_mapping = {
            "SUPPORTED_PROTOCOL_VERSIONS": "supported_protocol_versions",
            "PLUGIN_CORE_VERSION": "plugin_core_version",
            "PLUGIN_LOG_LEVEL": "plugin_log_level",
            "PLUGIN_MAGIC_COOKIE_KEY": "plugin_magic_cookie_key",
            "PLUGIN_MAGIC_COOKIE_VALUE": "plugin_magic_cookie_value",
            "PLUGIN_PROTOCOL_VERSIONS": "plugin_protocol_versions",
            "PLUGIN_SERVER_TRANSPORTS": "plugin_server_transports",
            "PLUGIN_SERVER_ENDPOINT": "plugin_server_endpoint",
            "PLUGIN_AUTO_MTLS": "plugin_auto_mtls",
            "PLUGIN_SERVER_CERT": "plugin_server_cert",
            "PLUGIN_SERVER_KEY": "plugin_server_key",
            "PLUGIN_SERVER_ROOT_CERTS": "plugin_server_root_certs",
            "PLUGIN_CLIENT_TRANSPORTS": "plugin_client_transports",
            "PLUGIN_CLIENT_ENDPOINT": "plugin_client_endpoint",
            "PLUGIN_CLIENT_CERT": "plugin_client_cert",
            "PLUGIN_CLIENT_KEY": "plugin_client_key",
            "PLUGIN_CLIENT_ROOT_CERTS": "plugin_client_root_certs",
            "PLUGIN_HANDSHAKE_TIMEOUT": "plugin_handshake_timeout",
            "PLUGIN_CONNECTION_TIMEOUT": "plugin_connection_timeout",
            "PLUGIN_SHOW_EMOJI_MATRIX": "plugin_show_emoji_matrix",
            "PLUGIN_CLIENT_RETRY_ENABLED": "plugin_client_retry_enabled",
            "PLUGIN_CLIENT_MAX_RETRIES": "plugin_client_max_retries",
            "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": "plugin_client_initial_backoff_ms",
            "PLUGIN_CLIENT_MAX_BACKOFF_MS": "plugin_client_max_backoff_ms",
            "PLUGIN_CLIENT_RETRY_JITTER_MS": "plugin_client_retry_jitter_ms",
            "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "plugin_client_retry_total_timeout_s",
            "PLUGIN_SHUTDOWN_FILE_PATH": "plugin_shutdown_file_path",
            "PLUGIN_RATE_LIMIT_ENABLED": "plugin_rate_limit_enabled",
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "plugin_rate_limit_requests_per_second",
            "PLUGIN_RATE_LIMIT_BURST_CAPACITY": "plugin_rate_limit_burst_capacity",
            "PLUGIN_HEALTH_SERVICE_ENABLED": "plugin_health_service_enabled",
        }
        
        field_name = key_mapping.get(key, key.lower())
        
        try:
            value = getattr(self, field_name, default)
            logger.debug(f"⚙️📖 Getting config {key} -> {field_name} = {value}")
            return value
        except AttributeError:
            logger.debug(f"⚙️📖 Getting config {key} = {default} (not found)")
            return default

    def get_list(self, key: str) -> list[Any]:
        """Get a configuration value as a list."""
        value = self.get(key, [])
        if not isinstance(value, list):
            value = [value]
        logger.debug(f"⚙️📖 Getting list config {key} = {value}")
        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value dynamically.
        
        Note: This updates the runtime instance. For persistent changes,
        update environment variables or configuration files.
        """
        # Map old keys to new field names
        key_mapping = {
            "SUPPORTED_PROTOCOL_VERSIONS": "supported_protocol_versions",
            "PLUGIN_CORE_VERSION": "plugin_core_version",
            "PLUGIN_LOG_LEVEL": "plugin_log_level",
            "PLUGIN_MAGIC_COOKIE_KEY": "plugin_magic_cookie_key",
            "PLUGIN_MAGIC_COOKIE_VALUE": "plugin_magic_cookie_value",
            "PLUGIN_PROTOCOL_VERSIONS": "plugin_protocol_versions",
            "PLUGIN_SERVER_TRANSPORTS": "plugin_server_transports",
            "PLUGIN_SERVER_ENDPOINT": "plugin_server_endpoint",
            "PLUGIN_AUTO_MTLS": "plugin_auto_mtls",
            "PLUGIN_SERVER_CERT": "plugin_server_cert",
            "PLUGIN_SERVER_KEY": "plugin_server_key",
            "PLUGIN_SERVER_ROOT_CERTS": "plugin_server_root_certs",
            "PLUGIN_CLIENT_TRANSPORTS": "plugin_client_transports",
            "PLUGIN_CLIENT_ENDPOINT": "plugin_client_endpoint",
            "PLUGIN_CLIENT_CERT": "plugin_client_cert",
            "PLUGIN_CLIENT_KEY": "plugin_client_key",
            "PLUGIN_CLIENT_ROOT_CERTS": "plugin_client_root_certs",
            "PLUGIN_HANDSHAKE_TIMEOUT": "plugin_handshake_timeout",
            "PLUGIN_CONNECTION_TIMEOUT": "plugin_connection_timeout",
            "PLUGIN_SHOW_EMOJI_MATRIX": "plugin_show_emoji_matrix",
            "PLUGIN_CLIENT_RETRY_ENABLED": "plugin_client_retry_enabled",
            "PLUGIN_CLIENT_MAX_RETRIES": "plugin_client_max_retries",
            "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": "plugin_client_initial_backoff_ms",
            "PLUGIN_CLIENT_MAX_BACKOFF_MS": "plugin_client_max_backoff_ms",
            "PLUGIN_CLIENT_RETRY_JITTER_MS": "plugin_client_retry_jitter_ms",
            "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "plugin_client_retry_total_timeout_s",
            "PLUGIN_SHUTDOWN_FILE_PATH": "plugin_shutdown_file_path",
            "PLUGIN_RATE_LIMIT_ENABLED": "plugin_rate_limit_enabled",
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "plugin_rate_limit_requests_per_second",
            "PLUGIN_RATE_LIMIT_BURST_CAPACITY": "plugin_rate_limit_burst_capacity",
            "PLUGIN_HEALTH_SERVICE_ENABLED": "plugin_health_service_enabled",
        }
        
        field_name = key_mapping.get(key, key.lower())
        
        if not hasattr(self, field_name) and not key.startswith("PLUGIN_"):
            logger.warning(f"⚙️⚠️ Setting unknown config key: {key}")
            raise ConfigError(
                message=f"Attempted to set an unknown configuration key: '{key}'.",
                hint=(
                    "Ensure the configuration key is spelled correctly. It should be "
                    "a predefined field or a dynamic key starting with 'PLUGIN_'."
                ),
            )
        
        try:
            setattr(self, field_name, value)
            logger.debug(f"⚙️📝 Setting config {key} -> {field_name} = {value}")
        except Exception as e:
            logger.error(f"⚙️❌ Failed to set config {key}: {e}")
            raise ConfigError(
                message=f"Failed to set configuration key '{key}' to value '{value}': {e}",
                hint="Check that the value is valid for this configuration field."
            ) from e
    
    # Helper methods for common configuration access patterns
    def magic_cookie_key(self) -> str:
        """Get the magic cookie key."""
        return self.plugin_magic_cookie_key
    
    def magic_cookie_value(self) -> str:
        """Get the magic cookie value."""
        return self.plugin_magic_cookie_value
    
    def server_transports(self) -> list[str]:
        """Get server transport list."""
        return self.plugin_server_transports
    
    def client_transports(self) -> list[str]:
        """Get client transport list."""
        return self.plugin_client_transports
    
    def protocol_versions(self) -> list[int]:
        """Get supported protocol versions."""
        return self.plugin_protocol_versions
    
    def handshake_timeout(self) -> float:
        """Get handshake timeout."""
        return self.plugin_handshake_timeout
    
    def connection_timeout(self) -> float:
        """Get connection timeout."""
        return self.plugin_connection_timeout
    
    async def validate(self) -> None:
        """
        Custom validation logic.
        """
        await super().validate()
        
        # Validate backoff configuration consistency
        if self.plugin_client_initial_backoff_ms > self.plugin_client_max_backoff_ms:
            raise ValidationError(
                f"Initial backoff ({self.plugin_client_initial_backoff_ms}ms) cannot be "
                f"greater than max backoff ({self.plugin_client_max_backoff_ms}ms)"
            )


# Singleton instance
_rpcplugin_config: RPCPluginConfig | None = None


def get_rpcplugin_config() -> RPCPluginConfig:
    """Get or create the singleton RPCPluginConfig instance."""
    global _rpcplugin_config
    
    if _rpcplugin_config is None:
        try:
            _rpcplugin_config = RPCPluginConfig.from_env()
            logger.debug("⚙️✅ RPCPluginConfig initialized from environment variables")
            logger.debug("⚙️🔄 Created new RPCPluginConfig singleton instance")
        except Exception as e:
            logger.error(
                "⚙️❌ Error initializing RPCPluginConfig", extra={"error": str(e)}
            )
            raise ConfigError(
                message=f"Failed to initialize RPC plugin configuration: {e}",
                hint="Check environment variables and configuration values."
            ) from e
    
    return _rpcplugin_config


# Global singleton instance (for backward compatibility)
rpcplugin_config = get_rpcplugin_config()


def configure(
    magic_cookie: str | None = None,
    protocol_version: int | None = None,
    transports: list[str] | None = None,
    auto_mtls: bool | None = None,
    **kwargs: Any,
) -> None:
    """
    Simplified configuration helper.
    
    Args:
        magic_cookie: Magic cookie value for plugin authentication
        protocol_version: Protocol version to use
        transports: List of supported transports
        auto_mtls: Enable automatic mutual TLS
        **kwargs: Additional configuration parameters
    """
    global rpcplugin_config
    
    try:
        if magic_cookie is not None:
            rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_VALUE", magic_cookie)
        
        if protocol_version is not None:
            rpcplugin_config.set("PLUGIN_CORE_VERSION", protocol_version)
            rpcplugin_config.set("PLUGIN_PROTOCOL_VERSIONS", [protocol_version])
        
        if transports is not None:
            rpcplugin_config.set("PLUGIN_SERVER_TRANSPORTS", transports)
            rpcplugin_config.set("PLUGIN_CLIENT_TRANSPORTS", transports)
        
        if auto_mtls is not None:
            rpcplugin_config.set("PLUGIN_AUTO_MTLS", auto_mtls)
        
        # Handle additional kwargs
        for key, value in kwargs.items():
            # Convert snake_case to PLUGIN_* format
            env_key = f"PLUGIN_{key.upper()}"
            rpcplugin_config.set(env_key, value)
            
        logger.debug("⚙️✅ Configuration applied successfully")
        
    except Exception as e:
        logger.error(f"⚙️❌ Configuration failed: {e}")
        raise ConfigError(
            message=f"Failed to apply configuration: {e}",
            hint="Check the provided configuration values."
        ) from e


# Legacy exports for compatibility during transition
CONFIG_SCHEMA = {}  # Empty - now using attrs fields instead
SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]


# Legacy function stubs for test compatibility
def fetch_env_variable(key: str, meta: dict[str, Any]) -> Any:
    """Legacy function - use rpcplugin_config.get() instead."""
    default = meta.get("default")
    return rpcplugin_config.get(key, default)


def validate_config_value(key: str, value: Any, meta: dict[str, Any]) -> bool:
    """Legacy function - validation now handled by attrs validators."""
    # In the new system, validation happens automatically
    # This is just a stub for test compatibility
    return True


def get_config() -> dict[str, Any]:
    """Legacy function - use rpcplugin_config directly instead."""
    # Return a dict representation of the config for compatibility
    config_dict = rpcplugin_config.to_dict(include_sensitive=True)
    # Map new field names back to old schema keys for compatibility
    legacy_dict = {}
    
    field_to_key_mapping = {
        "supported_protocol_versions": "SUPPORTED_PROTOCOL_VERSIONS",
        "plugin_core_version": "PLUGIN_CORE_VERSION", 
        "plugin_log_level": "PLUGIN_LOG_LEVEL",
        "plugin_magic_cookie_key": "PLUGIN_MAGIC_COOKIE_KEY",
        "plugin_magic_cookie_value": "PLUGIN_MAGIC_COOKIE_VALUE",
        "plugin_protocol_versions": "PLUGIN_PROTOCOL_VERSIONS",
        "plugin_server_transports": "PLUGIN_SERVER_TRANSPORTS",
        "plugin_server_endpoint": "PLUGIN_SERVER_ENDPOINT",
        "plugin_auto_mtls": "PLUGIN_AUTO_MTLS",
        "plugin_server_cert": "PLUGIN_SERVER_CERT",
        "plugin_server_key": "PLUGIN_SERVER_KEY",
        "plugin_server_root_certs": "PLUGIN_SERVER_ROOT_CERTS",
        "plugin_client_transports": "PLUGIN_CLIENT_TRANSPORTS",
        "plugin_client_endpoint": "PLUGIN_CLIENT_ENDPOINT",
        "plugin_client_cert": "PLUGIN_CLIENT_CERT",
        "plugin_client_key": "PLUGIN_CLIENT_KEY",
        "plugin_client_root_certs": "PLUGIN_CLIENT_ROOT_CERTS",
        "plugin_handshake_timeout": "PLUGIN_HANDSHAKE_TIMEOUT",
        "plugin_connection_timeout": "PLUGIN_CONNECTION_TIMEOUT",
        "plugin_show_emoji_matrix": "PLUGIN_SHOW_EMOJI_MATRIX",
        "plugin_client_retry_enabled": "PLUGIN_CLIENT_RETRY_ENABLED",
        "plugin_client_max_retries": "PLUGIN_CLIENT_MAX_RETRIES",
        "plugin_client_initial_backoff_ms": "PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
        "plugin_client_max_backoff_ms": "PLUGIN_CLIENT_MAX_BACKOFF_MS",
        "plugin_client_retry_jitter_ms": "PLUGIN_CLIENT_RETRY_JITTER_MS",
        "plugin_client_retry_total_timeout_s": "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S",
        "plugin_shutdown_file_path": "PLUGIN_SHUTDOWN_FILE_PATH",
        "plugin_rate_limit_enabled": "PLUGIN_RATE_LIMIT_ENABLED",
        "plugin_rate_limit_requests_per_second": "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND",
        "plugin_rate_limit_burst_capacity": "PLUGIN_RATE_LIMIT_BURST_CAPACITY",
        "plugin_health_service_enabled": "PLUGIN_HEALTH_SERVICE_ENABLED",
    }
    
    for field_name, legacy_key in field_to_key_mapping.items():
        if field_name in config_dict:
            legacy_dict[legacy_key] = config_dict[field_name]
    
    return legacy_dict


def _convert_value_to_schema_type(value: Any, type_string: str, key_for_error: str) -> Any:
    """Legacy function - type conversion now handled by Foundation."""
    # Foundation handles type conversion automatically through parsing utilities
    # This is just a stub for compatibility
    if type_string == "str":
        return str(value) if value is not None else None
    elif type_string == "int":
        return int(value)
    elif type_string == "float":
        return float(value)
    elif type_string == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "on")
        return bool(value)
    elif type_string == "list_str":
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return [v.strip() for v in value.split(",")]
        return [str(value)]
    elif type_string == "list_int":
        if value is None:
            return []
        if isinstance(value, list):
            return [int(v) for v in value]
        if isinstance(value, str):
            if not value.strip():
                return []
            return [int(v.strip()) for v in value.split(",")]
        return [int(value)]
    
    return value