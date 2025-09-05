"""
Foundation-based configuration for Pyvider RPC Plugin.

This module provides a modern configuration system using provide.foundation
while maintaining backward compatibility with the existing API.
"""

from typing import Any

from attrs import define
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
class RPCPluginFoundationConfig(EnvConfig):
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