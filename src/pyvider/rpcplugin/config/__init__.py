"""Configuration management for Pyvider RPC Plugin.

This module provides a Foundation-based configuration system for the Pyvider RPC Plugin framework.
Uses provide.foundation for modern async configuration loading, multi-source support, and validation.

Usage:
    # Get a configuration value
    from pyvider.rpcplugin.config import rpcplugin_config
    cookie_value = rpcplugin_config.plugin_magic_cookie_value

    # Use helper methods
    transports = rpcplugin_config.server_transports()
    timeout = rpcplugin_config.handshake_timeout()

    # Use the simplified configuration helper
    from pyvider.rpcplugin.config import configure
    configure(
        magic_cookie="my-plugin-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],
        auto_mtls=True,
    )
"""

from typing import Any

from attrs import define
from provide.foundation import logger
from provide.foundation.config import (
    RuntimeConfig,
    field,
    validate_choice,
    validate_non_negative,
    validate_positive,
    validate_range,
)
from provide.foundation.errors.config import ValidationError

from pyvider.rpcplugin.defaults import (
    DEFAULT_CLIENT_TRANSPORTS,
    DEFAULT_PLUGIN_PROTOCOL_VERSIONS,
    DEFAULT_SERVER_TRANSPORTS,
    DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
)
from pyvider.rpcplugin.exception import ConfigError


def _validate_protocol_versions_list(value: list[int]) -> list[int]:
    """Validate that all protocol versions in the list are supported."""
    for version in value:
        if version not in DEFAULT_SUPPORTED_PROTOCOL_VERSIONS:
            raise ValidationError(f"Protocol version must be between 1 and 7, got {version}")
    return value


def _validate_transports_list(value: list[str]) -> list[str]:
    """Validate that all transports in the list are supported."""
    valid_transports = ["unix", "tcp"]
    for transport in value:
        if transport not in valid_transports:
            raise ValidationError(f"Invalid transport '{transport}'. Must be one of: {valid_transports}")
    return value


@define
class RPCPluginConfig(RuntimeConfig):
    """
    Unified configuration for the RPC plugin system.

    This class provides all configuration settings organized by functional area:
    - Core settings (protocol versions, magic cookies)
    - Transport settings (timeouts, buffer sizes, supported transports)
    - Security settings (mTLS, certificates)
    - gRPC settings (keepalive, grace periods)
    - Client settings (retry logic)
    - Server settings (host, port, paths)
    - Feature settings (rate limiting, health checks, UI)
    """

    # =====================================================
    # Core Configuration
    # =====================================================

    plugin_core_version: int = field(
        default=1,
        validator=validate_choice(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS),
        description="Core protocol version supported by this plugin",
        env_var="PLUGIN_CORE_VERSION",
    )

    plugin_protocol_versions: list[int] = field(  # noqa: RUF009
        factory=lambda: DEFAULT_PLUGIN_PROTOCOL_VERSIONS.copy(),
        converter=_validate_protocol_versions_list,
        description="List of protocol versions this plugin supports",
        env_var="PLUGIN_PROTOCOL_VERSIONS",
    )

    plugin_protocol_version: int = field(
        default=1,
        validator=validate_choice(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS),
        description="Preferred protocol version for communication",
        env_var="PLUGIN_PROTOCOL_VERSION",
    )

    supported_protocol_versions: list[int] = field(  # noqa: RUF009
        factory=lambda: DEFAULT_SUPPORTED_PROTOCOL_VERSIONS.copy(),
        description="List of supported protocol versions (reference)",
        env_var="SUPPORTED_PROTOCOL_VERSIONS",
    )

    plugin_magic_cookie_key: str = field(
        default="PLUGIN_MAGIC_COOKIE",
        description="Environment variable name for the magic cookie",
        env_var="PLUGIN_MAGIC_COOKIE_KEY",
    )

    plugin_magic_cookie_value: str = field(
        default="test_cookie_value",
        description="Magic cookie value for handshake authentication",
        env_var="PLUGIN_MAGIC_COOKIE_VALUE",
        sensitive=True,
    )

    plugin_log_level: str = field(
        default="INFO",
        validator=validate_choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
        description="Logging level for the plugin",
        env_var="PLUGIN_LOG_LEVEL",
    )

    # =====================================================
    # Transport Configuration
    # =====================================================

    plugin_server_transports: list[str] = field(  # noqa: RUF009
        factory=lambda: DEFAULT_SERVER_TRANSPORTS.copy(),
        converter=_validate_transports_list,
        description="List of transports supported by the server",
        env_var="PLUGIN_SERVER_TRANSPORTS",
    )

    plugin_client_transports: list[str] = field(  # noqa: RUF009
        factory=lambda: DEFAULT_CLIENT_TRANSPORTS.copy(),
        converter=_validate_transports_list,
        description="List of transports supported by the client",
        env_var="PLUGIN_CLIENT_TRANSPORTS",
    )

    plugin_handshake_timeout: float = field(
        default=10.0,
        validator=validate_positive,
        description="Timeout for handshake operations in seconds",
        env_var="PLUGIN_HANDSHAKE_TIMEOUT",
    )

    plugin_connection_timeout: float = field(
        default=30.0,
        validator=validate_positive,
        description="Timeout for connection establishment in seconds",
        env_var="PLUGIN_CONNECTION_TIMEOUT",
    )

    plugin_channel_ready_timeout: float = field(
        default=5.0,
        validator=validate_positive,
        description="Timeout for gRPC channel to become ready in seconds",
        env_var="PLUGIN_CHANNEL_READY_TIMEOUT",
    )

    plugin_server_ready_timeout: float = field(
        default=5.0,
        validator=validate_positive,
        description="Timeout for server to become ready in seconds",
        env_var="PLUGIN_SERVER_READY_TIMEOUT",
    )

    plugin_buffer_size: int = field(
        default=16384,
        validator=validate_positive,
        description="Default buffer size for data operations in bytes",
        env_var="PLUGIN_BUFFER_SIZE",
    )

    plugin_chunk_size: int = field(
        default=8192,
        validator=validate_positive,
        description="Default chunk size for streaming in bytes",
        env_var="PLUGIN_CHUNK_SIZE",
    )

    # =====================================================
    # Security Configuration
    # =====================================================

    plugin_auto_mtls: bool = field(
        default=True,
        description="Enable automatic mutual TLS certificate generation",
        env_var="PLUGIN_AUTO_MTLS",
    )

    plugin_insecure: bool = field(
        default=False,
        description="Allow insecure connections (disable TLS)",
        env_var="PLUGIN_INSECURE",
    )

    plugin_cert_validity_days: int = field(
        default=365,
        validator=validate_positive,
        description="Certificate validity period in days",
        env_var="PLUGIN_CERT_VALIDITY_DAYS",
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
        description="Client root certificates for mTLS validation",
        env_var="PLUGIN_CLIENT_ROOT_CERTS",
        sensitive=True,
    )

    plugin_ca_cert: str | None = field(
        default=None,
        description="Certificate Authority certificate (PEM format or file:// path)",
        env_var="PLUGIN_CA_CERT",
        sensitive=True,
    )

    # =====================================================
    # gRPC Configuration
    # =====================================================

    plugin_grpc_keepalive_time_ms: int = field(
        default=30000,
        validator=validate_positive,
        description="gRPC keepalive time in milliseconds",
        env_var="PLUGIN_GRPC_KEEPALIVE_TIME_MS",
    )

    plugin_grpc_keepalive_timeout_ms: int = field(
        default=5000,
        validator=validate_positive,
        description="gRPC keepalive timeout in milliseconds",
        env_var="PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS",
    )

    plugin_grpc_grace_period: float = field(
        default=5.0,
        validator=validate_positive,
        description="gRPC channel close grace period in seconds",
        env_var="PLUGIN_GRPC_GRACE_PERIOD",
    )

    # =====================================================
    # Client Configuration
    # =====================================================

    plugin_client_retry_enabled: bool = field(
        default=True,
        description="Enable client retry logic",
        env_var="PLUGIN_CLIENT_RETRY_ENABLED",
    )

    plugin_client_max_retries: int = field(
        default=3,
        validator=validate_non_negative,
        description="Maximum number of client retries",
        env_var="PLUGIN_CLIENT_MAX_RETRIES",
    )

    plugin_client_initial_backoff_ms: int = field(
        default=100,
        validator=validate_positive,
        description="Initial backoff delay in milliseconds",
        env_var="PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
    )

    plugin_client_max_backoff_ms: int = field(
        default=5000,
        validator=validate_positive,
        description="Maximum backoff delay in milliseconds",
        env_var="PLUGIN_CLIENT_MAX_BACKOFF_MS",
    )

    plugin_client_retry_jitter_ms: int = field(
        default=50,
        validator=validate_non_negative,
        description="Retry jitter in milliseconds",
        env_var="PLUGIN_CLIENT_RETRY_JITTER_MS",
    )

    plugin_client_retry_total_timeout_s: float = field(
        default=30.0,
        validator=validate_positive,
        description="Total retry timeout in seconds",
        env_var="PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S",
    )

    plugin_client_endpoint: str | None = field(
        default=None,
        description="Client endpoint for connection",
        env_var="PLUGIN_CLIENT_ENDPOINT",
    )

    # =====================================================
    # Server Configuration
    # =====================================================

    plugin_server_host: str = field(
        default="localhost",
        description="Server host address",
        env_var="PLUGIN_SERVER_HOST",
    )

    plugin_server_port: int = field(
        default=0,
        validator=validate_range(0, 65535),
        description="Server port (0 for auto-assign)",
        env_var="PLUGIN_SERVER_PORT",
    )

    plugin_server_endpoint: str | None = field(
        default=None,
        description="Server endpoint for connection",
        env_var="PLUGIN_SERVER_ENDPOINT",
    )

    plugin_unix_socket_path: str = field(
        default="/tmp/plugin.sock",
        description="Unix socket path for local connections",
        env_var="PLUGIN_UNIX_SOCKET_PATH",
    )

    plugin_shutdown_file_path: str | None = field(
        default=None,
        description="Path to shutdown signal file",
        env_var="PLUGIN_SHUTDOWN_FILE_PATH",
    )

    # =====================================================
    # Feature Configuration
    # =====================================================

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

    plugin_health_service_enabled: bool = field(
        default=True,
        description="Enable health service",
        env_var="PLUGIN_HEALTH_SERVICE_ENABLED",
    )

    plugin_show_emoji_matrix: bool = field(
        default=False,
        description="Show emoji matrix in UI",
        env_var="PLUGIN_SHOW_EMOJI_MATRIX",
    )

    # =====================================================
    # Helper Methods
    # =====================================================

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

    def handshake_timeout(self) -> float:
        """Get handshake timeout."""
        return self.plugin_handshake_timeout

    def connection_timeout(self) -> float:
        """Get connection timeout."""
        return self.plugin_connection_timeout

    def channel_ready_timeout(self) -> float:
        """Get gRPC channel ready timeout."""
        return self.plugin_channel_ready_timeout

    def server_ready_timeout(self) -> float:
        """Get server ready timeout."""
        return self.plugin_server_ready_timeout

    def buffer_size(self) -> int:
        """Get default buffer size for data operations in bytes."""
        return self.plugin_buffer_size

    def chunk_size(self) -> int:
        """Get default chunk size for streaming in bytes."""
        return self.plugin_chunk_size

    def grpc_keepalive_time_ms(self) -> int:
        """Get gRPC keepalive time in milliseconds."""
        return self.plugin_grpc_keepalive_time_ms

    def grpc_keepalive_timeout_ms(self) -> int:
        """Get gRPC keepalive timeout in milliseconds."""
        return self.plugin_grpc_keepalive_timeout_ms

    def grpc_grace_period(self) -> float:
        """Get gRPC channel close grace period in seconds."""
        return self.plugin_grpc_grace_period

    def auto_mtls_enabled(self) -> bool:
        """Get auto mTLS enabled flag."""
        return self.plugin_auto_mtls

    def cert_validity_days(self) -> int:
        """Get certificate validity period in days."""
        return self.plugin_cert_validity_days

    def rate_limit_enabled(self) -> bool:
        """Get rate limit enabled flag."""
        return self.plugin_rate_limit_enabled

    def rate_limit_requests_per_second(self) -> float:
        """Get rate limit requests per second."""
        return self.plugin_rate_limit_requests_per_second

    def rate_limit_burst_capacity(self) -> float:
        """Get rate limit burst capacity."""
        return self.plugin_rate_limit_burst_capacity

    def health_service_enabled(self) -> bool:
        """Get health service enabled flag."""
        return self.plugin_health_service_enabled

    # =====================================================
    # Backward Compatibility Properties
    # =====================================================

    def protocol_versions(self) -> list[int]:
        """Alias for plugin_protocol_versions for backward compatibility."""
        return self.plugin_protocol_versions


# Create the global configuration instance
rpcplugin_config = RPCPluginConfig()


def configure(
    magic_cookie: str | None = None,
    protocol_version: int | None = None,
    transports: list[str] | None = None,
    auto_mtls: bool | None = None,
    handshake_timeout: float | None = None,
    **kwargs: Any,
) -> None:
    """
    Configure the RPC plugin system with common settings.

    This is a convenience function for setting up the most commonly
    used configuration options.

    Args:
        magic_cookie: Magic cookie value for handshake authentication
        protocol_version: Preferred protocol version
        transports: List of supported transports
        auto_mtls: Enable automatic mTLS certificate generation
        handshake_timeout: Timeout for handshake operations in seconds
        **kwargs: Additional configuration parameters
    """
    try:
        if magic_cookie is not None:
            rpcplugin_config.plugin_magic_cookie_value = magic_cookie

        if protocol_version is not None:
            rpcplugin_config.plugin_core_version = protocol_version
            rpcplugin_config.plugin_protocol_versions = [protocol_version]

        if transports is not None:
            rpcplugin_config.plugin_server_transports = transports
            rpcplugin_config.plugin_client_transports = transports

        if auto_mtls is not None:
            rpcplugin_config.plugin_auto_mtls = auto_mtls

        if handshake_timeout is not None:
            rpcplugin_config.plugin_handshake_timeout = handshake_timeout

        # Apply any additional keyword arguments
        for key, value in kwargs.items():
            if hasattr(rpcplugin_config, key):
                setattr(rpcplugin_config, key, value)
            else:
                logger.warning(f"Unknown configuration parameter: {key}")

    except Exception as e:
        raise ConfigError(f"Failed to configure RPC plugin: {e}") from e


# Export commonly used items for backward compatibility
__all__ = [
    "RPCPluginConfig",
    "configure",
    "rpcplugin_config",
]
