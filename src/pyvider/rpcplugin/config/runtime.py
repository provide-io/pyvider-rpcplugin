"""Runtime configuration for Pyvider RPC Plugin."""

from __future__ import annotations

from attrs import define
from provide.foundation.config import (
    RuntimeConfig,
    field,
    validate_choice,
    validate_non_negative,
    validate_positive,
    validate_range,
)

from pyvider.rpcplugin.config.validation import _validate_protocol_versions_list, _validate_transports_list
from pyvider.rpcplugin.defaults import (
    DEFAULT_CLIENT_TRANSPORTS,
    DEFAULT_PLUGIN_AUTO_MTLS,
    DEFAULT_PLUGIN_BUFFER_SIZE,
    DEFAULT_PLUGIN_CERT_VALIDITY_DAYS,
    DEFAULT_PLUGIN_CHANNEL_READY_TIMEOUT,
    DEFAULT_PLUGIN_CHUNK_SIZE,
    DEFAULT_PLUGIN_CLIENT_INITIAL_BACKOFF_MS,
    DEFAULT_PLUGIN_CLIENT_MAX_BACKOFF_MS,
    DEFAULT_PLUGIN_CLIENT_MAX_RETRIES,
    DEFAULT_PLUGIN_CLIENT_RETRY_ENABLED,
    DEFAULT_PLUGIN_CLIENT_RETRY_JITTER_MS,
    DEFAULT_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S,
    DEFAULT_PLUGIN_CONNECTION_TIMEOUT,
    DEFAULT_PLUGIN_CORE_VERSION,
    DEFAULT_PLUGIN_GRPC_GRACE_PERIOD,
    DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIME_MS,
    DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS,
    DEFAULT_PLUGIN_HANDSHAKE_TIMEOUT,
    DEFAULT_PLUGIN_HEALTH_SERVICE_ENABLED,
    DEFAULT_PLUGIN_INSECURE,
    DEFAULT_PLUGIN_LOG_LEVEL,
    DEFAULT_PLUGIN_MAGIC_COOKIE_KEY,
    DEFAULT_PLUGIN_MAGIC_COOKIE_VALUE,
    DEFAULT_PLUGIN_PROTOCOL_VERSION,
    DEFAULT_PLUGIN_PROTOCOL_VERSIONS,
    DEFAULT_PLUGIN_RATE_LIMIT_BURST_CAPACITY,
    DEFAULT_PLUGIN_RATE_LIMIT_ENABLED,
    DEFAULT_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND,
    DEFAULT_PLUGIN_SERVER_HOST,
    DEFAULT_PLUGIN_SERVER_PORT,
    DEFAULT_PLUGIN_SERVER_READY_TIMEOUT,
    DEFAULT_PLUGIN_SHOW_EMOJI_MATRIX,
    DEFAULT_PLUGIN_UNIX_SOCKET_PATH,
    DEFAULT_SERVER_TRANSPORTS,
    DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
)


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
        default=DEFAULT_PLUGIN_CORE_VERSION,
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
        default=DEFAULT_PLUGIN_PROTOCOL_VERSION,
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
        default=DEFAULT_PLUGIN_MAGIC_COOKIE_KEY,
        description="Environment variable name for the magic cookie",
        env_var="PLUGIN_MAGIC_COOKIE_KEY",
    )

    plugin_magic_cookie_value: str = field(
        default=DEFAULT_PLUGIN_MAGIC_COOKIE_VALUE,
        description="Magic cookie value for handshake authentication",
        env_var="PLUGIN_MAGIC_COOKIE_VALUE",
        sensitive=True,
    )

    plugin_log_level: str = field(
        default=DEFAULT_PLUGIN_LOG_LEVEL,
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
        default=DEFAULT_PLUGIN_HANDSHAKE_TIMEOUT,
        validator=validate_range(0.1, 300.0),
        description="Timeout for handshake operations in seconds",
        env_var="PLUGIN_HANDSHAKE_TIMEOUT",
    )

    plugin_connection_timeout: float = field(
        default=DEFAULT_PLUGIN_CONNECTION_TIMEOUT,
        validator=validate_positive,
        description="Timeout for connection establishment in seconds",
        env_var="PLUGIN_CONNECTION_TIMEOUT",
    )

    plugin_channel_ready_timeout: float = field(
        default=DEFAULT_PLUGIN_CHANNEL_READY_TIMEOUT,
        validator=validate_positive,
        description="Timeout for gRPC channel to become ready in seconds",
        env_var="PLUGIN_CHANNEL_READY_TIMEOUT",
    )

    plugin_server_ready_timeout: float = field(
        default=DEFAULT_PLUGIN_SERVER_READY_TIMEOUT,
        validator=validate_positive,
        description="Timeout for server to become ready in seconds",
        env_var="PLUGIN_SERVER_READY_TIMEOUT",
    )

    plugin_buffer_size: int = field(
        default=DEFAULT_PLUGIN_BUFFER_SIZE,
        validator=validate_positive,
        description="Default buffer size for data operations in bytes",
        env_var="PLUGIN_BUFFER_SIZE",
    )

    plugin_chunk_size: int = field(
        default=DEFAULT_PLUGIN_CHUNK_SIZE,
        validator=validate_positive,
        description="Default chunk size for streaming in bytes",
        env_var="PLUGIN_CHUNK_SIZE",
    )

    # =====================================================
    # Security Configuration
    # =====================================================

    plugin_auto_mtls: bool = field(
        default=DEFAULT_PLUGIN_AUTO_MTLS,
        description="Enable automatic mutual TLS certificate generation",
        env_var="PLUGIN_AUTO_MTLS",
    )

    plugin_insecure: bool = field(
        default=DEFAULT_PLUGIN_INSECURE,
        description="Allow insecure connections (disable TLS)",
        env_var="PLUGIN_INSECURE",
    )

    plugin_cert_validity_days: int = field(
        default=DEFAULT_PLUGIN_CERT_VALIDITY_DAYS,
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
        default=DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIME_MS,
        validator=validate_positive,
        description="gRPC keepalive time in milliseconds",
        env_var="PLUGIN_GRPC_KEEPALIVE_TIME_MS",
    )

    plugin_grpc_keepalive_timeout_ms: int = field(
        default=DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS,
        validator=validate_positive,
        description="gRPC keepalive timeout in milliseconds",
        env_var="PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS",
    )

    plugin_grpc_grace_period: float = field(
        default=DEFAULT_PLUGIN_GRPC_GRACE_PERIOD,
        validator=validate_positive,
        description="gRPC channel close grace period in seconds",
        env_var="PLUGIN_GRPC_GRACE_PERIOD",
    )

    # =====================================================
    # Client Configuration
    # =====================================================

    plugin_client_retry_enabled: bool = field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_ENABLED,
        description="Enable client retry logic",
        env_var="PLUGIN_CLIENT_RETRY_ENABLED",
    )

    plugin_client_max_retries: int = field(
        default=DEFAULT_PLUGIN_CLIENT_MAX_RETRIES,
        validator=validate_non_negative,
        description="Maximum number of client retries",
        env_var="PLUGIN_CLIENT_MAX_RETRIES",
    )

    plugin_client_initial_backoff_ms: int = field(
        default=DEFAULT_PLUGIN_CLIENT_INITIAL_BACKOFF_MS,
        validator=validate_positive,
        description="Initial backoff delay in milliseconds",
        env_var="PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
    )

    plugin_client_max_backoff_ms: int = field(
        default=DEFAULT_PLUGIN_CLIENT_MAX_BACKOFF_MS,
        validator=validate_positive,
        description="Maximum backoff delay in milliseconds",
        env_var="PLUGIN_CLIENT_MAX_BACKOFF_MS",
    )

    plugin_client_retry_jitter_ms: int = field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_JITTER_MS,
        validator=validate_non_negative,
        description="Retry jitter in milliseconds",
        env_var="PLUGIN_CLIENT_RETRY_JITTER_MS",
    )

    plugin_client_retry_total_timeout_s: float = field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S,
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
        default=DEFAULT_PLUGIN_SERVER_HOST,
        description="Server host address",
        env_var="PLUGIN_SERVER_HOST",
    )

    plugin_server_port: int = field(
        default=DEFAULT_PLUGIN_SERVER_PORT,
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
        default=DEFAULT_PLUGIN_UNIX_SOCKET_PATH,
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
        default=DEFAULT_PLUGIN_RATE_LIMIT_ENABLED,
        description="Enable rate limiting",
        env_var="PLUGIN_RATE_LIMIT_ENABLED",
    )

    plugin_rate_limit_requests_per_second: float = field(
        default=DEFAULT_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND,
        validator=validate_positive,
        description="Rate limit in requests per second",
        env_var="PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND",
    )

    plugin_rate_limit_burst_capacity: float = field(
        default=DEFAULT_PLUGIN_RATE_LIMIT_BURST_CAPACITY,
        validator=validate_positive,
        description="Rate limit burst capacity",
        env_var="PLUGIN_RATE_LIMIT_BURST_CAPACITY",
    )

    plugin_health_service_enabled: bool = field(
        default=DEFAULT_PLUGIN_HEALTH_SERVICE_ENABLED,
        description="Enable health service",
        env_var="PLUGIN_HEALTH_SERVICE_ENABLED",
    )

    plugin_show_emoji_matrix: bool = field(
        default=DEFAULT_PLUGIN_SHOW_EMOJI_MATRIX,
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