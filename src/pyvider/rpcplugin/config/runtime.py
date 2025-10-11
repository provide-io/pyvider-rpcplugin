#
# pyvider/rpcplugin/config/runtime.py
#
"""
Core RPCPluginConfig class implementation using Foundation framework.

This module contains the main configuration class that uses env_field
and parse_list for proper environment variable parsing.
"""

from __future__ import annotations

from attrs import define
from provide.foundation.config import RuntimeConfig, parse_log_level
from provide.foundation.config.env import env_field

from pyvider.rpcplugin.config.validators import validate_protocol_versions_list, validate_transport_list
from pyvider.rpcplugin.defaults import (
    DEFAULT_PLUGIN_AUTO_MTLS,
    DEFAULT_PLUGIN_BUFFER_SIZE,
    DEFAULT_PLUGIN_CA_CERT,
    DEFAULT_PLUGIN_CERT_VALIDITY_DAYS,
    DEFAULT_PLUGIN_CHANNEL_READY_TIMEOUT,
    DEFAULT_PLUGIN_CHUNK_SIZE,
    DEFAULT_PLUGIN_CLIENT_BACKOFF_MULTIPLIER,
    DEFAULT_PLUGIN_CLIENT_CERT,
    DEFAULT_PLUGIN_CLIENT_CERT_FILE,
    DEFAULT_PLUGIN_CLIENT_INITIAL_BACKOFF_MS,
    DEFAULT_PLUGIN_CLIENT_KEY,
    DEFAULT_PLUGIN_CLIENT_KEY_FILE,
    DEFAULT_PLUGIN_CLIENT_MAX_BACKOFF_MS,
    DEFAULT_PLUGIN_CLIENT_MAX_RETRIES,
    DEFAULT_PLUGIN_CLIENT_MAX_RETRY_DELAY,
    DEFAULT_PLUGIN_CLIENT_RETRY_DELAY,
    DEFAULT_PLUGIN_CLIENT_RETRY_ENABLED,
    DEFAULT_PLUGIN_CLIENT_RETRY_JITTER_MS,
    DEFAULT_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S,
    DEFAULT_PLUGIN_CLIENT_ROOT_CERTS,
    DEFAULT_PLUGIN_CLIENT_TRANSPORTS,
    DEFAULT_PLUGIN_CONNECTION_TIMEOUT,
    DEFAULT_PLUGIN_CORE_VERSION,
    DEFAULT_PLUGIN_GRPC_GRACE_PERIOD,
    DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIME_MS,
    DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS,
    DEFAULT_PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE,
    DEFAULT_PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE,
    DEFAULT_PLUGIN_HANDSHAKE_TIMEOUT,
    DEFAULT_PLUGIN_HEALTH_SERVICE_ENABLED,
    DEFAULT_PLUGIN_INSECURE,
    DEFAULT_PLUGIN_LOG_LEVEL,
    DEFAULT_PLUGIN_MAGIC_COOKIE_KEY,
    DEFAULT_PLUGIN_MAGIC_COOKIE_VALUE,
    DEFAULT_PLUGIN_MTLS_CERT_DIR,
    DEFAULT_PLUGIN_PROTOCOL_VERSION,
    DEFAULT_PLUGIN_PROTOCOL_VERSIONS,
    DEFAULT_PLUGIN_RATE_LIMIT_BURST_CAPACITY,
    DEFAULT_PLUGIN_RATE_LIMIT_ENABLED,
    DEFAULT_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND,
    DEFAULT_PLUGIN_SERVER_CERT,
    DEFAULT_PLUGIN_SERVER_HOST,
    DEFAULT_PLUGIN_SERVER_KEY,
    DEFAULT_PLUGIN_SERVER_PORT,
    DEFAULT_PLUGIN_SERVER_READY_TIMEOUT,
    DEFAULT_PLUGIN_SERVER_ROOT_CERTS,
    DEFAULT_PLUGIN_SERVER_TRANSPORTS,
    DEFAULT_PLUGIN_SERVER_UNIX_SOCKET_PATH,
    DEFAULT_PLUGIN_SHOW_EMOJI_MATRIX,
    DEFAULT_PLUGIN_SHUTDOWN_FILE_PATH,
    DEFAULT_PLUGIN_UI_ENABLED,
    DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
    DEFAULT_SUPPORTED_TRANSPORTS,
)

PLUGIN_PROTOCOL_VERSIONS_FIELD = env_field(
    factory=lambda: DEFAULT_PLUGIN_PROTOCOL_VERSIONS.copy(),
    parser=validate_protocol_versions_list,
    env_var="PLUGIN_PROTOCOL_VERSIONS",
)

PLUGIN_PROTOCOL_VERSION_FIELD = env_field(
    default=DEFAULT_PLUGIN_PROTOCOL_VERSION,
    parser=int,
    env_var="PLUGIN_PROTOCOL_VERSION",
)

SUPPORTED_PROTOCOL_VERSIONS_FIELD = env_field(
    factory=lambda: DEFAULT_SUPPORTED_PROTOCOL_VERSIONS.copy(),
    env_var="SUPPORTED_PROTOCOL_VERSIONS",
)

PLUGIN_SERVER_TRANSPORTS_FIELD = env_field(
    factory=lambda: DEFAULT_PLUGIN_SERVER_TRANSPORTS.copy(),
    parser=validate_transport_list,
    env_var="PLUGIN_SERVER_TRANSPORTS",
)

PLUGIN_CLIENT_TRANSPORTS_FIELD = env_field(
    factory=lambda: DEFAULT_PLUGIN_CLIENT_TRANSPORTS.copy(),
    parser=validate_transport_list,
    env_var="PLUGIN_CLIENT_TRANSPORTS",
)

PLUGIN_SUPPORTED_TRANSPORTS_FIELD = env_field(
    factory=lambda: DEFAULT_SUPPORTED_TRANSPORTS.copy(),
    env_var="PLUGIN_SUPPORTED_TRANSPORTS",
)


@define
class RPCPluginConfig(RuntimeConfig):
    """
    Configuration for RPC plugin system.

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

    plugin_core_version: int = env_field(
        default=DEFAULT_PLUGIN_CORE_VERSION,
        parser=int,
        env_var="PLUGIN_CORE_VERSION",
    )

    plugin_protocol_versions: list[int] = PLUGIN_PROTOCOL_VERSIONS_FIELD

    plugin_protocol_version: int = PLUGIN_PROTOCOL_VERSION_FIELD

    supported_protocol_versions: list[int] = SUPPORTED_PROTOCOL_VERSIONS_FIELD

    plugin_magic_cookie_key: str = env_field(
        default=DEFAULT_PLUGIN_MAGIC_COOKIE_KEY,
        env_var="PLUGIN_MAGIC_COOKIE_KEY",
    )

    plugin_magic_cookie_value: str = env_field(
        default=DEFAULT_PLUGIN_MAGIC_COOKIE_VALUE,
        env_var="PLUGIN_MAGIC_COOKIE_VALUE",
    )

    plugin_log_level: str = env_field(
        default=DEFAULT_PLUGIN_LOG_LEVEL,
        parser=parse_log_level,
        env_var="PLUGIN_LOG_LEVEL",
    )

    # =====================================================
    # Transport Configuration
    # =====================================================

    plugin_handshake_timeout: float = env_field(
        default=DEFAULT_PLUGIN_HANDSHAKE_TIMEOUT,
        parser=float,
        env_var="PLUGIN_HANDSHAKE_TIMEOUT",
    )

    plugin_connection_timeout: float = env_field(
        default=DEFAULT_PLUGIN_CONNECTION_TIMEOUT,
        parser=float,
        env_var="PLUGIN_CONNECTION_TIMEOUT",
    )

    plugin_channel_ready_timeout: float = env_field(
        default=DEFAULT_PLUGIN_CHANNEL_READY_TIMEOUT,
        parser=float,
        env_var="PLUGIN_CHANNEL_READY_TIMEOUT",
    )

    plugin_server_ready_timeout: float = env_field(
        default=DEFAULT_PLUGIN_SERVER_READY_TIMEOUT,
        parser=float,
        env_var="PLUGIN_SERVER_READY_TIMEOUT",
    )

    plugin_server_transports: list[str] = PLUGIN_SERVER_TRANSPORTS_FIELD

    plugin_client_transports: list[str] = PLUGIN_CLIENT_TRANSPORTS_FIELD

    plugin_supported_transports: list[str] = PLUGIN_SUPPORTED_TRANSPORTS_FIELD

    plugin_transport_buffer_size: int = env_field(
        default=DEFAULT_PLUGIN_BUFFER_SIZE,
        parser=int,
        env_var="PLUGIN_TRANSPORT_BUFFER_SIZE",
    )

    plugin_buffer_size: int = env_field(
        default=DEFAULT_PLUGIN_BUFFER_SIZE,
        parser=int,
        env_var="PLUGIN_BUFFER_SIZE",
    )

    plugin_chunk_size: int = env_field(
        default=DEFAULT_PLUGIN_CHUNK_SIZE,
        parser=int,
        env_var="PLUGIN_CHUNK_SIZE",
    )

    # =====================================================
    # Security Configuration
    # =====================================================

    plugin_auto_mtls: bool = env_field(
        default=DEFAULT_PLUGIN_AUTO_MTLS,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_AUTO_MTLS",
    )

    plugin_mtls_cert_dir: str = env_field(
        default=DEFAULT_PLUGIN_MTLS_CERT_DIR,
        env_var="PLUGIN_MTLS_CERT_DIR",
    )

    plugin_client_cert_file: str = env_field(
        default=DEFAULT_PLUGIN_CLIENT_CERT_FILE,
        env_var="PLUGIN_CLIENT_CERT_FILE",
    )

    plugin_client_key_file: str = env_field(
        default=DEFAULT_PLUGIN_CLIENT_KEY_FILE,
        env_var="PLUGIN_CLIENT_KEY_FILE",
    )

    plugin_client_root_certs: str = env_field(
        default=DEFAULT_PLUGIN_CLIENT_ROOT_CERTS,
        env_var="PLUGIN_CLIENT_ROOT_CERTS",
    )

    plugin_insecure: bool = env_field(
        default=DEFAULT_PLUGIN_INSECURE,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_INSECURE",
    )

    plugin_cert_validity_days: int = env_field(
        default=DEFAULT_PLUGIN_CERT_VALIDITY_DAYS,
        parser=int,
        env_var="PLUGIN_CERT_VALIDITY_DAYS",
    )

    plugin_server_cert: str | None = env_field(
        default=DEFAULT_PLUGIN_SERVER_CERT,
        env_var="PLUGIN_SERVER_CERT",
    )

    plugin_server_key: str | None = env_field(
        default=DEFAULT_PLUGIN_SERVER_KEY,
        env_var="PLUGIN_SERVER_KEY",
    )

    plugin_server_root_certs: str | None = env_field(
        default=DEFAULT_PLUGIN_SERVER_ROOT_CERTS,
        env_var="PLUGIN_SERVER_ROOT_CERTS",
    )

    plugin_client_cert: str | None = env_field(
        default=DEFAULT_PLUGIN_CLIENT_CERT,
        env_var="PLUGIN_CLIENT_CERT",
    )

    plugin_client_key: str | None = env_field(
        default=DEFAULT_PLUGIN_CLIENT_KEY,
        env_var="PLUGIN_CLIENT_KEY",
    )

    plugin_ca_cert: str | None = env_field(
        default=DEFAULT_PLUGIN_CA_CERT,
        env_var="PLUGIN_CA_CERT",
    )

    # =====================================================
    # gRPC Configuration
    # =====================================================

    plugin_grpc_keepalive_time_ms: int = env_field(
        default=DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIME_MS,
        parser=int,
        env_var="PLUGIN_GRPC_KEEPALIVE_TIME_MS",
    )

    plugin_grpc_keepalive_timeout_ms: int = env_field(
        default=DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS,
        parser=int,
        env_var="PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS",
    )

    plugin_grpc_grace_period: float = env_field(
        default=DEFAULT_PLUGIN_GRPC_GRACE_PERIOD,
        parser=float,
        env_var="PLUGIN_GRPC_GRACE_PERIOD",
    )

    plugin_grpc_max_receive_message_size: int = env_field(
        default=DEFAULT_PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE,
        parser=int,
        env_var="PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE",
    )

    plugin_grpc_max_send_message_size: int = env_field(
        default=DEFAULT_PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE,
        parser=int,
        env_var="PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE",
    )

    # =====================================================
    # Client Configuration
    # =====================================================

    plugin_client_max_retries: int = env_field(
        default=DEFAULT_PLUGIN_CLIENT_MAX_RETRIES,
        parser=int,
        env_var="PLUGIN_CLIENT_MAX_RETRIES",
    )

    plugin_client_retry_delay: float = env_field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_DELAY,
        parser=float,
        env_var="PLUGIN_CLIENT_RETRY_DELAY",
    )

    plugin_client_backoff_multiplier: float = env_field(
        default=DEFAULT_PLUGIN_CLIENT_BACKOFF_MULTIPLIER,
        parser=float,
        env_var="PLUGIN_CLIENT_BACKOFF_MULTIPLIER",
    )

    plugin_client_max_retry_delay: float = env_field(
        default=DEFAULT_PLUGIN_CLIENT_MAX_RETRY_DELAY,
        parser=float,
        env_var="PLUGIN_CLIENT_MAX_RETRY_DELAY",
    )

    plugin_client_retry_enabled: bool = env_field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_ENABLED,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_CLIENT_RETRY_ENABLED",
    )

    plugin_client_initial_backoff_ms: int = env_field(
        default=DEFAULT_PLUGIN_CLIENT_INITIAL_BACKOFF_MS,
        parser=int,
        env_var="PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
    )

    plugin_client_max_backoff_ms: int = env_field(
        default=DEFAULT_PLUGIN_CLIENT_MAX_BACKOFF_MS,
        parser=int,
        env_var="PLUGIN_CLIENT_MAX_BACKOFF_MS",
    )

    plugin_client_retry_jitter_ms: int = env_field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_JITTER_MS,
        parser=int,
        env_var="PLUGIN_CLIENT_RETRY_JITTER_MS",
    )

    plugin_client_retry_total_timeout_s: float = env_field(
        default=DEFAULT_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S,
        parser=float,
        env_var="PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S",
    )

    # =====================================================
    # Server Configuration
    # =====================================================

    plugin_server_host: str = env_field(
        default=DEFAULT_PLUGIN_SERVER_HOST,
        env_var="PLUGIN_SERVER_HOST",
    )

    plugin_server_port: int = env_field(
        default=DEFAULT_PLUGIN_SERVER_PORT,
        parser=int,
        env_var="PLUGIN_SERVER_PORT",
    )

    plugin_server_unix_socket_path: str = env_field(
        default=DEFAULT_PLUGIN_SERVER_UNIX_SOCKET_PATH,
        env_var="PLUGIN_SERVER_UNIX_SOCKET_PATH",
    )

    plugin_shutdown_file_path: str = env_field(
        default=DEFAULT_PLUGIN_SHUTDOWN_FILE_PATH,
        env_var="PLUGIN_SHUTDOWN_FILE_PATH",
    )

    # =====================================================
    # Feature Configuration
    # =====================================================

    plugin_rate_limit_enabled: bool = env_field(
        default=DEFAULT_PLUGIN_RATE_LIMIT_ENABLED,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_RATE_LIMIT_ENABLED",
    )

    plugin_rate_limit_burst_capacity: int = env_field(
        default=DEFAULT_PLUGIN_RATE_LIMIT_BURST_CAPACITY,
        parser=int,
        env_var="PLUGIN_RATE_LIMIT_BURST_CAPACITY",
    )

    plugin_rate_limit_requests_per_second: float = env_field(
        default=DEFAULT_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND,
        parser=float,
        env_var="PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND",
    )

    plugin_health_service_enabled: bool = env_field(
        default=DEFAULT_PLUGIN_HEALTH_SERVICE_ENABLED,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_HEALTH_SERVICE_ENABLED",
    )

    plugin_ui_enabled: bool = env_field(
        default=DEFAULT_PLUGIN_UI_ENABLED,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_UI_ENABLED",
    )

    plugin_show_emoji_matrix: bool = env_field(
        default=DEFAULT_PLUGIN_SHOW_EMOJI_MATRIX,
        parser=lambda x: str(x).lower() in ("true", "1", "yes", "on"),
        env_var="PLUGIN_SHOW_EMOJI_MATRIX",
    )

    # All helper methods have been removed.
    # Use direct attribute access instead:
    # - config.plugin_magic_cookie_key instead of config.magic_cookie_key()
    # - config.plugin_handshake_timeout instead of config.handshake_timeout()
    # - etc.
