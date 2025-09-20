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
from provide.foundation.config import RuntimeConfig
from provide.foundation.config.env import env_field
from provide.foundation.config.validators import validate_choice, validate_positive, validate_range
from provide.foundation.errors import ValidationError
from provide.foundation.utils.parsing import parse_list

from pyvider.rpcplugin.defaults import *


def _validate_protocol_versions_list(value: str | list[int]) -> list[int]:
    """Validate that all protocol versions in the list are supported."""
    if isinstance(value, str):
        # Parse comma-separated string
        str_list = parse_list(value)
        try:
            int_list = [int(x) for x in str_list if x.strip()]
        except ValueError as e:
            raise ValidationError(f"Invalid protocol version format: {e}") from e
    elif isinstance(value, list):
        int_list = value
    else:
        raise ValidationError(f"Protocol versions must be a list or comma-separated string, got {type(value)}")

    for version in int_list:
        if version not in DEFAULT_SUPPORTED_PROTOCOL_VERSIONS:
            raise ValidationError(f"Protocol version must be between 1 and 7, got {version}")
    return int_list


def _validate_transport_list(value: str | list[str]) -> list[str]:
    """Validate that all transports in the list are supported."""
    if isinstance(value, str):
        # Parse comma-separated string
        str_list = parse_list(value)
    elif isinstance(value, list):
        str_list = value
    else:
        raise ValidationError(f"Transports must be a list or comma-separated string, got {type(value)}")

    for transport in str_list:
        if transport not in DEFAULT_SUPPORTED_TRANSPORTS:
            raise ValidationError(f"Invalid transport '{transport}'. Must be one of: {DEFAULT_SUPPORTED_TRANSPORTS}")
    return str_list


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

    plugin_protocol_versions: list[int] = env_field(
        factory=lambda: DEFAULT_PLUGIN_PROTOCOL_VERSIONS.copy(),
        parser=_validate_protocol_versions_list,
        env_var="PLUGIN_PROTOCOL_VERSIONS",
    )

    plugin_protocol_version: int = env_field(
        default=DEFAULT_PLUGIN_PROTOCOL_VERSION,
        parser=int,
        env_var="PLUGIN_PROTOCOL_VERSION",
    )

    supported_protocol_versions: list[int] = env_field(
        factory=lambda: DEFAULT_SUPPORTED_PROTOCOL_VERSIONS.copy(),
        env_var="SUPPORTED_PROTOCOL_VERSIONS",
    )

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

    plugin_server_transports: list[str] = env_field(
        factory=lambda: DEFAULT_PLUGIN_SERVER_TRANSPORTS.copy(),
        parser=_validate_transport_list,
        env_var="PLUGIN_SERVER_TRANSPORTS",
    )

    plugin_client_transports: list[str] = env_field(
        factory=lambda: DEFAULT_PLUGIN_CLIENT_TRANSPORTS.copy(),
        parser=_validate_transport_list,
        env_var="PLUGIN_CLIENT_TRANSPORTS",
    )

    plugin_supported_transports: list[str] = env_field(
        factory=lambda: DEFAULT_SUPPORTED_TRANSPORTS.copy(),
        env_var="PLUGIN_SUPPORTED_TRANSPORTS",
    )

    plugin_transport_buffer_size: int = env_field(
        default=DEFAULT_PLUGIN_BUFFER_SIZE,
        parser=int,
        env_var="PLUGIN_TRANSPORT_BUFFER_SIZE",
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

    # =====================================================
    # gRPC Configuration
    # =====================================================

    plugin_grpc_keepalive_time: float = env_field(
        default=DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIME,
        parser=float,
        env_var="PLUGIN_GRPC_KEEPALIVE_TIME",
    )

    plugin_grpc_keepalive_timeout: float = env_field(
        default=DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIMEOUT,
        parser=float,
        env_var="PLUGIN_GRPC_KEEPALIVE_TIMEOUT",
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

    # =====================================================
    # Helper Methods
    # =====================================================

    def server_ready_timeout(self) -> float:
        """Get server ready timeout value."""
        return self.plugin_server_ready_timeout

    def channel_ready_timeout(self) -> float:
        """Get channel ready timeout value."""
        return self.plugin_channel_ready_timeout

    def handshake_timeout(self) -> float:
        """Get handshake timeout value."""
        return self.plugin_handshake_timeout

    def connection_timeout(self) -> float:
        """Get connection timeout value."""
        return self.plugin_connection_timeout

    def grpc_grace_period(self) -> float:
        """Get gRPC grace period value."""
        return self.plugin_grpc_grace_period