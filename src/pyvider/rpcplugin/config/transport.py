"""Transport layer configuration."""

from attrs import define, field
from provide.foundation.config import validate_positive

from pyvider.rpcplugin.defaults import (
    DEFAULT_CLIENT_TRANSPORTS,
    DEFAULT_SERVER_TRANSPORTS,
)


@define(slots=True)
class TransportConfig:
    """Transport layer configuration."""

    # =====================================================
    # Transport Types
    # =====================================================

    plugin_server_transports: list[str] = field(
        factory=lambda: DEFAULT_SERVER_TRANSPORTS.copy(),
        description="List of transports supported by the server",
        env_var="PLUGIN_SERVER_TRANSPORTS",
    )

    plugin_client_transports: list[str] = field(
        factory=lambda: DEFAULT_CLIENT_TRANSPORTS.copy(),
        description="List of transports supported by the client",
        env_var="PLUGIN_CLIENT_TRANSPORTS",
    )

    # =====================================================
    # Connection Timeouts
    # =====================================================

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

    # =====================================================
    # Buffer and Chunk Sizes
    # =====================================================

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
