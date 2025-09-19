"""Transport configuration for Pyvider RPC Plugin.

Contains transport-related settings like timeouts, buffer sizes,
and supported transport types.
"""

from provide.foundation.config import field, validate_positive, validate_range
from ..defaults import DEFAULT_CLIENT_TRANSPORTS, DEFAULT_SERVER_TRANSPORTS


class TransportConfigMixin:
    """Transport configuration settings."""

    # Transport types
    plugin_server_transports: list[str] = field(
        default_factory=lambda: DEFAULT_SERVER_TRANSPORTS.copy(),
        description="List of server transport types supported",
        env_var="PLUGIN_SERVER_TRANSPORTS",
    )

    plugin_client_transports: list[str] = field(
        default_factory=lambda: DEFAULT_CLIENT_TRANSPORTS.copy(),
        description="List of client transport types supported",
        env_var="PLUGIN_CLIENT_TRANSPORTS",
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
        validator=validate_range(0.1, 300.0),
        description="Timeout for connection establishment in seconds",
        env_var="PLUGIN_CONNECTION_TIMEOUT",
    )

    plugin_channel_ready_timeout: float = field(
        default=10.0,
        validator=validate_range(0.1, 300.0),
        description="Timeout for gRPC channel ready check in seconds",
        env_var="PLUGIN_CHANNEL_READY_TIMEOUT",
    )

    plugin_server_ready_timeout: float = field(
        default=5.0,
        validator=validate_range(0.1, 300.0),
        description="Timeout for server ready check in seconds",
        env_var="PLUGIN_SERVER_READY_TIMEOUT",
    )

    # Buffer and data size configuration
    plugin_buffer_size: int = field(
        default=16384,
        validator=validate_positive,
        description="Default buffer size for data operations in bytes",
        env_var="PLUGIN_BUFFER_SIZE",
    )

    plugin_chunk_size: int = field(
        default=1024,
        validator=validate_positive,
        description="Default chunk size for streaming in bytes",
        env_var="PLUGIN_CHUNK_SIZE",
    )

    # Helper methods
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