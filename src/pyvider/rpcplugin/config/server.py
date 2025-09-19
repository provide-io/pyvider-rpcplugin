"""Server hosting configuration."""

from attrs import define
from provide.foundation.config import field, validate_range


@define(slots=True)
class ServerConfig:
    """Server hosting configuration."""

    # =====================================================
    # Network Configuration
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

    # =====================================================
    # Unix Socket Configuration
    # =====================================================

    plugin_unix_socket_path: str = field(
        default="/tmp/plugin.sock",
        description="Unix socket path for local connections",
        env_var="PLUGIN_UNIX_SOCKET_PATH",
    )

    # =====================================================
    # Lifecycle Configuration
    # =====================================================

    plugin_shutdown_file_path: str | None = field(
        default=None,
        description="Path to shutdown signal file",
        env_var="PLUGIN_SHUTDOWN_FILE_PATH",
    )
