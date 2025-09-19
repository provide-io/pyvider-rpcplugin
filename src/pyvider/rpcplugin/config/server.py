"""Server configuration for Pyvider RPC Plugin.

Contains server-specific settings like server behavior,
listener configuration, and server lifecycle management.
"""

from provide.foundation.config import field


class ServerConfigMixin:
    """Server configuration settings."""

    # Server host/port configuration
    plugin_server_host: str = field(
        default="127.0.0.1",
        description="Default server host for TCP transport",
        env_var="PLUGIN_SERVER_HOST",
    )

    plugin_server_port: int = field(
        default=0,  # 0 means auto-assign
        description="Default server port for TCP transport (0 for auto-assign)",
        env_var="PLUGIN_SERVER_PORT",
    )

    plugin_unix_socket_path: str | None = field(
        default=None,
        description="Default Unix socket path for Unix transport",
        env_var="PLUGIN_UNIX_SOCKET_PATH",
    )

    # Helper methods (reserved for future server-specific helpers)