"""gRPC configuration for Pyvider RPC Plugin.

Contains gRPC-specific settings like keepalive timeouts, grace periods,
and channel configuration.
"""

from provide.foundation.config import field, validate_positive


class GRPCConfigMixin:
    """gRPC configuration settings."""

    # gRPC keepalive configuration
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
        default=0.5,
        validator=validate_positive,
        description="gRPC channel close grace period in seconds",
        env_var="PLUGIN_GRPC_GRACE_PERIOD",
    )

    # Helper methods
    def grpc_keepalive_time_ms(self) -> int:
        """Get gRPC keepalive time in milliseconds."""
        return self.plugin_grpc_keepalive_time_ms

    def grpc_keepalive_timeout_ms(self) -> int:
        """Get gRPC keepalive timeout in milliseconds."""
        return self.plugin_grpc_keepalive_timeout_ms

    def grpc_grace_period(self) -> float:
        """Get gRPC channel close grace period in seconds."""
        return self.plugin_grpc_grace_period