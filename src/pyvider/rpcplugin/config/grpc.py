"""gRPC-specific configuration."""

from attrs import define, field
from provide.foundation.config import validate_positive


@define(slots=True)
class GRPCConfig:
    """gRPC-specific configuration."""

    # =====================================================
    # Keepalive Settings
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

    # =====================================================
    # Connection Management
    # =====================================================

    plugin_grpc_grace_period: float = field(
        default=5.0,
        validator=validate_positive,
        description="gRPC channel close grace period in seconds",
        env_var="PLUGIN_GRPC_GRACE_PERIOD",
    )