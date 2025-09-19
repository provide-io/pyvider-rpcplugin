"""Feature flags and optional capabilities."""

from attrs import define, field
from provide.foundation.config import validate_positive


@define(slots=True)
class FeaturesConfig:
    """Feature flags and optional capabilities."""

    # =====================================================
    # Rate Limiting
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

    # =====================================================
    # Health Service
    # =====================================================

    plugin_health_service_enabled: bool = field(
        default=True,
        description="Enable health service",
        env_var="PLUGIN_HEALTH_SERVICE_ENABLED",
    )

    # =====================================================
    # UI Features
    # =====================================================

    plugin_show_emoji_matrix: bool = field(
        default=False,
        description="Show emoji matrix in UI",
        env_var="PLUGIN_SHOW_EMOJI_MATRIX",
    )