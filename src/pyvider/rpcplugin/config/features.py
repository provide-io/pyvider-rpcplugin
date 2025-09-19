"""Feature configuration for Pyvider RPC Plugin.

Contains feature flags and optional component settings like
rate limiting, health checks, UI options, and shutdown handling.
"""

from provide.foundation.config import field, validate_positive


class FeaturesConfigMixin:
    """Feature configuration settings."""

    # UI configuration
    plugin_show_emoji_matrix: bool = field(
        default=True,
        description="Show emoji matrix in logs",
        env_var="PLUGIN_SHOW_EMOJI_MATRIX",
    )

    # Shutdown configuration
    plugin_shutdown_file_path: str | None = field(
        default=None,
        description="Path to shutdown signal file",
        env_var="PLUGIN_SHUTDOWN_FILE_PATH",
    )

    # Rate limiting configuration
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

    # Health service configuration
    plugin_health_service_enabled: bool = field(
        default=True,
        description="Enable health service",
        env_var="PLUGIN_HEALTH_SERVICE_ENABLED",
    )

    # Helper methods
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