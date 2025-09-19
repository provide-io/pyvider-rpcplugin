"""Client configuration for Pyvider RPC Plugin.

Contains client-specific settings like retry logic, backoff strategies,
and client behavior configuration.
"""

from provide.foundation.config import field, validate_non_negative, validate_positive


class ClientConfigMixin:
    """Client configuration settings."""

    # Retry configuration
    plugin_client_retry_enabled: bool = field(
        default=True,
        description="Enable client retry mechanism",
        env_var="PLUGIN_CLIENT_RETRY_ENABLED",
    )

    plugin_client_max_retries: int = field(
        default=3,
        validator=validate_non_negative,
        description="Maximum number of retry attempts",
        env_var="PLUGIN_CLIENT_MAX_RETRIES",
    )

    plugin_client_initial_backoff_ms: int = field(
        default=500,
        validator=validate_positive,
        description="Initial backoff time in milliseconds",
        env_var="PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
    )

    plugin_client_max_backoff_ms: int = field(
        default=5000,
        validator=validate_positive,
        description="Maximum backoff time in milliseconds",
        env_var="PLUGIN_CLIENT_MAX_BACKOFF_MS",
    )

    plugin_client_retry_jitter_ms: int = field(
        default=100,
        validator=validate_non_negative,
        description="Retry jitter in milliseconds",
        env_var="PLUGIN_CLIENT_RETRY_JITTER_MS",
    )

    plugin_client_retry_total_timeout_s: int = field(
        default=60,
        validator=validate_positive,
        description="Total retry timeout in seconds",
        env_var="PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S",
    )

    # Helper methods (none specific to client config yet, but reserved for future use)