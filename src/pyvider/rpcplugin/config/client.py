"""Client retry and connection configuration."""

from attrs import define
from provide.foundation.config import field, validate_non_negative, validate_positive


@define
class ClientConfig:
    """Client retry and connection configuration."""

    # =====================================================
    # Retry Configuration
    # =====================================================

    plugin_client_retry_enabled: bool = field(
        default=True,
        description="Enable client retry logic",
        env_var="PLUGIN_CLIENT_RETRY_ENABLED",
    )

    plugin_client_max_retries: int = field(
        default=3,
        validator=validate_non_negative,
        description="Maximum number of client retries",
        env_var="PLUGIN_CLIENT_MAX_RETRIES",
    )

    plugin_client_initial_backoff_ms: int = field(
        default=100,
        validator=validate_positive,
        description="Initial backoff delay in milliseconds",
        env_var="PLUGIN_CLIENT_INITIAL_BACKOFF_MS",
    )

    plugin_client_max_backoff_ms: int = field(
        default=5000,
        validator=validate_positive,
        description="Maximum backoff delay in milliseconds",
        env_var="PLUGIN_CLIENT_MAX_BACKOFF_MS",
    )

    plugin_client_retry_jitter_ms: int = field(
        default=50,
        validator=validate_non_negative,
        description="Retry jitter in milliseconds",
        env_var="PLUGIN_CLIENT_RETRY_JITTER_MS",
    )

    plugin_client_retry_total_timeout_s: float = field(
        default=30.0,
        validator=validate_positive,
        description="Total retry timeout in seconds",
        env_var="PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S",
    )

    # =====================================================
    # Connection Settings
    # =====================================================

    plugin_client_endpoint: str | None = field(
        default=None,
        description="Client endpoint for connection",
        env_var="PLUGIN_CLIENT_ENDPOINT",
    )
