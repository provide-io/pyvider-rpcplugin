#
# pyvider/rpcplugin/telemetry.py
#
"""
OpenTelemetry integration for RPC Plugin framework.

This module provides a thin wrapper over Foundation's OpenTelemetry integration,
adapting RPC plugin configuration to Foundation's telemetry system.

Key features:
- Distributed tracing for RPC operations
- Performance metrics collection
- Graceful degradation when OTEL unavailable
- Zero overhead when disabled

Examples:
    Setup telemetry with RPC configuration:
        >>> from pyvider.rpcplugin.config import RPCPluginConfig
        >>> from pyvider.rpcplugin.telemetry import setup_rpc_telemetry
        >>>
        >>> config = RPCPluginConfig(
        ...     plugin_telemetry_enabled=True,
        ...     plugin_otel_traces_enabled=True,
        ...     plugin_otel_endpoint="http://localhost:4317"
        ... )
        >>> setup_rpc_telemetry(config)

    Get tracer for RPC operations:
        >>> from pyvider.rpcplugin.telemetry import get_rpc_tracer
        >>>
        >>> tracer = get_rpc_tracer()
        >>> if tracer:
        ...     with tracer.start_as_current_span("rpc.operation"):
        ...         # ... perform operation
        ...         pass

Note:
    This module does NOT reimplement OpenTelemetry. It uses Foundation's
    OTEL integration (provide.foundation.tracer.otel and
    provide.foundation.metrics.otel) and provides RPC-specific configuration
    mapping and helper functions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from provide.foundation import logger

if TYPE_CHECKING:
    from opentelemetry import metrics as otel_metrics, trace as otel_trace

    from pyvider.rpcplugin.config.runtime import RPCPluginConfig

# Feature detection - gracefully handle missing OTEL dependencies
try:
    from provide.foundation.logger.config.telemetry import TelemetryConfig
    from provide.foundation.metrics.otel import setup_opentelemetry_metrics
    from provide.foundation.tracer.otel import get_otel_tracer, setup_opentelemetry_tracing

    _HAS_FOUNDATION_OTEL = True
except ImportError:
    _HAS_FOUNDATION_OTEL = False
    TelemetryConfig = None  # type: ignore[misc,assignment]
    setup_opentelemetry_tracing = None  # type: ignore[assignment]
    setup_opentelemetry_metrics = None  # type: ignore[assignment]
    get_otel_tracer = None  # type: ignore[assignment]


def _require_foundation_otel() -> None:
    """Ensure Foundation OTEL integration is available.

    Raises:
        ImportError: If Foundation OTEL integration is not available
    """
    if not _HAS_FOUNDATION_OTEL:
        raise ImportError(
            "OpenTelemetry integration requires Foundation with OTEL support. "
            "Install with: pip install 'provide-foundation[opentelemetry]'",
        )


def _parse_otel_headers(headers_str: str | None) -> dict[str, str]:
    """Parse OTEL headers string into dictionary.

    Args:
        headers_str: Comma-separated key=value pairs (e.g., "key1=val1,key2=val2")

    Returns:
        Dictionary of header key-value pairs

    Example:
        >>> _parse_otel_headers("api-key=secret,service=rpc")
        {'api-key': 'secret', 'service': 'rpc'}
    """
    if not headers_str:
        return {}

    headers = {}
    for pair in headers_str.split(","):
        pair = pair.strip()
        if "=" in pair:
            key, value = pair.split("=", 1)
            headers[key.strip()] = value.strip()

    return headers


def setup_rpc_telemetry(config: RPCPluginConfig) -> None:
    """Setup OpenTelemetry for RPC operations using Foundation integration.

    This function converts RPC plugin configuration to Foundation's TelemetryConfig
    and calls Foundation's OTEL setup functions. It does NOT reimplement OTEL.

    Args:
        config: RPC plugin configuration with telemetry settings

    Note:
        - No-op if telemetry is disabled
        - Gracefully handles missing OTEL dependencies
        - Safe to call multiple times (idempotent)

    Example:
        >>> config = RPCPluginConfig(
        ...     plugin_telemetry_enabled=True,
        ...     plugin_otel_traces_enabled=True,
        ...     plugin_otel_endpoint="http://localhost:4317",
        ...     plugin_otel_protocol="grpc"
        ... )
        >>> setup_rpc_telemetry(config)
    """
    # Early exit if telemetry disabled
    if not config.plugin_telemetry_enabled:
        logger.debug("RPC telemetry disabled, skipping setup")
        return

    # Check if Foundation OTEL available
    if not _HAS_FOUNDATION_OTEL:
        logger.warning(
            "OpenTelemetry requested but Foundation OTEL not available. "
            "Install with: pip install 'provide-foundation[opentelemetry]'"
        )
        return

    logger.info(
        "Setting up RPC telemetry",
        service_name=config.plugin_telemetry_service_name,
        traces_enabled=config.plugin_otel_traces_enabled,
        metrics_enabled=config.plugin_otel_metrics_enabled,
    )

    # Convert RPC config → Foundation TelemetryConfig
    telemetry_config = TelemetryConfig(
        # Service identification
        service_name=config.plugin_telemetry_service_name,
        service_version=config.plugin_telemetry_service_version,
        # Feature flags
        tracing_enabled=config.plugin_otel_traces_enabled,
        metrics_enabled=config.plugin_otel_metrics_enabled,
        globally_disabled=not config.plugin_telemetry_enabled,
        # OTLP endpoints
        # Note: Foundation uses otlp_endpoint for both traces and metrics
        otlp_endpoint=config.plugin_otel_endpoint,
        otlp_traces_endpoint=config.plugin_otel_traces_endpoint,
        # Protocol and headers
        otlp_protocol=config.plugin_otel_protocol,
        otlp_headers=_parse_otel_headers(config.plugin_otel_headers),
        # Sampling
        trace_sample_rate=config.plugin_trace_sample_rate,
    )

    # Use Foundation's OTEL setup (not reimplementing!)
    try:
        if config.plugin_otel_traces_enabled:
            setup_opentelemetry_tracing(telemetry_config)
            logger.info("RPC tracing setup complete")

        if config.plugin_otel_metrics_enabled:
            setup_opentelemetry_metrics(telemetry_config)
            logger.info("RPC metrics setup complete")

    except Exception as e:
        logger.error(
            "Failed to setup RPC telemetry",
            error=str(e),
            error_type=type(e).__name__,
        )
        # Don't raise - graceful degradation
        return


def get_rpc_tracer() -> otel_trace.Tracer | None:
    """Get OpenTelemetry tracer for RPC operations.

    Returns:
        Tracer instance if available, None otherwise

    Example:
        >>> tracer = get_rpc_tracer()
        >>> if tracer:
        ...     with tracer.start_as_current_span("rpc.handshake") as span:
        ...         span.set_attribute("transport", "unix")
        ...         # ... perform handshake
    """
    if not _HAS_FOUNDATION_OTEL:
        return None

    try:
        return get_otel_tracer("pyvider.rpcplugin")
    except Exception:
        # Graceful degradation on any error
        return None


def get_rpc_meter() -> otel_metrics.Meter | None:
    """Get OpenTelemetry meter for RPC metrics.

    Returns:
        Meter instance if available, None otherwise

    Example:
        >>> meter = get_rpc_meter()
        >>> if meter:
        ...     counter = meter.create_counter(
        ...         "rpc.handshake.success",
        ...         description="Successful handshakes"
        ...     )
        ...     counter.add(1, {"transport": "unix"})
    """
    if not _HAS_FOUNDATION_OTEL:
        return None

    try:
        from opentelemetry import metrics as otel_metrics

        return otel_metrics.get_meter("pyvider.rpcplugin")
    except Exception:
        # Graceful degradation on any error
        return None


def is_telemetry_available() -> bool:
    """Check if OpenTelemetry telemetry is available.

    Returns:
        True if Foundation OTEL integration is available

    Example:
        >>> if is_telemetry_available():
        ...     setup_rpc_telemetry(config)
    """
    return _HAS_FOUNDATION_OTEL


__all__ = [
    "get_rpc_meter",
    "get_rpc_tracer",
    "is_telemetry_available",
    "setup_rpc_telemetry",
]
