#
# pyvider/rpcplugin/telemetry.py
#
"""
OpenTelemetry integration for RPC Plugin framework.

This module provides access to OpenTelemetry tracing for RPC operations.

IMPORTANT: This is a LIBRARY module. It does NOT configure OpenTelemetry.
Applications using this library should configure OpenTelemetry themselves
via provide-foundation or standard OTEL SDK setup.

Key features:
- Access to OpenTelemetry tracer for RPC operations
- Access to OpenTelemetry meter for metrics
- Graceful degradation when OTEL unavailable
- Zero overhead when disabled

Usage:
    Application configures OpenTelemetry:
        >>> from provide.foundation import TelemetryConfig
        >>> from provide.foundation.tracer.otel import setup_opentelemetry_tracing
        >>>
        >>> config = TelemetryConfig(
        ...     service_name="my-app",  # Application's service name
        ...     tracing_enabled=True,
        ...     otlp_endpoint="http://localhost:4317"
        ... )
        >>> setup_opentelemetry_tracing(config)

    Library gets tracer (already configured by app):
        >>> from pyvider.rpcplugin.telemetry import get_rpc_tracer
        >>>
        >>> tracer = get_rpc_tracer()  # instrumentation.library.name="pyvider.rpcplugin"
        >>> if tracer:
        ...     with tracer.start_as_current_span("rpc.operation"):
        ...         # ... perform operation
        ...         pass

Note:
    This module does NOT reimplement OpenTelemetry. It uses the tracer
    already configured by the application, and identifies RPC operations
    via instrumentation.library.name="pyvider.rpcplugin".

    All traces will appear under the application's service.name, making
    observability unified rather than fragmented.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from provide.foundation.logger import get_logger

if TYPE_CHECKING:
    from opentelemetry import metrics as otel_metrics, trace as otel_trace

logger = get_logger(__name__)

# Feature detection - gracefully handle missing OTEL dependencies
try:
    from opentelemetry import metrics as otel_metrics, trace as otel_trace

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False
    otel_trace = None  # type: ignore[assignment]
    otel_metrics = None  # type: ignore[assignment]


def get_rpc_tracer() -> otel_trace.Tracer | None:
    """Get OpenTelemetry tracer for RPC operations.

    Returns tracer from the already-configured global tracer provider.
    The application must have configured OpenTelemetry before calling this.

    Returns:
        Tracer instance if available, None otherwise

    Example:
        >>> tracer = get_rpc_tracer()
        >>> if tracer:
        ...     with tracer.start_as_current_span("rpc.handshake") as span:
        ...         span.set_attribute("transport", "unix")
        ...         # ... perform handshake
    """
    if not _HAS_OTEL:
        return None

    try:
        return otel_trace.get_tracer(
            instrumenting_module_name="pyvider.rpcplugin",
            instrumenting_library_version="1.0.0",
        )
    except Exception:
        # Graceful degradation on any error
        return None


def get_rpc_meter() -> otel_metrics.Meter | None:
    """Get OpenTelemetry meter for RPC metrics.

    Returns meter from the already-configured global meter provider.
    The application must have configured OpenTelemetry before calling this.

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
    if not _HAS_OTEL:
        return None

    try:
        return otel_metrics.get_meter(
            name="pyvider.rpcplugin",
            version="1.0.0",
        )
    except Exception:
        # Graceful degradation on any error
        return None


def is_telemetry_available() -> bool:
    """Check if OpenTelemetry telemetry is available.

    Returns:
        True if OpenTelemetry SDK is installed

    Example:
        >>> if is_telemetry_available():
        ...     tracer = get_rpc_tracer()
    """
    return _HAS_OTEL


__all__ = [
    "get_rpc_meter",
    "get_rpc_tracer",
    "is_telemetry_available",
]
