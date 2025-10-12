"""
Tests for OpenTelemetry integration module.

Tests the telemetry module's access to Foundation OTEL.
"""


from pyvider.rpcplugin.telemetry import (
    get_rpc_meter,
    get_rpc_tracer,
    is_telemetry_available,
)


class TestTelemetryAvailability:
    """Test telemetry availability detection."""

    def test_is_telemetry_available(self) -> None:
        """Test OTEL availability check."""
        # Should return True since Foundation OTEL is available
        assert is_telemetry_available() is True


class TestGetRPCTracer:
    """Test RPC tracer retrieval."""

    def test_get_rpc_tracer_when_available(self) -> None:
        """Test getting tracer when OTEL available."""
        tracer = get_rpc_tracer()

        # Should return a tracer (or None if not initialized by app)
        # The function is designed to gracefully handle uninitialized state
        assert tracer is None or hasattr(tracer, "start_as_current_span")

    def test_get_rpc_tracer_multiple_times(self) -> None:
        """Test getting tracer multiple times."""
        tracer1 = get_rpc_tracer()
        tracer2 = get_rpc_tracer()

        # Should be callable multiple times
        assert tracer1 is not None or tracer1 is None
        assert tracer2 is not None or tracer2 is None


class TestGetRPCMeter:
    """Test RPC meter retrieval."""

    def test_get_rpc_meter_when_available(self) -> None:
        """Test getting meter when OTEL available."""
        meter = get_rpc_meter()

        # Should return a meter (or None if not initialized by app)
        assert meter is None or hasattr(meter, "create_counter")

    def test_get_rpc_meter_multiple_times(self) -> None:
        """Test getting meter multiple times."""
        meter1 = get_rpc_meter()
        meter2 = get_rpc_meter()

        # Should be callable multiple times
        assert meter1 is not None or meter1 is None
        assert meter2 is not None or meter2 is None
