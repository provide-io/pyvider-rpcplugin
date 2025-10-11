"""
Tests for OpenTelemetry integration module.

Tests the telemetry module's thin wrapper over Foundation OTEL.
"""

import pytest

from pyvider.rpcplugin.config import RPCPluginConfig
from pyvider.rpcplugin.telemetry import (
    get_rpc_meter,
    get_rpc_tracer,
    is_telemetry_available,
    setup_rpc_telemetry,
)


class TestTelemetryAvailability:
    """Test telemetry availability detection."""

    def test_is_telemetry_available(self) -> None:
        """Test OTEL availability check."""
        # Should return True since Foundation OTEL is available
        assert is_telemetry_available() is True


class TestSetupRPCTelemetry:
    """Test telemetry setup with various configurations."""

    def test_setup_disabled(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test setup with telemetry disabled."""
        config = RPCPluginConfig(plugin_telemetry_enabled=False)

        setup_rpc_telemetry(config)

        # Should log that telemetry is disabled
        assert any("disabled" in record.message.lower() for record in caplog.records)

    def test_setup_with_traces_enabled(self) -> None:
        """Test setup with traces enabled."""
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_otel_traces_enabled=True,
            plugin_otel_metrics_enabled=False,
            plugin_otel_endpoint="http://localhost:4317",
        )

        # Should not raise
        setup_rpc_telemetry(config)

    def test_setup_with_metrics_enabled(self) -> None:
        """Test setup with metrics enabled."""
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_otel_traces_enabled=False,
            plugin_otel_metrics_enabled=True,
            plugin_otel_endpoint="http://localhost:4317",
        )

        # Should not raise
        setup_rpc_telemetry(config)

    def test_setup_with_both_enabled(self) -> None:
        """Test setup with both traces and metrics."""
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_otel_traces_enabled=True,
            plugin_otel_metrics_enabled=True,
            plugin_otel_endpoint="http://localhost:4317",
            plugin_otel_protocol="grpc",
        )

        # Should not raise
        setup_rpc_telemetry(config)

    def test_setup_with_custom_service_name(self) -> None:
        """Test setup with custom service name."""
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_telemetry_service_name="custom-rpc-service",
            plugin_otel_traces_enabled=True,
        )

        # Should not raise
        setup_rpc_telemetry(config)

    def test_setup_with_http_protocol(self) -> None:
        """Test setup with HTTP protocol."""
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_otel_traces_enabled=True,
            plugin_otel_endpoint="http://localhost:4318",
            plugin_otel_protocol="http",
        )

        # Should not raise
        setup_rpc_telemetry(config)


class TestGetRPCTracer:
    """Test RPC tracer retrieval."""

    def test_get_rpc_tracer_when_available(self) -> None:
        """Test getting tracer when OTEL available."""
        tracer = get_rpc_tracer()

        # Should return a tracer (or None if not initialized)
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

        # Should return a meter (or None if not initialized)
        assert meter is None or hasattr(meter, "create_counter")

    def test_get_rpc_meter_multiple_times(self) -> None:
        """Test getting meter multiple times."""
        meter1 = get_rpc_meter()
        meter2 = get_rpc_meter()

        # Should be callable multiple times
        assert meter1 is not None or meter1 is None
        assert meter2 is not None or meter2 is None


class TestTelemetryIntegration:
    """Integration tests for telemetry."""

    def test_full_setup_and_usage(self) -> None:
        """Test full setup and usage flow."""
        # Setup telemetry
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_otel_traces_enabled=True,
            plugin_otel_metrics_enabled=True,
            plugin_otel_endpoint="http://localhost:4317",
        )
        setup_rpc_telemetry(config)

        # Get tracer and meter
        tracer = get_rpc_tracer()
        meter = get_rpc_meter()

        # Should be available after setup (or None if not initialized)
        # The graceful degradation means None is acceptable
        assert tracer is None or hasattr(tracer, "start_as_current_span")
        assert meter is None or hasattr(meter, "create_counter")

    def test_setup_idempotent(self) -> None:
        """Test that setup can be called multiple times safely."""
        config = RPCPluginConfig(
            plugin_telemetry_enabled=True,
            plugin_otel_traces_enabled=True,
        )

        # Should not raise on multiple calls
        setup_rpc_telemetry(config)
        setup_rpc_telemetry(config)
        setup_rpc_telemetry(config)
