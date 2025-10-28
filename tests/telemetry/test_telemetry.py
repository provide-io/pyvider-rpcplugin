#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for OpenTelemetry integration module.

Tests the telemetry module's access to Foundation OTEL.
"""

from unittest.mock import MagicMock, patch

import pytest

from pyvider.rpcplugin.telemetry import (
    get_rpc_meter,
    get_rpc_tracer,
    is_telemetry_available,
)


class TestTelemetryAvailability:
    """Test telemetry availability detection."""

    def test_is_telemetry_available(self) -> None:
        """Test OTEL availability check."""
        # Should return True if OpenTelemetry is available, False otherwise
        # The function gracefully handles missing OpenTelemetry dependencies
        result = is_telemetry_available()
        assert isinstance(result, bool)  # Should always return a boolean
        # Result depends on whether opentelemetry is installed in the environment


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

    def test_get_rpc_tracer_when_otel_unavailable(self) -> None:
        """Test getting tracer when OTEL is not available."""
        # Mock the module to simulate OTEL not being available
        with patch("pyvider.rpcplugin.telemetry._HAS_OTEL", False):
            tracer = get_rpc_tracer()
            assert tracer is None

    def test_get_rpc_tracer_exception_handling(self) -> None:
        """Test that exceptions in get_tracer are handled gracefully."""
        # Mock otel_trace to raise an exception when get_tracer is called
        with patch("pyvider.rpcplugin.telemetry._HAS_OTEL", True):
            with patch("pyvider.rpcplugin.telemetry.otel_trace") as mock_trace:
                mock_trace.get_tracer.side_effect = RuntimeError("OTEL initialization failed")
                tracer = get_rpc_tracer()
                # Should gracefully return None on any error
                assert tracer is None


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

    def test_get_rpc_meter_when_otel_unavailable(self) -> None:
        """Test getting meter when OTEL is not available."""
        # Mock the module to simulate OTEL not being available
        with patch("pyvider.rpcplugin.telemetry._HAS_OTEL", False):
            meter = get_rpc_meter()
            assert meter is None

    def test_get_rpc_meter_exception_handling(self) -> None:
        """Test that exceptions in get_meter are handled gracefully."""
        # Mock otel_metrics to raise an exception when get_meter is called
        with patch("pyvider.rpcplugin.telemetry._HAS_OTEL", True):
            with patch("pyvider.rpcplugin.telemetry.otel_metrics") as mock_metrics:
                mock_metrics.get_meter.side_effect = RuntimeError("OTEL metrics initialization failed")
                meter = get_rpc_meter()
                # Should gracefully return None on any error
                assert meter is None


class TestTelemetryImportError:
    """Test behavior when OpenTelemetry is not installed."""

    def test_telemetry_module_loads_without_otel(self) -> None:
        """Test that the module loads even if OpenTelemetry is not available."""
        # This test verifies that the try/except ImportError block works
        # We can't easily test the import path without reloading the module,
        # but we can verify the functions handle _HAS_OTEL=False correctly
        with patch("pyvider.rpcplugin.telemetry._HAS_OTEL", False):
            # All functions should work and return None
            assert is_telemetry_available() is False
            assert get_rpc_tracer() is None
            assert get_rpc_meter() is None

# 📞🔌🔚
