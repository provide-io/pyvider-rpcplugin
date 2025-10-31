#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""OpenTelemetry Telemetry Demo

This example demonstrates the CORRECT OpenTelemetry pattern for libraries:
- APPLICATION configures OpenTelemetry (sets service.name)
- LIBRARY just accesses tracer (gets instrumentation.library.name attribution)

Key Concepts:
1. Application sets service.name (e.g., "demo-app")
2. Library gets tracer with instrumentation.library.name ("pyvider.rpcplugin")
3. All traces appear under application's service with proper library attribution
4. No observability fragmentation!

Traces are automatically created for:
- rpc.handshake.validate_cookie
- rpc.handshake.build_response
- rpc.handshake.parse_response
- rpc.client.create_channel
- rpc.server.serve

Usage:
    # Console traces (default)
    python examples/telemetry_demo.py

    # With OpenObserve/OTLP export
    export PLUGIN_OTEL_ENDPOINT=http://localhost:5080/api/default
    export OPENOBSERVE_USER=tim@provide.io
    export OPENOBSERVE_PASSWORD=password
    python examples/telemetry_demo.py"""

import asyncio
import os
import sys

from provide.foundation import logger

# Add src to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import contextlib

from pyvider.rpcplugin import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerServicer
from pyvider.rpcplugin.telemetry import get_rpc_tracer, is_telemetry_available


# Simple echo protocol for demo
class DemoProtocol(RPCPluginProtocol):
    """Simple protocol for telemetry demo."""

    def create_server(self) -> tuple:
        """Create gRPC server and handler."""
        import grpc.aio

        server = grpc.aio.server()
        handler = DemoHandler()
        return server, handler

    def add_to_server(self, server, handler) -> None:
        """Add service to server."""
        from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import (
            add_GRPCControllerServicer_to_server,
        )

        add_GRPCControllerServicer_to_server(handler, server)

    def get_grpc_descriptors(self):
        """Get gRPC service descriptors."""
        from pyvider.rpcplugin.protocol import grpc_controller_pb2

        return [grpc_controller_pb2.DESCRIPTOR.services_by_name["GRPCController"]]


class DemoHandler(GRPCControllerServicer):
    """Simple handler for demo."""

    async def Shutdown(self, request, context):
        """Handle shutdown."""
        from google.protobuf.empty_pb2 import Empty

        logger.info("Shutdown request received")
        return Empty()


async def run_demo() -> None:
    """Run the telemetry demo."""
    print("\n" + "=" * 70)
    print("🔭 OpenTelemetry Telemetry Demo for pyvider-rpcplugin")
    print("=" * 70 + "\n")

    # Check if telemetry is available
    if not is_telemetry_available():
        print("⚠️  OpenTelemetry not available. Install with:")
        print("   pip install 'provide-foundation[opentelemetry]'\n")
        return

    # Application configures OpenTelemetry (library just accesses it)
    print("📊 Setting up OpenTelemetry (application-level)...")

    # Import Foundation's telemetry configuration
    from provide.foundation.logger.config.telemetry import TelemetryConfig
    from provide.foundation.tracer.otel import setup_opentelemetry_tracing

    # Application sets service name, not the library!
    telemetry_config = TelemetryConfig(
        tracing_enabled=True,
        otlp_endpoint=os.getenv("PLUGIN_OTEL_ENDPOINT", "http://localhost:4317"),
        otlp_protocol=os.getenv("PLUGIN_OTEL_PROTOCOL", "grpc"),
    )

    print(f"   Service Name: {telemetry_config.service_name} (application)")
    print(f"   Traces Enabled: {telemetry_config.tracing_enabled}")
    print(f"   OTLP Endpoint: {telemetry_config.otlp_endpoint}")
    print()

    # Application initializes OpenTelemetry
    setup_opentelemetry_tracing(telemetry_config)

    # Library gets tracer from app's configuration
    tracer = get_rpc_tracer()
    if tracer:
        print("✅ Tracer initialized and ready")
    else:
        print("⚠️  Tracer not available")
    print()

    # Create protocol and server
    protocol = DemoProtocol()
    server = RPCPluginServer(
        protocol=protocol,
        handler=DemoHandler(),
        config={
            "PLUGIN_MAGIC_COOKIE_KEY": "DEMO_COOKIE",
            "PLUGIN_MAGIC_COOKIE_VALUE": "demo123",
        },
    )

    # Start server in background
    print("🚀 Starting server with telemetry instrumentation...")
    server_task = asyncio.create_task(server.serve())

    # Wait for server to be ready
    try:
        await server.wait_for_server_ready(timeout=5.0)
    except Exception as e:
        print(f"❌ Server startup failed: {e}")
        server_task.cancel()
        return

    print("📡 Traces are being captured for:")
    print("   - rpc.server.serve (server startup)")
    print("   - rpc.handshake.build_response (handshake building)")
    print("   - rpc.handshake.validate_cookie (cookie validation)")
    print()

    # Simulate some operations
    print("⏱️  Running for 2 seconds to collect traces...")
    await asyncio.sleep(2)

    # Shutdown
    print("\n🛑 Shutting down server...")
    await server.stop()

    # Wait for server task to complete
    try:
        await asyncio.wait_for(server_task, timeout=2.0)
    except TimeoutError:
        server_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await server_task

    print("\n" + "=" * 70)
    print("✨ Demo Complete!")
    print("=" * 70)
    print("\n📝 Key Takeaways:")
    print("   • APPLICATION configures OpenTelemetry (service.name='demo-app')")
    print("   • LIBRARY just accesses tracer (instrumentation.library.name='pyvider.rpcplugin')")
    print("   • All traces appear under 'demo-app' with proper library attribution")
    print()
    print("📝 To export traces to OpenObserve, set environment variables:")
    print("   export PLUGIN_OTEL_ENDPOINT=http://localhost:5080/api/default")
    print("   export OPENOBSERVE_USER=tim@provide.io")
    print("   export OPENOBSERVE_PASSWORD=password")
    print()
    print("🔍 Check your observability backend for:")
    print("   • service.name = 'demo-app' (application identity)")
    print("   • instrumentation.library.name = 'pyvider.rpcplugin' (library attribution)\n")


if __name__ == "__main__":
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Demo failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

# 🔌📞🔚
