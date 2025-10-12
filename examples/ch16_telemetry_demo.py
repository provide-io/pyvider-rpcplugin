#!/usr/bin/env python3
"""
Chapter 16: OpenTelemetry Telemetry Demo

This example demonstrates the OpenTelemetry integration in pyvider-rpcplugin.
It shows how to:
1. Enable telemetry with correct service_name
2. Capture distributed traces for RPC operations
3. Export traces to console or OTLP collector

Traces are automatically created for:
- rpc.handshake.validate_cookie
- rpc.handshake.build_response
- rpc.handshake.parse_response
- rpc.client.create_channel
- rpc.server.serve

Usage:
    # Console traces (default)
    python examples/ch16_telemetry_demo.py

    # With OpenObserve/OTLP export
    export PLUGIN_TELEMETRY_ENABLED=true
    export PLUGIN_OTEL_TRACES_ENABLED=true
    export PLUGIN_OTEL_ENDPOINT=http://localhost:5080/api/default
    python examples/ch16_telemetry_demo.py
"""

import asyncio
import os
import sys

from provide.foundation import logger

# Add src to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import contextlib

from pyvider.rpcplugin import RPCPluginServer
from pyvider.rpcplugin.config import RPCPluginConfig
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerServicer
from pyvider.rpcplugin.telemetry import is_telemetry_available, setup_rpc_telemetry


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

    # Setup telemetry configuration
    config = RPCPluginConfig(
        plugin_telemetry_enabled=True,
        plugin_telemetry_service_name="pyvider.rpcplugin",  # Using dot notation
        plugin_otel_traces_enabled=True,
        plugin_otel_metrics_enabled=False,
        plugin_otel_endpoint=os.getenv("PLUGIN_OTEL_ENDPOINT"),
        plugin_otel_protocol=os.getenv("PLUGIN_OTEL_PROTOCOL", "grpc"),
    )

    # Initialize telemetry
    print("📊 Initializing telemetry...")
    print(f"   Service Name: {config.plugin_telemetry_service_name}")
    print(f"   Traces Enabled: {config.plugin_otel_traces_enabled}")
    print(f"   OTLP Endpoint: {config.plugin_otel_endpoint or 'console (default)'}")
    print()

    setup_rpc_telemetry(config)

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
        print("✅ Server ready\n")
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
    print("\n📝 To export traces to OpenObserve, set environment variables:")
    print("   export PLUGIN_TELEMETRY_ENABLED=true")
    print("   export PLUGIN_OTEL_TRACES_ENABLED=true")
    print("   export PLUGIN_OTEL_ENDPOINT=http://localhost:5080/api/default")
    print("   export OPENOBSERVE_USER=tim@provide.io")
    print("   export OPENOBSERVE_PASSWORD=password")
    print("\n🔍 Check your observability backend for traces with service.name='pyvider.rpcplugin'\n")


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
