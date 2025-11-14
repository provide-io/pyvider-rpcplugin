#!/usr/bin/env python3
"""
Calculator RPC Client - Production-Quality Example

This example demonstrates:
- Client connection to plugin server
- Making RPC calls
- Error handling
- Connection lifecycle management
- Retry logic
- Structured logging
"""

import asyncio
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / "src"))

from pyvider.rpcplugin import configure, plugin_client
from pyvider.rpcplugin.exception import RPCPluginError
from pyvider.telemetry import logger


async def test_calculator_operations(client):
    """
    Test calculator operations through RPC calls.

    Note: This is a simplified example. In production, you would:
    1. Use actual protobuf-generated stubs
    2. Have proper request/response message types
    3. Handle gRPC errors with proper status codes
    """
    logger.info("🧪 Testing calculator operations...")

    # In a real implementation, you would create actual gRPC stubs:
    # from calculator_pb2_grpc import CalculatorStub
    # stub = CalculatorStub(client.grpc_channel)

    # For this demo, we're showing the pattern
    operations = [
        ("Add", 10, 5, "should be 15"),
        ("Subtract", 20, 7, "should be 13"),
        ("Multiply", 6, 7, "should be 42"),
        ("Divide", 100, 4, "should be 25"),
    ]

    for op, a, b, expected in operations:
        logger.info(
            f"📞 Calling {op}",
            operation=op,
            a=a,
            b=b,
            expected=expected
        )

    logger.info("✅ All operations would be executed via gRPC channel")
    logger.info("💡 In production, use protobuf-generated stubs with client.grpc_channel")


async def demonstrate_client_features(client):
    """Demonstrate key client features"""
    logger.info("🔍 Client Features Demonstration")
    logger.info("=" * 60)

    # Show connection info
    if client.grpc_channel:
        logger.info("✅ gRPC channel established", channel=str(client.grpc_channel))
    else:
        logger.warning("⚠️ No gRPC channel available")

    # Show transport info
    if client._transport_name:
        logger.info(f"🚇 Transport: {client._transport_name}")
    if client.target_endpoint:
        logger.info(f"📍 Connected to: {client.target_endpoint}")

    # Show protocol version
    if client._protocol_version:
        logger.info(f"🔢 Protocol version: {client._protocol_version}")

    # Test calculator operations
    await test_calculator_operations(client)

    logger.info("=" * 60)


async def main():
    """Run the calculator RPC client"""
    logger.info("=" * 60)
    logger.info("🚀 Starting Calculator RPC Client")
    logger.info("=" * 60)

    # Configure the client
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="calculator-demo-secret",
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_LOG_LEVEL="INFO",
        PLUGIN_HANDSHAKE_TIMEOUT=15.0,
        PLUGIN_CONNECTION_TIMEOUT=60.0,
        PLUGIN_CLIENT_RETRY_ENABLED=True,
        PLUGIN_CLIENT_MAX_RETRIES=3,
    )

    # Determine the server command
    server_script = Path(__file__).parent / "demo_calculator_server.py"

    if not server_script.exists():
        logger.error(f"❌ Server script not found: {server_script}")
        return 1

    server_command = [sys.executable, str(server_script)]
    logger.info(f"🎯 Will launch server: {' '.join(server_command)}")

    # Create client
    client = plugin_client(command=server_command)

    try:
        logger.info("🔌 Connecting to calculator server...")

        # Start the client (launches server and performs handshake)
        await client.start()

        logger.info("✅ Client connected successfully!")
        logger.info("=" * 60)

        # Demonstrate client features
        await demonstrate_client_features(client)

        # Keep the connection alive for a bit
        logger.info("⏱️ Keeping connection alive for 5 seconds...")
        await asyncio.sleep(5)

        # Shutdown the plugin gracefully
        logger.info("🔌 Shutting down plugin...")
        if client._controller_stub:
            try:
                await client.shutdown_plugin()
                logger.info("✅ Plugin shutdown signal sent")
            except Exception as e:
                logger.warning(f"⚠️ Could not send shutdown signal: {e}")

    except RPCPluginError as e:
        logger.error(f"❌ RPC Plugin error: {e}", exc_info=True)
        return 1
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        return 1
    finally:
        # Clean up
        if client and hasattr(client, 'is_started') and client.is_started:
            logger.info("🧹 Cleaning up client...")
            await client.close()
            logger.info("✅ Client closed")

        logger.info("=" * 60)
        logger.info("👋 Client session ended")
        logger.info("=" * 60)

    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("👋 Interrupted by user")
        sys.exit(130)
