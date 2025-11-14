#!/usr/bin/env python3
"""
Calculator RPC Server - Production-Quality Example

This example demonstrates:
- Server setup with Unix socket transport
- Health checks and graceful shutdown
- Rate limiting
- Structured logging
- Error handling
- Signal handling (SIGTERM, SIGINT)
"""

import asyncio
import signal
import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / "src"))

import grpc
from pyvider.rpcplugin import configure, plugin_server, plugin_protocol
from pyvider.telemetry import logger


class CalculatorHandler:
    """
    Calculator service handler implementing basic arithmetic operations.

    In production, this would be backed by your actual business logic.
    """

    def __init__(self):
        self.request_count = 0
        logger.info("🧮 CalculatorHandler initialized")

    async def Add(self, request, context):
        """Add two numbers"""
        self.request_count += 1
        a = getattr(request, 'a', 0)
        b = getattr(request, 'b', 0)
        result = a + b

        logger.info(
            "➕ Add operation",
            a=a,
            b=b,
            result=result,
            request_count=self.request_count
        )

        # Return a simple dict (in real gRPC, this would be a protobuf message)
        return type('Response', (), {'result': result})()

    async def Subtract(self, request, context):
        """Subtract two numbers"""
        self.request_count += 1
        a = getattr(request, 'a', 0)
        b = getattr(request, 'b', 0)
        result = a - b

        logger.info(
            "➖ Subtract operation",
            a=a,
            b=b,
            result=result,
            request_count=self.request_count
        )

        return type('Response', (), {'result': result})()

    async def Multiply(self, request, context):
        """Multiply two numbers"""
        self.request_count += 1
        a = getattr(request, 'a', 0)
        b = getattr(request, 'b', 0)
        result = a * b

        logger.info(
            "✖️ Multiply operation",
            a=a,
            b=b,
            result=result,
            request_count=self.request_count
        )

        return type('Response', (), {'result': result})()

    async def Divide(self, request, context):
        """Divide two numbers with error handling"""
        self.request_count += 1
        a = getattr(request, 'a', 0)
        b = getattr(request, 'b', 0)

        if b == 0:
            logger.warning("⚠️ Division by zero attempted", a=a, b=b)
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "Cannot divide by zero"
            )

        result = a / b

        logger.info(
            "➗ Divide operation",
            a=a,
            b=b,
            result=result,
            request_count=self.request_count
        )

        return type('Response', (), {'result': result})()

    async def GetStats(self, request, context):
        """Get server statistics"""
        logger.info("📊 Stats requested", total_requests=self.request_count)
        return type('Stats', (), {
            'total_requests': self.request_count,
            'status': 'healthy'
        })()


async def main():
    """Run the calculator RPC server"""
    logger.info("=" * 60)
    logger.info("🚀 Starting Calculator RPC Server")
    logger.info("=" * 60)

    # Configure the RPC plugin
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="calculator-demo-secret",
        PLUGIN_AUTO_MTLS=False,  # Disable mTLS for demo simplicity
        PLUGIN_LOG_LEVEL="INFO",
        PLUGIN_HANDSHAKE_TIMEOUT=15.0,
        PLUGIN_CONNECTION_TIMEOUT=60.0,
        PLUGIN_RATE_LIMIT_ENABLED=True,
        PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0,
        PLUGIN_RATE_LIMIT_BURST_CAPACITY=200,
        PLUGIN_HEALTH_SERVICE_ENABLED=True,
    )

    logger.info("⚙️ Configuration complete")

    # Create protocol and handler
    protocol = plugin_protocol()
    handler = CalculatorHandler()

    # Create server with Unix socket transport
    socket_path = "/tmp/calculator-rpc.sock"
    logger.info(f"📍 Server will listen on: {socket_path}")

    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",
        transport_path=socket_path
    )

    logger.info("✅ Server created successfully")
    logger.info("=" * 60)
    logger.info("📡 Server is ready to accept connections")
    logger.info("💡 Use Ctrl+C to stop the server gracefully")
    logger.info("=" * 60)

    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"🛑 Received signal {signum}, initiating graceful shutdown...")
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Start the server (this will block until shutdown)
        await server.serve()
    except KeyboardInterrupt:
        logger.info("🛑 Shutdown signal received")
    except Exception as e:
        logger.error("❌ Server error", error=str(e), exc_info=True)
    finally:
        logger.info("👋 Server stopped")
        logger.info("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Goodbye!")
