#!/usr/bin/env python3
"""
Custom Protocols - Custom protocol definitions and middleware patterns.
"""

import asyncio
from typing import Any

from example_utils import configure_for_example

configure_for_example()

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.telemetry import logger


class CustomProtocol(RPCPluginProtocol):
    """Example custom protocol implementation."""

    def __init__(self, service_name: str = "CustomService"):
        super().__init__()
        self.service_name = service_name
        self.middleware_stack: list[Any] = []

    async def get_grpc_descriptors(self):
        """Get gRPC service descriptors."""
        logger.info(f"🔌 Getting descriptors for {self.service_name}")
        return None, self.service_name

    def get_method_type(self, method_name: str) -> str:
        """Determine RPC method type."""
        method_types = {
            "ProcessData": "unary_unary",
            "StreamData": "unary_stream",
            "UploadData": "stream_unary",
            "BidirectionalStream": "stream_stream",
        }
        return method_types.get(method_name, "unary_unary")

    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Add service to gRPC server with middleware."""
        logger.info(f"🔧 Registering {self.service_name} with middleware")

        # Apply middleware to handler
        wrapped_handler = self._apply_middleware(handler)

        # In real implementation, would register with actual gRPC server
        logger.info(
            f"✅ {self.service_name} registered with {len(self.middleware_stack)} middleware"
        )

    def add_middleware(self, middleware):
        """Add middleware to the protocol."""
        self.middleware_stack.append(middleware)
        logger.info(f"➕ Added middleware: {middleware.__class__.__name__}")

    def _apply_middleware(self, handler):
        """Apply middleware stack to handler."""
        wrapped = handler
        for middleware in reversed(self.middleware_stack):
            wrapped = middleware(wrapped)
        return wrapped


class LoggingMiddleware:
    """Example logging middleware."""

    def __init__(self, handler):
        self.handler = handler

    async def __getattr__(self, name):
        """Intercept method calls for logging."""
        if hasattr(self.handler, name):
            original_method = getattr(self.handler, name)

            async def logged_method(*args, **kwargs):
                logger.info(f"📝 [LOG] Calling {name}")
                try:
                    result = await original_method(*args, **kwargs)
                    logger.info(f"✅ [LOG] {name} completed successfully")
                    return result
                except Exception as e:
                    logger.error(f"❌ [LOG] {name} failed: {e}")
                    raise

            return logged_method
        raise AttributeError(
            f"'{self.handler.__class__.__name__}' has no attribute '{name}'"
        )


class TimingMiddleware:
    """Example timing middleware."""

    def __init__(self, handler):
        self.handler = handler

    async def __getattr__(self, name):
        """Intercept method calls for timing."""
        if hasattr(self.handler, name):
            original_method = getattr(self.handler, name)

            async def timed_method(*args, **kwargs):
                import time

                start_time = time.time()
                try:
                    result = await original_method(*args, **kwargs)
                    duration = time.time() - start_time
                    logger.info(f"⏱️  [TIMING] {name} took {duration:.3f}s")
                    return result
                except Exception as e:
                    duration = time.time() - start_time
                    logger.error(
                        f"⏱️  [TIMING] {name} failed after {duration:.3f}s: {e}"
                    )
                    raise

            return timed_method
        raise AttributeError(
            f"'{self.handler.__class__.__name__}' has no attribute '{name}'"
        )


class CustomHandler:
    """Example handler for custom protocol."""

    async def ProcessData(self, request, context):
        """Process data method."""
        await asyncio.sleep(0.1)  # Simulate processing
        return f"Processed: {request}"

    async def StreamData(self, request, context):
        """Stream data method."""
        for i in range(3):
            await asyncio.sleep(0.05)
            yield f"Stream item {i + 1}"


async def custom_protocol_example():
    """Example: Custom protocol with middleware."""
    logger.info("🔧 Custom Protocol Example")

    # Create custom protocol
    protocol = CustomProtocol("DataProcessingService")

    # Add middleware
    protocol.add_middleware(LoggingMiddleware)
    protocol.add_middleware(TimingMiddleware)

    # Create handler
    handler = CustomHandler()

    # Simulate protocol registration
    await protocol.add_to_server(None, handler)

    logger.info("✅ Custom protocol example completed")


async def protocol_composition_example():
    """Example: Composing protocols."""
    logger.info("🔗 Protocol Composition Example")

    protocols = [
        CustomProtocol("ServiceA"),
        CustomProtocol("ServiceB"),
        CustomProtocol("ServiceC"),
    ]

    for protocol in protocols:
        protocol.add_middleware(LoggingMiddleware)
        await protocol.add_to_server(None, CustomHandler())

    logger.info(f"✅ Composed {len(protocols)} protocols")


async def main():
    """Run custom protocol examples."""
    logger.info("🚀 Custom Protocol Examples")

    await custom_protocol_example()
    await protocol_composition_example()

    logger.info("✅ All custom protocol examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔧
