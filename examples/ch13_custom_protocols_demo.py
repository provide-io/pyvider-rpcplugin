#!/usr/bin/env python3
"""
Custom Protocols - Custom protocol definitions and middleware patterns.
"""

import asyncio
from typing import Any

from examples.example_utils import configure_for_example # noqa: E402

configure_for_example()

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol # noqa: E402
from pyvider.telemetry import logger # noqa: E402
# Changed Tuple to tuple for type hint consistency
from typing import Any, Callable, Awaitable, List, Tuple as TypingTuple # For CustomProtocol
from collections.abc import AsyncGenerator # For CustomHandler & StreamData


class CustomProtocol(RPCPluginProtocol):
    """Example custom protocol implementation."""

    def __init__(self, service_name: str = "CustomService") -> None:
        super().__init__()
        self.service_name = service_name
        self.middleware_factories: List[Callable[[Any], Any]] = []

    async def get_grpc_descriptors(self) -> TypingTuple[Any | None, str]: # Use aliased Tuple
        """Get gRPC service descriptors."""
        logger.info(f"🔌 Getting descriptors for {self.service_name}")
        return None, self.service_name

    async def add_to_server(self, server: Any, handler: Any) -> None:
        """
        In a real scenario, 'server' is grpc.aio.Server.
        'handler' is your gRPC servicer instance.
        This method would call generated add_Servicer_to_server functions.
        """
        logger.info(f"🔧 Registering {self.service_name} to gRPC server.")

        # Conceptually apply middleware to the handler before registration
        wrapped_handler = self._apply_middleware(handler)

        # Placeholder for actual gRPC registration:
        # your_service_pb2_grpc.add_YourServiceServicer_to_server(wrapped_handler, server)
        logger.info(
            f"✅ {self.service_name} (with {len(self.middleware_factories)} middleware "
            f"layers, using handler {type(wrapped_handler).__name__}) would be "
            "registered with the gRPC server here."
        )

    def add_middleware(self, middleware_factory: Callable[[Any], Any]) -> None:
        """Add middleware to the protocol."""
        self.middleware_factories.append(middleware_factory)
        logger.info(f"➕ Added middleware factory: {middleware_factory.__name__ if hasattr(middleware_factory, '__name__') else middleware_factory}")

    def _apply_middleware(self, handler: Any) -> Any:
        """Apply middleware stack to handler."""
        wrapped_handler = handler
        for factory in reversed(self.middleware_factories):
            wrapped_handler = factory(wrapped_handler)
        return wrapped_handler


class LoggingMiddleware:
    """Example logging middleware."""

    def __init__(self, next_handler: Any) -> None:
        self.next_handler = next_handler
        logger.info("LoggingMiddleware initialized.")

    async def __getattr__(self, name: str) -> Any:
        """Intercept method calls for logging."""
        original_method = getattr(self.next_handler, name)
        if callable(original_method) and asyncio.iscoroutinefunction(original_method):
            async def logged_method(*args: Any, **kwargs: Any) -> Any:
                logger.info(f"📝 [LOG] Calling: {self.next_handler.__class__.__name__}.{name}")
                try:
                    result = await original_method(*args, **kwargs)
                    logger.info(f"✅ [LOG] Completed: {name}")
                    return result
                except Exception as e:
                    logger.error(f"❌ [LOG] Error in {name}: {e}")
                    raise
            return logged_method
        return original_method # Return original if not callable async method


class TimingMiddleware:
    """Example timing middleware."""

    def __init__(self, next_handler: Any) -> None:
        self.next_handler = next_handler
        logger.info("TimingMiddleware initialized.")

    async def __getattr__(self, name: str) -> Any:
        """Intercept method calls for timing."""
        original_method = getattr(self.next_handler, name)
        if callable(original_method) and asyncio.iscoroutinefunction(original_method):
            async def timed_method(*args: Any, **kwargs: Any) -> Any:
                import time # Moved import inside method as it's only used here

                start_time = time.perf_counter() # Use perf_counter for more precision
                try:
                    result = await original_method(*args, **kwargs)
                    duration = time.perf_counter() - start_time
                    logger.info(f"⏱️  [TIMING] {name} took {duration:.4f}s")
                    return result
                except Exception as e:
                    duration = time.perf_counter() - start_time
                    logger.error(
                        f"⏱️  [TIMING] {name} failed after {duration:.4f}s: {e}"
                    )
                    raise
            return timed_method
        return original_method # Return original if not callable async method


class CustomHandler:
    """Example handler for custom protocol."""

    async def ProcessData(self, request: Any, context: Any) -> str:
        """Process data method."""
        await asyncio.sleep(0.1)  # Simulate processing
        return f"Processed: {request}"

    async def StreamData(self, request: Any, context: Any) -> AsyncGenerator[str, None]:
        """Stream data method."""
        for i in range(3):
            await asyncio.sleep(0.05)
            yield f"Stream item {i + 1}"


async def custom_protocol_example() -> None:
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


async def protocol_composition_example() -> None:
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


async def main() -> None:
    """Run custom protocol examples."""
    logger.info("🚀 Custom Protocol Examples")

    await custom_protocol_example()
    await protocol_composition_example()

    logger.info("✅ All custom protocol examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔧
