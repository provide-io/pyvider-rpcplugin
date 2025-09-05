#!/usr/bin/env python3
"""
Custom Protocols - Custom protocol definitions and middleware patterns.
"""

import asyncio
from collections.abc import (  # For CustomProtocol
    AsyncGenerator,  # For CustomHandler & StreamData
    Callable,
)
from typing import Any

# Ensure example_utils is imported before other project modules
# that might depend on its setup
from examples import example_utils
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation import logger

example_utils.configure_for_example()


class CustomProtocol(RPCPluginProtocol):
    """Example custom protocol implementation."""

    def __init__(self, service_name: str = "CustomService") -> None:
        super().__init__()
        self.service_name = service_name
        self.middleware_factories: list[Callable[[Any], Any]] = []

    async def get_grpc_descriptors(
        self,
    ) -> tuple[Any | None, str]:
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

        logger.info(
            f"✅ {self.service_name} (with {len(self.middleware_factories)} middleware "
            f"layers, using handler {type(wrapped_handler).__name__}) would be "
            "registered with the gRPC server here."
        )

    def add_middleware(self, middleware_factory: Callable[[Any], Any]) -> None:
        """Add middleware to the protocol."""
        self.middleware_factories.append(middleware_factory)
        factory_name = (
            middleware_factory.__name__
            if hasattr(middleware_factory, "__name__")
            else str(middleware_factory)
        )
        logger.info(f"➕ Added middleware factory: {factory_name}")

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
                logger.info(
                    f"📝 [LOG] Calling: {self.next_handler.__class__.__name__}.{name}"
                )
                try:
                    result = await original_method(*args, **kwargs)
                    logger.info(f"✅ [LOG] Completed: {name}")
                    return result
                except Exception as e:
                    logger.error(f"❌ [LOG] Error in {name}: {e}")
                    raise

            return logged_method
        return original_method


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
                import time

                start_time = time.perf_counter()
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
        return original_method


class CustomHandler:
    """Example handler for custom protocol."""

    async def ProcessData(self, request: Any, context: Any) -> str:
        """Process data method."""
        await asyncio.sleep(0.1)  # Simulate processing
        return f"Processed: {request}"

    async def StreamData(self, request: Any, context: Any) -> AsyncGenerator[str]:
        """Stream data method."""
        for i in range(3):
            await asyncio.sleep(0.05)
            yield f"Stream item {i + 1}"


async def custom_protocol_example() -> None:
    """Example: Custom protocol with middleware."""
    logger.info("🔧 Custom Protocol Example")

    protocol = CustomProtocol("DataProcessingService")
    protocol.add_middleware(LoggingMiddleware)
    protocol.add_middleware(TimingMiddleware)
    handler = CustomHandler()
    await protocol.add_to_server(None, handler)
    logger.info("✅ Custom protocol example completed")


async def protocol_composition_example() -> None:
    """Example: Composing protocols."""
    logger.info("🔗 Protocol Composition Example")

    # Demonstrate applying different middleware to different services
    protocol_a = CustomProtocol("ServiceA")
    protocol_a.add_middleware(LoggingMiddleware)
    # In a real scenario, you'd use specific handlers like ServiceAHandler()
    await protocol_a.add_to_server(None, CustomHandler())

    protocol_b = CustomProtocol("ServiceB")
    # No middleware for ServiceB
    await protocol_b.add_to_server(None, CustomHandler())

    protocol_c = CustomProtocol("ServiceC")
    protocol_c.add_middleware(TimingMiddleware)
    await protocol_c.add_to_server(None, CustomHandler())

    logger.info("✅ Composed 3 protocols with varied middleware")


async def main() -> None:
    """Run custom protocol examples."""
    logger.info("🚀 Custom Protocol Examples")
    await custom_protocol_example()
    await protocol_composition_example()
    logger.info("✅ All custom protocol examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔧

# 🐍🔌📄🪄
