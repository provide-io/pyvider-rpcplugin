#!/usr/bin/env python3
"""
Error Handling - Robust error management patterns.
"""

import asyncio
from collections.abc import (  # For circuit breaker and attempt_primary_service
    Awaitable,
    Callable,
)
from typing import (
    Any,
    Never,
)

from example_utils import configure_for_example  # type: ignore[import-not-found]
from provide.foundation import logger

from pyvider.rpcplugin.exception import (
    HandshakeError,
    ProtocolError,
    RPCPluginError,
    SecurityError,
    TransportError,
)

configure_for_example()


async def exception_hierarchy_demo() -> None:
    """Demonstrate the exception hierarchy."""
    logger.info("⚠️  Exception Hierarchy Demo")

    exceptions = [
        (TransportError, "Network connection failed"),
        (ProtocolError, "Invalid protocol message"),
        (HandshakeError, "Authentication failed"),
        (SecurityError, "Certificate validation failed"),
        (RPCPluginError, "Generic plugin error"),
    ]

    for exc_class, message in exceptions:
        try:
            raise exc_class(message, hint=f"Check {exc_class.__name__} documentation")
        except RPCPluginError as e:
            logger.info(f"🔍 Caught: {e}")

    logger.info("✅ Exception hierarchy demo completed")


async def graceful_degradation_example() -> None:
    """Example: Graceful degradation patterns."""
    logger.info("🛡️  Graceful Degradation Example")

    async def attempt_primary_service() -> Never:
        """Simulate primary service failure."""
        raise TransportError("Primary service unavailable")

    async def fallback_service() -> str:
        """Simulate fallback service."""
        await asyncio.sleep(0.1)
        return "Fallback service response"

    result: str  # Explicit type annotation
    try:
        logger.info("🎯 Attempting primary service")
        result = await attempt_primary_service()  # This line won't be reached due to Never
    except TransportError as e:
        logger.warning(f"⚠️  Primary service failed: {e}")
        logger.info("🔄 Falling back to secondary service")
        result = await fallback_service()

    logger.info(f"✅ Final result: {result}")
    logger.info("✅ Graceful degradation example completed")


async def circuit_breaker_example() -> None:
    """Example: Circuit breaker pattern."""
    logger.info("🔌 Circuit Breaker Example")

    class SimpleCircuitBreaker:
        def __init__(self, failure_threshold: int = 3, recovery_timeout: int = 5) -> None:
            self.failure_threshold = failure_threshold
            self.recovery_timeout = recovery_timeout
            self.failure_count = 0
            self.last_failure_time: float = 0.0  # Explicit type annotation
            self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

        async def call(self, func: Callable[[], Awaitable[Any]]) -> Any:
            """Execute function with circuit breaker protection."""
            current_time = asyncio.get_event_loop().time()

            if self.state == "OPEN":
                if current_time - self.last_failure_time >= self.recovery_timeout:
                    self.state = "HALF_OPEN"
                    logger.info("🔄 Circuit breaker: HALF_OPEN")
                else:
                    raise TransportError("Circuit breaker is OPEN")

            try:
                result = await func()
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
                    self.failure_count = 0
                    logger.info("✅ Circuit breaker: CLOSED")
                return result
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = current_time

                if self.failure_count >= self.failure_threshold:
                    self.state = "OPEN"
                    logger.warning("🚫 Circuit breaker: OPEN")
                raise e

    async def unreliable_service() -> str:
        """Simulate unreliable service."""
        import random

        if random.random() < 0.7:  # nosec B311 # 70% failure rate
            raise TransportError("Service failure")
        return "Service success"

    circuit_breaker = SimpleCircuitBreaker()

    # Test circuit breaker
    for i in range(10):
        try:
            result = await circuit_breaker.call(unreliable_service)
            logger.info(f"✅ Call {i + 1}: {result}")
        except TransportError as e:
            logger.warning(f"⚠️  Call {i + 1}: {e}")

        await asyncio.sleep(0.1)

    logger.info("✅ Circuit breaker example completed")


async def main() -> None:
    """Run error handling examples."""
    logger.info("🚀 Error Handling Examples")

    await exception_hierarchy_demo()
    await graceful_degradation_example()
    await circuit_breaker_example()

    logger.info("✅ All error handling examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍⚠️

# 🐍🔌📄🪄
