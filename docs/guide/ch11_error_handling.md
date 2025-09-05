# Chapter 11: Error Handling

Robust applications require diligent error handling. `pyvider.rpcplugin` is designed to provide clear and specific exceptions to help you diagnose and manage issues that can occur during plugin communication. Additionally, standard gRPC errors might be encountered during RPC calls.

## `pyvider.rpcplugin` Exception Hierarchy

The library defines a base exception, `RPCPluginError`, from which more specific exceptions inherit. This allows you to catch broad plugin-related errors or target specific failure conditions.

*   **`RPCPluginError`**: The base class for all custom exceptions raised by this library.
    *   `message: str`: Human-readable error message.
    *   `hint: str | None`: Optional hint for resolving the error.
    *   `code: int | str | None`: Optional error code.

*   **`ConfigError(RPCPluginError)`**: Raised for issues related to plugin configuration.
    *   Examples: Missing required configuration keys, invalid value formats for settings.

*   **`HandshakeError(RPCPluginError)`**: Raised for errors occurring during the initial client-server handshake process.
    *   Examples: Magic cookie mismatch, protocol version incompatibility, mTLS certificate validation failure, timeout waiting for handshake response.

*   **`ProtocolError(RPCPluginError)`**: Raised for errors related to violations of the plugin's communication protocol (distinct from gRPC errors).
    *   Examples: Malformed handshake string (if not caught as `HandshakeError`), unexpected message sequence outside of gRPC calls.

*   **`TransportError(RPCPluginError)`**: Raised for issues with the underlying network transport or communication.
    *   Examples: Connection refused, socket creation/binding errors, network timeouts during transport setup.

*   **`SecurityError(RPCPluginError)`**: Base class for security-related errors.
    *   **`CertificateError(SecurityError)`**: Specifically for errors related to SSL/TLS certificates, private keys, or credential validation (e.g., loading a malformed PEM, key mismatch).

## gRPC Errors

Once a connection is established via `RPCPluginClient.start()` and you are making calls using a gRPC stub, errors specific to the RPC call itself will typically be raised as `grpc.RpcError` (or its more specific subtype `grpc.aio.AioRpcError` when using `asyncio`).

Key attributes of `grpc.aio.AioRpcError`:
*   `code()`: Returns a `grpc.StatusCode` enum (e.g., `grpc.StatusCode.UNAVAILABLE`, `grpc.StatusCode.NOT_FOUND`).
*   `details()`: Returns a string with more details about the error.

Common `grpc.StatusCode` values to handle:
*   `UNAVAILABLE`: The service is currently unavailable (e.g., server is down, network issue). Often indicates a retryable condition.
*   `UNIMPLEMENTED`: The method called is not implemented by the server.
*   `NOT_FOUND`: A requested resource was not found.
*   `INTERNAL`: An unhandled error occurred on the server side.
*   `DEADLINE_EXCEEDED`: The call took longer than its configured timeout.
*   `PERMISSION_DENIED` / `UNAUTHENTICATED`: Authentication or authorization issues at the gRPC or service level.

## Example: Error Handling Strategies (`examples/ch11_error_handling_demo.py`)

This example demonstrates how to catch and handle various exceptions from `pyvider.rpcplugin` and provides conceptual patterns for building resilient applications.

```python
#!/usr/bin/env python3
# examples/ch11_error_handling_demo.py
import asyncio
from example_utils import configure_for_example
configure_for_example() # Basic example setup

# Import specific exceptions from the library
from pyvider.rpcplugin.exception import (
    HandshakeError,
    ProtocolError,
    RPCPluginError,
    SecurityError,
    TransportError,
)
from provide.foundation import logger
from typing import Any, Callable, Awaitable # For circuit breaker
from collections.abc import Never # For attempt_primary_service


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
        return "Fallback service response"

    result = "Not set" # Initialize result
    try:
        logger.info("🎯 Attempting primary service")
        result = await attempt_primary_service()
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
            self.last_failure_time = 0
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
```

**Best Practices for Error Handling:**

1.  **Specific First, General Later**: Catch more specific exceptions (like `HandshakeError` or `TransportError`) before broader ones (`RPCPluginError`, then `Exception`). This allows for targeted recovery logic.
2.  **Use `finally` for Cleanup**: Ensure resources like client connections (`await client.close()`) are cleaned up in `finally` blocks to prevent leaks, regardless of whether an error occurred.
3.  **Retries with Backoff**: For transient network errors (often manifesting as `TransportError` or `grpc.RpcError` with `StatusCode.UNAVAILABLE`), implement a retry mechanism with exponential backoff and jitter.
    *   The `RPCPluginClient.start()` method has built-in retry logic for the initial connection/handshake phase, configurable via `PLUGIN_CLIENT_RETRY_*` settings.
    *   For individual RPC calls after connection, you may need to implement your own retry wrapper if the specific operation is prone to transient failures and is idempotent.
4.  **Logging**: Log errors with sufficient context (e.g., using `logger.error("...", exc_info=True)` or by including relevant variables in structured logs). `pyvider.telemetry` and the custom exception `hint` attributes aid in this.
5.  **Circuit Breaker Pattern**: For services that might become temporarily overwhelmed or unavailable, consider implementing a circuit breaker pattern to fail fast and avoid further load on the struggling service. The `examples/ch11_error_handling_demo.py` script includes a `SimpleCircuitBreaker` class and its usage in `circuit_breaker_example()`.
6.  **User Feedback**: For client applications, translate low-level exceptions into user-friendly error messages or actions.
7.  **Health Checks**: Regularly check the health of your plugins (if they expose a health check RPC, or via the standard gRPC health service enabled by `PLUGIN_HEALTH_SERVICE_ENABLED`) to proactively detect issues.
