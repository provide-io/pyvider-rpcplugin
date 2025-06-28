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
    HandshakeError, ProtocolError, RPCPluginError, SecurityError, TransportError,
)
from pyvider.telemetry import logger

async def exception_hierarchy_demo():
    """Demonstrates catching exceptions from the pyvider.rpcplugin hierarchy."""
    logger.info("⚠️  Exception Hierarchy Demo")

    exceptions_to_raise = [
        (TransportError, "Simulated network connection failed"),
        (ProtocolError, "Simulated invalid protocol message"),
        (HandshakeError, "Simulated authentication failed"),
        (SecurityError, "Simulated certificate validation failed"),
        (RPCPluginError, "Simulated generic plugin error"), # Base plugin error
    ]

    for exc_class, message in exceptions_to_raise:
        try:
            # Simulate raising an instance of the exception
            raise exc_class(message, hint=f"This is a hint for {exc_class.__name__}")
        except RPCPluginError as e: # Catches any error inheriting from RPCPluginError
            logger.info(f"🔍 Caught: {e}") # __str__ method of exception includes name, message, hint
            # You can access specific attributes too:
            # logger.info(f"   Message: {e.message}")
            # logger.info(f"   Hint: {e.hint}")
            # if isinstance(e, HandshakeError):
            #     logger.info("   This was specifically a HandshakeError.")
        except Exception: # Should not be reached if all are RPCPluginError subclasses
            logger.error("   Caught a non-RPCPluginError, which is unexpected here.")

    logger.info("✅ Exception hierarchy demo completed")

async def graceful_degradation_example():
    """Illustrates a conceptual pattern for falling back to alternative logic."""
    logger.info("🛡️  Graceful Degradation Example")

    async def attempt_primary_service():
        # Simulate an operation that might use pyvider.rpcplugin and fail
        logger.info("  Trying primary service...")
        await asyncio.sleep(0.1) # Simulate work
        raise TransportError("Primary service endpoint unreachable")

    async def fallback_service():
        logger.info("  Primary failed, trying fallback service...")
        await asyncio.sleep(0.1) # Simulate work for fallback
        return "Data from fallback service"

    final_result = None
    try:
        logger.info("🎯 Attempting primary service operation...")
        final_result = await attempt_primary_service()
    except TransportError as e: # Catch a specific, potentially recoverable error
        logger.warning(f"⚠️  Primary service attempt failed: {e.message}")
        logger.info("🔄 Falling back to secondary service logic.")
        final_result = await fallback_service()
    except RPCPluginError as e: # Catch other plugin system errors
        logger.error(f"🚫 Plugin system error, cannot proceed: {e.message}")
        final_result = "Error: Plugin system failure"
    except Exception as e: # Catch any other unexpected errors
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        final_result = "Error: Unexpected failure"

    logger.info(f"✅ Final result from operation: {final_result}")
    logger.info("✅ Graceful degradation example completed")

# The SimpleCircuitBreaker class and its usage example from ch11_error_handling_demo.py
# can also be included here to demonstrate more advanced resilience patterns.
# For brevity in this generated documentation, it's summarized.
# A circuit breaker can be useful if a plugin becomes intermittently unavailable,
# to prevent hammering it and to fail fast for a period.

async def main():
    logger.info("🚀 Error Handling Examples")
    await exception_hierarchy_demo()
    await asyncio.sleep(0.1)
    await graceful_degradation_example()
    # await circuit_breaker_example() # If including the circuit breaker demo
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
5.  **Circuit Breaker Pattern**: For services that might become temporarily overwhelmed or unavailable, consider implementing a circuit breaker pattern to fail fast and avoid further load on the struggling service. The `07_error_handling.py` example includes a conceptual `SimpleCircuitBreaker`.
6.  **User Feedback**: For client applications, translate low-level exceptions into user-friendly error messages or actions.
7.  **Health Checks**: Regularly check the health of your plugins (if they expose a health check RPC, or via the standard gRPC health service enabled by `PLUGIN_HEALTH_SERVICE_ENABLED`) to proactively detect issues.
