# Connection Resilience

Build robust, fault-tolerant plugin clients with comprehensive error handling, retry strategies, health monitoring, and connection management patterns.

## Overview

Production plugin systems require resilience against transient failures - network hiccups, server restarts, temporary overload, and other recoverable errors common in distributed systems.

### Key Capabilities

- **Error Handling** - Structured exception hierarchy with helpful context
- **Retry Logic** - Exponential backoff, jitter, circuit breakers
- **Connection Management** - Health monitoring, reconnection strategies
- **Graceful Degradation** - Fallback strategies when services unavailable

## Exception Handling

=== "Exception Hierarchy"

    All plugin-related exceptions inherit from the base `RPCPluginError`:

    ```python
    from pyvider.rpcplugin.exception import (
        RPCPluginError,      # Base exception
        TransportError,      # Network/transport issues
        HandshakeError,      # Connection establishment failures
        ProtocolError,       # Protocol violations
        SecurityError,       # Authentication/encryption issues
        ConfigError,         # Configuration problems
    )
    ```

    Each exception provides helpful context:

    ```python
    try:
        await client.start()
    except RPCPluginError as e:
        print(f"Error: {e.message}")     # Human-readable description
        print(f"Hint: {e.hint}")         # Resolution suggestion
        print(f"Code: {e.code}")         # Optional error code
    ```

=== "Transport Errors"

    **When it occurs:** Network connection issues, socket errors, transport setup failures

    **Common scenarios:**
    - Plugin process fails to start
    - Network connectivity problems
    - Port conflicts or binding issues
    - Unix socket permission problems

    ```python
    try:
        async with plugin_client(command=["python", "my_plugin.py"]) as client:
            await client.start()
    except TransportError as e:
        logger.error(f"❌ Connection failed: {e.message}")
        if "port" in str(e).lower():
            logger.info("Hint: Use port=0 for auto-assignment")
        elif "permission" in str(e).lower():
            logger.info("Hint: Fix socket permissions or use different path")
    ```

=== "Handshake Errors"

    **When it occurs:** Authentication and protocol negotiation failures

    **Common scenarios:**
    - Magic cookie mismatch
    - Protocol version incompatibility
    - mTLS certificate validation failures
    - Handshake timeout

    ```python
    try:
        await client.start()
    except HandshakeError as e:
        logger.error(f"🤝 Handshake failed: {e.message}")
        if "magic cookie" in str(e).lower():
            cookie_key = rpcplugin_config.plugin_magic_cookie_key
            logger.error(f"Expected cookie key: {cookie_key}")
        elif "certificate" in str(e).lower():
            logger.error("Check certificate paths and validity")
    ```

=== "Protocol Errors"

    **When it occurs:** Invalid RPC calls, malformed messages, protocol violations

    ```python
    from grpc import StatusCode
    import grpc

    try:
        result = await stub.Calculate(invalid_request)
    except grpc.aio.AioRpcError as e:
        if e.code() == StatusCode.INVALID_ARGUMENT:
            logger.error(f"Invalid request: {e.details()}")
        elif e.code() == StatusCode.UNIMPLEMENTED:
            logger.error(f"Method not implemented: {e.details()}")
        elif e.code() == StatusCode.UNAVAILABLE:
            logger.warning("Service temporarily unavailable, retry")
    ```

## Retry Strategies

=== "Exponential Backoff"

    Standard retry pattern with exponential delay:

    ```python
    import asyncio
    from pyvider.rpcplugin import plugin_client
    from pyvider.rpcplugin.exception import TransportError, HandshakeError

    async def retry_with_backoff(max_retries=3):
        """Basic retry with exponential backoff."""

        base_delay = 1.0

        for attempt in range(max_retries + 1):
            try:
                async with plugin_client(command=["python", "plugin.py"]) as client:
                    await client.start()
                    result = await client.call_service_method()
                    logger.info(f"Success on attempt {attempt + 1}")
                    return result

            except (TransportError, HandshakeError) as e:
                if attempt == max_retries:
                    logger.error(f"All {max_retries + 1} attempts failed")
                    raise

                # Exponential backoff: 1s, 2s, 4s, 8s
                delay = base_delay * (2 ** attempt)
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay}s")
                await asyncio.sleep(delay)
    ```

=== "Exponential Backoff with Jitter"

    Prevents thundering herd problems by adding randomization:

    ```python
    import random

    async def retry_with_jitter(max_retries=5):
        """Retry with exponential backoff and jitter."""

        base_delay = 1.0
        max_delay = 30.0

        for attempt in range(max_retries + 1):
            try:
                async with plugin_client(command=["python", "plugin.py"]) as client:
                    await client.start()
                    return await client.call_service_method()

            except (TransportError, HandshakeError) as e:
                if attempt == max_retries:
                    raise

                # Calculate delay with jitter
                delay = min(base_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.1)  # 10% jitter
                total_delay = delay + jitter

                logger.warning(f"Retry in {total_delay:.2f}s (attempt {attempt + 1}/{max_retries + 1})")
                await asyncio.sleep(total_delay)
    ```

=== "Circuit Breaker"

    Fail fast when service is consistently unavailable:

    ```python
    from enum import Enum
    from datetime import datetime, timedelta

    class CircuitState(Enum):
        CLOSED = "closed"       # Normal operation
        OPEN = "open"           # Failing, reject requests
        HALF_OPEN = "half_open" # Testing recovery

    class CircuitBreaker:
        def __init__(
            self,
            failure_threshold: int = 5,
            timeout: int = 60,
            expected_exception: type = Exception
        ):
            self.failure_threshold = failure_threshold
            self.timeout = timeout
            self.expected_exception = expected_exception
            self.failure_count = 0
            self.last_failure_time = None
            self.state = CircuitState.CLOSED

        async def call(self, func, *args, **kwargs):
            """Execute function with circuit breaker protection."""

            # Check if circuit should transition to HALF_OPEN
            if self.state == CircuitState.OPEN:
                if datetime.now() - self.last_failure_time > timedelta(seconds=self.timeout):
                    self.state = CircuitState.HALF_OPEN
                    logger.info("Circuit breaker: OPEN -> HALF_OPEN (testing recovery)")
                else:
                    raise Exception("Circuit breaker is OPEN")

            try:
                result = await func(*args, **kwargs)

                # Success - reset circuit
                if self.state == CircuitState.HALF_OPEN:
                    self.state = CircuitState.CLOSED
                    logger.info("Circuit breaker: HALF_OPEN -> CLOSED (recovered)")

                self.failure_count = 0
                return result

            except self.expected_exception as e:
                self.failure_count += 1
                self.last_failure_time = datetime.now()

                # Trip circuit if threshold exceeded
                if self.failure_count >= self.failure_threshold:
                    self.state = CircuitState.OPEN
                    logger.error(f"Circuit breaker: CLOSED -> OPEN ({self.failure_count} failures)")

                raise

    # Usage
    circuit_breaker = CircuitBreaker(
        failure_threshold=5,
        timeout=60,
        expected_exception=(TransportError, HandshakeError)
    )

    try:
        result = await circuit_breaker.call(make_rpc_call)
    except Exception as e:
        logger.error(f"Circuit breaker prevented call: {e}")
    ```

=== "Retry Decorator"

    Reusable retry decorator for client methods:

    ```python
    import functools
    from typing import Callable

    def retry(
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (TransportError, HandshakeError)
    ):
        """Retry decorator with exponential backoff."""

        def decorator(func: Callable):
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                last_exception = None

                for attempt in range(max_attempts):
                    try:
                        return await func(*args, **kwargs)
                    except exceptions as e:
                        last_exception = e
                        if attempt < max_attempts - 1:
                            wait_time = delay * (backoff ** attempt)
                            logger.warning(
                                f"{func.__name__} failed (attempt {attempt + 1}/{max_attempts}), "
                                f"retrying in {wait_time}s"
                            )
                            await asyncio.sleep(wait_time)

                logger.error(f"{func.__name__} failed after {max_attempts} attempts")
                raise last_exception

            return wrapper
        return decorator

    # Usage
    class ResilientClient:
        @retry(max_attempts=5, delay=1.0, backoff=2.0)
        async def connect(self):
            """Connect with automatic retry."""
            self.client = plugin_client(command=["python", "plugin.py"])
            await self.client.start()
            return self.client

        @retry(max_attempts=3, delay=0.5, backoff=1.5)
        async def call_service(self, method_name: str, **kwargs):
            """Call service method with retry."""
            return await self.client.call_method(method_name, **kwargs)
    ```

## Connection Management

=== "Health Monitoring"

    Monitor connection health with periodic checks:

    ```python
    from grpc_health.v1 import health_pb2, health_pb2_grpc

    class HealthMonitor:
        def __init__(self, client, check_interval: int = 10):
            self.client = client
            self.check_interval = check_interval
            self.is_healthy = False
            self._monitor_task = None

        async def start_monitoring(self):
            """Start periodic health checks."""
            self._monitor_task = asyncio.create_task(self._monitor_loop())

        async def stop_monitoring(self):
            """Stop health monitoring."""
            if self._monitor_task:
                self._monitor_task.cancel()

        async def _monitor_loop(self):
            """Periodic health check loop."""
            health_stub = health_pb2_grpc.HealthStub(self.client.grpc_channel)

            while True:
                try:
                    response = await health_stub.Check(
                        health_pb2.HealthCheckRequest(service="")
                    )

                    self.is_healthy = (
                        response.status == health_pb2.HealthCheckResponse.SERVING
                    )

                    if self.is_healthy:
                        logger.debug("Health check: SERVING")
                    else:
                        logger.warning(f"Health check: {response.status}")

                except Exception as e:
                    self.is_healthy = False
                    logger.error(f"Health check failed: {e}")

                await asyncio.sleep(self.check_interval)

        async def wait_for_healthy(self, timeout: int = 30):
            """Wait for service to become healthy."""
            start_time = asyncio.get_event_loop().time()

            while not self.is_healthy:
                if asyncio.get_event_loop().time() - start_time > timeout:
                    raise TimeoutError("Service did not become healthy in time")

                await asyncio.sleep(1)

    # Usage
    async def monitored_client():
        async with plugin_client(command=["python", "plugin.py"]) as client:
            await client.start()

            # Start health monitoring
            monitor = HealthMonitor(client, check_interval=10)
            await monitor.start_monitoring()

            try:
                # Wait for service to be healthy
                await monitor.wait_for_healthy(timeout=30)

                # Use client
                if monitor.is_healthy:
                    result = await client.call_method()

            finally:
                await monitor.stop_monitoring()
    ```

=== "Auto-Reconnection"

    Automatic reconnection on connection loss:

    ```python
    class AutoReconnectClient:
        def __init__(self, command: list[str], max_reconnect_attempts: int = 5):
            self.command = command
            self.max_reconnect_attempts = max_reconnect_attempts
            self.client = None
            self.connected = False

        async def connect(self):
            """Connect with retry logic."""
            for attempt in range(self.max_reconnect_attempts):
                try:
                    self.client = plugin_client(command=self.command)
                    await self.client.start()
                    self.connected = True
                    logger.info(f"Connected on attempt {attempt + 1}")
                    return
                except (TransportError, HandshakeError) as e:
                    if attempt < self.max_reconnect_attempts - 1:
                        wait_time = 2 ** attempt
                        logger.warning(f"Connection failed, retrying in {wait_time}s")
                        await asyncio.sleep(wait_time)
                    else:
                        raise

        async def ensure_connected(self):
            """Ensure connection is active, reconnect if needed."""
            if not self.connected or not await self._is_connection_alive():
                logger.warning("Connection lost, reconnecting...")
                await self.connect()

        async def _is_connection_alive(self):
            """Check if connection is still alive."""
            try:
                # Simple health check
                health_stub = health_pb2_grpc.HealthStub(self.client.grpc_channel)
                await health_stub.Check(health_pb2.HealthCheckRequest())
                return True
            except:
                return False

        async def call_with_reconnect(self, func, *args, **kwargs):
            """Call function with automatic reconnection."""
            try:
                await self.ensure_connected()
                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Call failed: {e}, attempting reconnect")
                self.connected = False
                await self.ensure_connected()
                return await func(*args, **kwargs)

        async def disconnect(self):
            """Disconnect cleanly."""
            if self.client:
                await self.client.close()
                self.connected = False

    # Usage
    async def auto_reconnect_example():
        client_mgr = AutoReconnectClient(command=["python", "plugin.py"])

        try:
            await client_mgr.connect()

            # Call with automatic reconnection
            stub = CalculatorStub(client_mgr.client.grpc_channel)
            result = await client_mgr.call_with_reconnect(
                stub.Add,
                AddRequest(a=5, b=3)
            )

        finally:
            await client_mgr.disconnect()
    ```

=== "Connection Pooling"

    Manage multiple connections efficiently:

    ```python
    from asyncio import Lock, Semaphore

    class ConnectionPool:
        def __init__(self, command: list[str], pool_size: int = 5):
            self.command = command
            self.pool_size = pool_size
            self.connections = []
            self.available = []
            self.lock = Lock()
            self.semaphore = Semaphore(pool_size)

        async def initialize(self):
            """Initialize connection pool."""
            for i in range(self.pool_size):
                try:
                    client = plugin_client(command=self.command)
                    await client.start()
                    self.connections.append(client)
                    self.available.append(client)
                    logger.info(f"Initialized connection {i + 1}/{self.pool_size}")
                except Exception as e:
                    logger.error(f"Failed to initialize connection {i + 1}: {e}")

        async def acquire(self):
            """Acquire a connection from the pool."""
            await self.semaphore.acquire()

            async with self.lock:
                if self.available:
                    return self.available.pop()
                else:
                    # Pool exhausted, create temporary connection
                    client = plugin_client(command=self.command)
                    await client.start()
                    return client

        async def release(self, client):
            """Release a connection back to the pool."""
            async with self.lock:
                if client in self.connections:
                    self.available.append(client)
                else:
                    # Temporary connection, close it
                    await client.close()

            self.semaphore.release()

        async def close_all(self):
            """Close all connections in the pool."""
            for client in self.connections:
                await client.close()
            logger.info("Connection pool closed")

    # Usage
    async def pool_example():
        pool = ConnectionPool(command=["python", "calculator.py"], pool_size=5)
        await pool.initialize()

        try:
            # Acquire connection
            client = await pool.acquire()

            try:
                stub = CalculatorStub(client.grpc_channel)
                result = await stub.Add(AddRequest(a=10, b=5))
                logger.info(f"Result: {result.result}")
            finally:
                # Always release back to pool
                await pool.release(client)

        finally:
            await pool.close_all()
    ```

## Best Practices

### 1. Classify Errors for Retry

Only retry transient errors:

```python
def is_retryable_error(error: Exception) -> bool:
    """Determine if error is retryable."""
    if isinstance(error, (TransportError, HandshakeError)):
        return True

    if isinstance(error, grpc.aio.AioRpcError):
        # Retry on transient gRPC errors
        retryable_codes = {
            StatusCode.UNAVAILABLE,
            StatusCode.DEADLINE_EXCEEDED,
            StatusCode.RESOURCE_EXHAUSTED,
        }
        return error.code() in retryable_codes

    return False
```

### 2. Implement Timeout Strategies

Set appropriate timeouts for different operations:

```python
import os

# Connection timeout
os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "30"

# RPC call timeout
async def call_with_timeout(stub_method, request, timeout=10):
    """Call RPC method with timeout."""
    try:
        return await asyncio.wait_for(
            stub_method(request),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.error(f"RPC call timed out after {timeout}s")
        raise
```

### 3. Log Retry Attempts

Provide visibility into retry behavior:

```python
logger.warning(
    "Retry attempt",
    extra={
        "attempt": attempt,
        "max_attempts": max_attempts,
        "delay": delay,
        "error": str(error),
    }
)
```

### 4. Implement Graceful Degradation

Provide fallbacks when service is unavailable:

```python
async def call_with_fallback(primary_func, fallback_func):
    """Call primary function with fallback."""
    try:
        return await primary_func()
    except Exception as e:
        logger.warning(f"Primary call failed: {e}, using fallback")
        return await fallback_func()
```

## Next Steps

- **[Client Development Guide](client-guide/)** - Basic client setup and configuration
- **[Direct Connections](direct-connections/)** - Connect to existing servers
- **[Security Guide](../security/)** - mTLS and authentication
- **[Examples](../../examples/)** - Complete working examples
