# Async Patterns

Master asynchronous programming patterns for high-performance plugin servers using asyncio, concurrent processing, and resilient error handling.

## Core Async Patterns

### Basic Async Server

```python
import asyncio
from pyvider.rpcplugin import plugin_server
from provide.foundation import logger

class AsyncHandler:
    """Async-first plugin handler."""

    async def process_request(self, request):
        logger.info("Processing async request")

        # Concurrent operations
        results = await asyncio.gather(
            self.fetch_data(request.id),
            self.validate_permissions(request.user),
            self.check_quota(request.user)
        )

        return {"data": results[0], "authorized": results[1], "quota_ok": results[2]}

    async def fetch_data(self, id: str):
        await asyncio.sleep(0.1)  # Simulate I/O
        return {"id": id, "data": "..."}

    async def validate_permissions(self, user: str):
        await asyncio.sleep(0.05)
        return True

    async def check_quota(self, user: str):
        await asyncio.sleep(0.02)
        return True

async def main():
    server = plugin_server(
        protocol=plugin_protocol(),
        handler=AsyncHandler()
    )
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## Concurrent Processing

### Batch Processing with Semaphore

```python
from typing import TypeVar, Callable, Awaitable

T = TypeVar('T')
R = TypeVar('R')

class BatchProcessor:
    """Process items concurrently with controlled concurrency."""

    def __init__(self, max_concurrency: int = 10):
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def process_batch(self,
                          items: list[T],
                          processor: Callable[[T], Awaitable[R]],
                          batch_size: int = None) -> list[R]:
        """Process items in controlled batches."""
        if batch_size is None:
            batch_size = self.max_concurrency

        async def process_with_semaphore(item: T) -> R:
            async with self.semaphore:
                return await processor(item)

        tasks = [process_with_semaphore(item) for item in items]
        return await asyncio.gather(*tasks, return_exceptions=True)

# Usage
processor = BatchProcessor(max_concurrency=5)
results = await processor.process_batch(
    items=["item1", "item2", "item3"],
    processor=lambda x: process_item(x)
)
```

### Task Management

```python
class TaskManager:
    """Manage background tasks lifecycle."""

    def __init__(self):
        self.tasks: dict[str, asyncio.Task] = {}
        self.shutdown_event = asyncio.Event()

    async def start_task(self, name: str, coro):
        """Start a managed background task."""
        if name in self.tasks:
            await self.stop_task(name)

        self.tasks[name] = asyncio.create_task(coro)
        logger.info(f"Started task: {name}")
        return self.tasks[name]

    async def stop_task(self, name: str):
        """Stop a specific task."""
        if task := self.tasks.get(name):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self.tasks[name]
            logger.info(f"Stopped task: {name}")

    async def stop_all(self):
        """Stop all tasks gracefully."""
        for name in list(self.tasks.keys()):
            await self.stop_task(name)
        self.shutdown_event.set()

# Usage in server
class ServerWithTasks:
    def __init__(self):
        self.task_manager = TaskManager()

    async def start(self):
        # Start background tasks
        await self.task_manager.start_task(
            "health_check",
            self.periodic_health_check()
        )
        await self.task_manager.start_task(
            "metrics",
            self.collect_metrics()
        )

    async def periodic_health_check(self):
        while True:
            await asyncio.sleep(30)
            logger.info("Health check passed")

    async def collect_metrics(self):
        while True:
            await asyncio.sleep(60)
            logger.info("Metrics collected")
```

## Stream Processing

### Async Generators

```python
from collections.abc import AsyncIterator

class StreamProcessor:
    """Process data streams efficiently."""

    async def process_stream(self, stream: AsyncIterator[dict]) -> AsyncIterator[dict]:
        """Process streaming data with transformation."""
        async for item in stream:
            # Transform item
            processed = await self.transform_item(item)

            # Filter if needed
            if self.should_include(processed):
                yield processed

    async def transform_item(self, item: dict) -> dict:
        # Async transformation
        await asyncio.sleep(0.01)
        return {**item, "processed": True}

    def should_include(self, item: dict) -> bool:
        return item.get("valid", True)

# Usage
async def generate_stream():
    """Generate sample stream."""
    for i in range(100):
        await asyncio.sleep(0.1)
        yield {"id": i, "data": f"item_{i}"}

processor = StreamProcessor()
async for result in processor.process_stream(generate_stream()):
    print(result)
```

### Bidirectional Streaming

```python
class BidirectionalStreamHandler:
    """Handle bidirectional gRPC streams."""

    async def StreamChat(self, request_iterator, context):
        """Bidirectional streaming RPC."""
        client_id = str(uuid.uuid4())
        logger.info(f"Client {client_id} connected")

        try:
            async for request in request_iterator:
                # Process incoming message
                response = await self.process_message(request, client_id)

                # Send response
                yield response

                # Check for special commands
                if request.message == "/quit":
                    break

        finally:
            logger.info(f"Client {client_id} disconnected")

    async def process_message(self, request, client_id: str):
        logger.debug(f"Message from {client_id}: {request.message}")

        # Echo with timestamp
        return ChatResponse(
            message=f"Echo: {request.message}",
            timestamp=time.time(),
            client_id=client_id
        )
```

## Connection Management

### Connection Pooling

```python
class ConnectionPool:
    """Async connection pool with health checks."""

    def __init__(self, min_size: int = 2, max_size: int = 10):
        self.min_size = min_size
        self.max_size = max_size
        self.pool: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self.connections: set = set()
        self._lock = asyncio.Lock()

    async def initialize(self):
        """Create initial connections."""
        for _ in range(self.min_size):
            conn = await self._create_connection()
            await self.pool.put(conn)

    async def acquire(self):
        """Get connection from pool."""
        try:
            return await asyncio.wait_for(self.pool.get(), timeout=0.1)
        except asyncio.TimeoutError:
            if len(self.connections) < self.max_size:
                return await self._create_connection()
            return await self.pool.get()

    async def release(self, conn):
        """Return connection to pool."""
        if await self._is_healthy(conn):
            await self.pool.put(conn)
        else:
            self.connections.discard(conn)
            await conn.close()

    async def _create_connection(self):
        """Create new connection."""
        async with self._lock:
            conn = await create_connection()  # Your connection logic
            self.connections.add(conn)
            return conn

    async def _is_healthy(self, conn) -> bool:
        """Check connection health."""
        try:
            await conn.ping()
            return True
        except:
            return False
```

### HTTP Client with Connection Pooling

```python
class AsyncHTTPClient:
    """HTTP client with connection pooling."""

    def __init__(self, max_connections: int = 100):
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=30,
            ttl_dns_cache=300
        )
        self.session: aiohttp.ClientSession | None = None

    async def start(self):
        """Initialize HTTP session."""
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )

    async def stop(self):
        """Cleanup HTTP session."""
        if self.session:
            await self.session.close()

    async def get(self, url: str, **kwargs) -> dict:
        """Make GET request."""
        async with self.session.get(url, **kwargs) as response:
            return await response.json()

    async def post(self, url: str, **kwargs) -> dict:
        """Make POST request."""
        async with self.session.post(url, **kwargs) as response:
            return await response.json()
```

## Context Management

### Request Context

```python
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar('request_id', default=None)
client_id_var: ContextVar[str] = ContextVar('client_id', default=None)

class ContextManager:
    """Manage request context for async operations."""

    def __init__(self):
        self.active_contexts: dict[str, dict[str, Any]] = {}

    async def with_context(self,
                          req_id: str,
                          client_id: str,
                          user_info: dict[str, Any] = None):
        """Set context for async operation."""
        request_id_var.set(req_id)
        client_id_var.set(client_id)

        self.active_contexts[req_id] = {
            'client_id': client_id,
            'user_info': user_info,
            'start_time': time.time()
        }

        try:
            yield
        finally:
            self.active_contexts.pop(req_id, None)

    def get_current_context(self) -> dict[str, Any] | None:
        """Get current request context."""
        req_id = request_id_var.get()
        return self.active_contexts.get(req_id) if req_id else None

# Usage
context_mgr = ContextManager()

async def handle_request(request, context):
    req_id = str(uuid.uuid4())
    client_id = context.peer()

    async with context_mgr.with_context(req_id, client_id):
        logger.info("Processing request", extra={
            "request_id": req_id,
            "client_id": client_id
        })

        return await process_with_context(request)
```

## Error Handling & Resilience

### Retry with Exponential Backoff

```python
class RetryHandler:
    """Advanced retry logic with backoff."""

    async def with_retry(self,
                        operation: Callable[[], Awaitable[T]],
                        max_retries: int = 3,
                        base_delay: float = 1.0,
                        max_delay: float = 60.0,
                        exponential_base: float = 2.0) -> T:
        """Execute with exponential backoff retry."""

        for attempt in range(max_retries):
            try:
                return await operation()
            except Exception as e:
                if attempt == max_retries - 1:
                    raise

                delay = min(base_delay * (exponential_base ** attempt), max_delay)
                logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay}s: {e}")
                await asyncio.sleep(delay)
```

### Circuit Breaker

```python
class CircuitBreaker:
    """Circuit breaker for fault tolerance."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half_open

    async def call(self, operation: Callable[[], Awaitable[T]]) -> T:
        """Execute operation with circuit breaker."""

        current_time = time.time()

        # Check if should attempt reset
        if self.state == "open":
            if current_time - self.last_failure_time >= self.recovery_timeout:
                self.state = "half_open"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = await operation()

            # Success - reset or close circuit
            if self.state == "half_open":
                self.state = "closed"
                logger.info("Circuit breaker CLOSED")
            self.failure_count = 0

            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = current_time

            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error(f"Circuit breaker OPENED after {self.failure_threshold} failures")

            raise
```

## Performance Optimization

### Async Caching

```python
class AsyncCache:
    """Thread-safe async cache with TTL."""

    def __init__(self, ttl: float = 300.0):
        self.ttl = ttl
        self.cache: dict[str, tuple[Any, float]] = {}
        self._lock = asyncio.Lock()

    async def get_or_compute(self,
                            key: str,
                            compute_fn: Callable[[], Awaitable[T]]) -> T:
        """Get from cache or compute if missing."""

        async with self._lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    return value

        # Compute outside lock
        value = await compute_fn()

        async with self._lock:
            self.cache[key] = (value, time.time())

        return value

    async def invalidate(self, key: str = None):
        """Invalidate cache entries."""
        async with self._lock:
            if key:
                self.cache.pop(key, None)
            else:
                self.cache.clear()
```

## Best Practices

### 1. Structured Concurrency

```python
async def structured_concurrent_operations():
    """Use async context managers for cleanup."""

    async with asyncio.TaskGroup() as tg:
        task1 = tg.create_task(operation1())
        task2 = tg.create_task(operation2())
        task3 = tg.create_task(operation3())

    # All tasks complete or all are cancelled
    return task1.result(), task2.result(), task3.result()
```

### 2. Graceful Shutdown

```python
class GracefulShutdownServer:
    """Server with proper shutdown handling."""

    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.tasks = []

    async def serve(self):
        """Serve with signal handling."""
        loop = asyncio.get_running_loop()

        # Register signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(self.shutdown())
            )

        try:
            await self.shutdown_event.wait()
        finally:
            # Cleanup
            await self._cleanup()

    async def shutdown(self):
        """Trigger graceful shutdown."""
        logger.info("Shutting down gracefully...")
        self.shutdown_event.set()

    async def _cleanup(self):
        """Clean up resources."""
        for task in self.tasks:
            task.cancel()

        await asyncio.gather(*self.tasks, return_exceptions=True)
        logger.info("Shutdown complete")
```

### 3. Resource Management

```python
class ResourceManager:
    """Manage async resources properly."""

    async def __aenter__(self):
        self.resource = await acquire_resource()
        return self.resource

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await release_resource(self.resource)

# Usage
async with ResourceManager() as resource:
    await use_resource(resource)
```

## Testing Async Code

```python
import pytest

@pytest.mark.asyncio
async def test_async_handler():
    """Test async handler."""
    handler = AsyncHandler()

    request = {"id": "123", "user": "testuser"}
    result = await handler.process_request(request)

    assert result["data"]["id"] == "123"
    assert result["authorized"] == True
    assert result["quota_ok"] == True

@pytest.mark.asyncio
async def test_concurrent_processing():
    """Test concurrent batch processing."""
    processor = BatchProcessor(max_concurrency=3)

    async def slow_operation(x):
        await asyncio.sleep(0.1)
        return x * 2

    items = list(range(10))
    results = await processor.process_batch(items, slow_operation)

    assert results == [x * 2 for x in items]
```

## See Also

- [Server Configuration](index.md)
- [Performance Tuning](../advanced/observability.md)
- [Foundation Integration](../advanced/foundation-integration.md)
