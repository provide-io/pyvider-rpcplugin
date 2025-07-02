# Chapter 14: Performance Tuning

While `pyvider.rpcplugin` is designed for high performance, especially when using Unix Domain Sockets and asynchronous operations, several factors can influence the overall performance of your plugin system. This chapter discusses key areas for performance consideration and tuning.

## Key Performance Factors

1.  **Transport Choice**:
    *   **Unix Domain Sockets (UDS)**: Offers the lowest latency and highest throughput for Inter-Process Communication (IPC) on the same machine as it bypasses much of the network stack. This is generally the preferred transport for co-located host applications and plugins.
    *   **TCP Sockets**: Necessary for network communication if your plugin runs on a different host. Even for localhost communication, TCP involves more overhead than UDS. Performance can be affected by network latency, bandwidth, and TCP stack tuning.

2.  **Data Serialization (Protocol Buffers)**:
    *   Protocol Buffers (used by gRPC) are generally very efficient for serialization and deserialization.
    *   **Message Size**: Keep your `.proto` message definitions concise. Large messages will naturally take longer to serialize, transmit, and deserialize.
    *   **Avoid Unnecessary Data**: Only send the data that is strictly needed for an RPC call.

3.  **Asynchronous Programming (`asyncio`)**:
    *   **Non-Blocking I/O**: Ensure all I/O-bound operations within your RPC handler methods (e.g., database queries, file access, calls to other network services) are asynchronous (using `await`). Blocking calls in an async handler will stall the event loop and severely degrade concurrency and responsiveness.
    *   **Concurrency**: Leverage `asyncio.gather` to perform multiple independent awaitable operations concurrently if needed within a single RPC handler or on the client side when making multiple calls.

4.  **RPC Method Design**:
    *   **Chattiness**: Avoid overly "chatty" interfaces that require many small RPC calls to achieve a single logical operation. Prefer fewer, well-defined calls that transfer all necessary data.
    *   **Streaming**: For large datasets or ongoing event notifications, use gRPC streaming (unary-stream, stream-unary, or bidirectional-stream) instead of sending large chunks in unary calls or polling.
    *   **Batching**: If you have many small, independent operations, consider designing RPC methods that accept a batch of items to process in a single call, reducing RPC overhead per item.

5.  **Plugin Process Resources**:
    *   Ensure the plugin process has adequate CPU, memory, and I/O resources. Resource starvation will lead to poor performance.
    *   Monitor resource utilization of your plugin processes.

6.  **gRPC Configuration (Advanced)**:
    *   gRPC itself has various channel and server options that can be tuned (e.g., keepalive settings, thread pool sizes for synchronous gRPC, message size limits). `pyvider.rpcplugin` uses `grpc.aio.server` which manages its concurrency via the asyncio event loop, but channel options can still be relevant for clients. Some of these might be exposed or configurable via `pyvider.rpcplugin` settings or directly if you customize server/channel creation.

7.  **Python Version & Libraries**:
    *   Use a recent version of Python (3.13+ as recommended by `pyvider.rpcplugin`) as newer versions often include performance improvements in `asyncio` and other core libraries.
    *   Keep `grpcio` and other dependencies updated.

## Example: Performance Tuning Techniques (`examples/ch14_performance_tuning_concepts.py`)

The `ch14_performance_tuning_concepts.py` example script demonstrates several general programming patterns that contribute to better performance, such as batch processing and choosing memory-efficient data structures. While not all directly manipulate `pyvider.rpcplugin` configurations, the principles are applicable to how you design your plugin's logic.

```python
#!/usr/bin/env python3
# examples/ch14_performance_tuning_concepts.py
"""
Performance Tuning - Performance benchmarking and optimization patterns.
"""

import asyncio
import time
from typing import Any  # Import Any
import sys # For sys.getsizeof

from example_utils import configure_for_example  # type: ignore[import-not-found]

configure_for_example()

from pyvider.telemetry import logger # noqa: E402


class PerformanceMonitor:
    """Simple performance monitoring utility."""

    def __init__(self) -> None:
        self.metrics: dict[str, dict[str, Any]] = {}

    def start_timer(self, name: str) -> None:
        """Start timing an operation."""
        self.metrics[name] = {"start": time.perf_counter()}

    def end_timer(self, name: str) -> None:
        """End timing an operation."""
        if name in self.metrics:
            end_time = time.perf_counter()
            self.metrics[name]["duration"] = end_time - self.metrics[name]["start"]

    def get_duration(self, name: str) -> float:
        """Get duration of a timed operation."""
        return self.metrics.get(name, {}).get("duration", 0.0)

    def report(self) -> None:
        """Report performance metrics."""
        logger.info("📊 Performance Report:")
        for name, data in self.metrics.items():
            if "duration" in data:
                logger.info(f"  ⏱️  {name}: {data['duration']:.3f}s")


async def connection_pooling_example() -> None:
    """Example: Connection pooling optimization."""
    logger.info("🏊 Connection Pooling Example")

    class MockConnectionPool:
        def __init__(self, pool_size: int = 10) -> None:
            self.pool_size = pool_size
            self.connections: list[Any] = []
            self.active_connections = 0

        async def get_connection(self) -> Any:
            """Get connection from pool."""
            if self.active_connections < self.pool_size:
                self.active_connections += 1
                connection_id = f"conn_{self.active_connections}"
                logger.info(f"🔌 Created new connection: {connection_id}")
                return connection_id
            else:
                await asyncio.sleep(0.01)  # Wait for available connection
                return await self.get_connection()

        async def release_connection(self, connection_id: str) -> None:
            """Release connection back to pool."""
            logger.info(f"🔓 Released connection: {connection_id}")
            self.active_connections -= 1

    pool = MockConnectionPool(pool_size=5)
    monitor = PerformanceMonitor()

    # Test connection pooling performance
    monitor.start_timer("connection_test")

    tasks = []
    for i in range(10):

        async def use_connection(request_id: int) -> str:
            conn = await pool.get_connection()
            await asyncio.sleep(0.1)  # Simulate work
            await pool.release_connection(conn) # Assuming conn is the id str
            return f"Request {request_id} completed"

        tasks.append(use_connection(i))

    results = await asyncio.gather(*tasks)
    monitor.end_timer("connection_test")

    logger.info(f"✅ Processed {len(results)} requests")
    monitor.report()


async def batch_processing_example() -> None:
    """Example: Batch processing optimization."""
    logger.info("📦 Batch Processing Example")

    async def process_single_item(item: str) -> str:
        """Process a single item (inefficient)."""
        await asyncio.sleep(0.01)  # Simulate processing overhead
        return f"processed_{item}"

    async def process_batch(items: list[str]) -> list[str]:
        """Process items in batch (efficient)."""
        await asyncio.sleep(0.05)  # Simulate batch processing overhead
        return [f"batch_processed_{item}" for item in items]

    items = [f"item_{i}" for i in range(100)]
    monitor = PerformanceMonitor()

    # Test single item processing
    monitor.start_timer("single_processing")
    single_results = []
    for item in items:
        result = await process_single_item(item)
        single_results.append(result)
    monitor.end_timer("single_processing")

    # Test batch processing
    monitor.start_timer("batch_processing")
    batch_size = 10
    batch_results = []
    for i in range(0, len(items), batch_size):
        batch = items[i : i + batch_size]
        results = await process_batch(batch)
        batch_results.extend(results)
    monitor.end_timer("batch_processing")

    logger.info(f"📊 Single processing: {len(single_results)} items")
    logger.info(f"📊 Batch processing: {len(batch_results)} items")
    monitor.report()

    # Calculate speedup
    single_duration = monitor.get_duration("single_processing")
    batch_duration = monitor.get_duration("batch_processing")
    speedup = single_duration / batch_duration if batch_duration > 0 else 0
    logger.info(f"🚀 Batch processing speedup: {speedup:.2f}x")

from collections.abc import Generator # Added for create_generator

async def memory_optimization_example() -> None:
    """Example: Memory optimization techniques."""
    logger.info("💾 Memory Optimization Example")

    # Generator vs list comparison
    def create_large_list(size: int) -> list[str]:
        """Create large list (memory intensive)."""
        return [f"item_{i}" for i in range(size)]

    def create_generator(size: int) -> Generator[str, None, None]:
        """Create generator (memory efficient)."""
        for i in range(size):
            yield f"item_{i}"

    size = 10000

    # Measure list memory usage
    list_data = create_large_list(size)
    list_size = sys.getsizeof(list_data)
    logger.info(f"📊 List memory usage: {list_size:,} bytes")

    # Measure generator memory usage
    gen_data = create_generator(size)
    gen_size = sys.getsizeof(gen_data)
    logger.info(f"📊 Generator memory usage: {gen_size:,} bytes")

    memory_savings = list_size - gen_size
    logger.info(
        f"💰 Memory savings: {memory_savings:,} bytes "
        f"({memory_savings / list_size * 100:.1f}%)"
    )

    logger.info("✅ Memory optimization example completed")


async def main() -> None:
    """Run performance tuning examples."""
    logger.info("🚀 Performance Tuning Examples")

    await connection_pooling_example()
    await batch_processing_example()
    await memory_optimization_example()

    logger.info("🏁 Performance Guidelines:")
    logger.info("  🏊 Use connection pooling for high-concurrency scenarios")
    logger.info("  📦 Batch operations when possible to reduce overhead")
    logger.info("  💾 Use generators for large datasets to save memory")
    logger.info("  ⏱️  Profile your application to identify bottlenecks")
    logger.info("  📊 Monitor key metrics in production")

    logger.info("✅ All performance examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍📈
```

**Applying Performance Principles to `pyvider.rpcplugin`:**

*   **Connection Pooling**: `RPCPluginClient` manages a single, persistent gRPC channel to its plugin. Connection pooling is generally handled by gRPC itself if the host application makes many concurrent calls over that single channel. If your host application talks to *many different plugin executables*, you would have multiple `RPCPluginClient` instances, and managing these instances efficiently (e.g., reusing them if appropriate for the same plugin target) could be seen as a form of client-instance pooling.
*   **Batch Processing**: If your plugin's service involves operations that can be grouped, design your `.proto` service methods to accept lists of items (e.g., `rpc ProcessItems (stream ItemRequest) returns (ProcessSummary) {}` or `rpc ProcessBatch (BatchRequest) returns (BatchResponse) {}`). This significantly reduces the per-call overhead of RPC.
*   **Memory Optimization**: When dealing with large data transfers, especially with streaming RPCs, process data iteratively using asynchronous generators (`async for ... yield ...`) rather than accumulating large lists in memory on either the client or server side.

**Profiling Your Plugin:**

To find real performance bottlenecks:
1.  **Server-Side (Plugin)**:
    *   Use Python's built-in `cProfile` or `profile` modules.
    *   For `asyncio` applications, `asyncio-profiler` can provide insights into event loop behavior.
    *   `py-spy` can sample Python processes without modifying code, useful for production.
2.  **Client-Side (Host Application)**:
    *   Profile the host application similarly to understand time spent in RPC calls versus other logic.
    *   Measure end-to-end latency for critical RPC calls.
3.  **gRPC Metrics**: gRPC libraries often expose metrics that can be collected by monitoring systems (e.g., Prometheus). Check the `grpcio` documentation for details on enabling and accessing these. `pyvider.telemetry` can be a channel for these if integrated.

By considering these factors and profiling your application, you can optimize the performance of your `pyvider.rpcplugin`-based system.
