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
import asyncio
import time
import sys # For sys.getsizeof
from typing import Any # For type hints
from example_utils import configure_for_example
configure_for_example() # Basic example setup
from pyvider.telemetry import logger

class PerformanceMonitor:
    """Simple performance monitoring utility."""
    def __init__(self):
        self.metrics: dict[str, dict[str, Any]] = {} # Added type hint

    def start_timer(self, name: str) -> None: # Added type hint
        self.metrics[name] = {"start": time.perf_counter()}

    def end_timer(self, name: str) -> None: # Added type hint
        if name in self.metrics:
            end_time = time.perf_counter()
            self.metrics[name]["duration"] = end_time - self.metrics[name]["start"]

    def get_duration(self, name: str) -> float:
        return self.metrics.get(name, {}).get("duration", 0.0)

    def report(self) -> None: # Added type hint
        logger.info("📊 Performance Report:")
        for name, data in self.metrics.items():
            if "duration" in data:
                logger.info(f"  ⏱️  {name}: {data['duration']:.3f}s")

async def connection_pooling_example(): # Conceptual for this library
    logger.info("🏊 Connection Pooling Example (Conceptual for RPC Plugins)")
    # In a typical pyvider.rpcplugin setup, RPCPluginClient manages a single
    # persistent connection to its plugin. Connection pooling is more relevant
    # if a single application were acting as a client to many different services
    # or a traditional database.
    # For plugins, if you have many host processes talking to one plugin server,
    # the gRPC server within the plugin handles concurrent connections.
    logger.info("   (Note: RPCPluginClient typically manages one main connection per plugin instance.)")
    logger.info("✅ Connection pooling concept discussed.")

async def batch_processing_example():
    logger.info("📦 Batch Processing Example")
    async def process_single_item(item: str) -> str: # Added type hint
        await asyncio.sleep(0.01) # Simulate processing overhead for a single item
        return f"processed_{item}"

    async def process_batch(items: list[str]) -> list[str]: # Added type hint
        await asyncio.sleep(0.05) # Simulate a slightly larger overhead for batch setup
        # In a real scenario, processing items in a batch might be much faster
        # per item due to reduced fixed overheads (e.g., one DB call for many items).
        return [f"batch_processed_{item}" for item in items]

    items_to_process = [f"item_{i}" for i in range(100)]
    monitor = PerformanceMonitor()

    # Test single item processing
    monitor.start_timer("single_item_processing_total")
    single_results = []
    for item in items_to_process:
        result = await process_single_item(item)
        single_results.append(result)
    monitor.end_timer("single_item_processing_total")

    # Test batch processing
    monitor.start_timer("batch_item_processing_total")
    batch_size = 10
    batch_results = []
    for i in range(0, len(items_to_process), batch_size):
        current_batch = items_to_process[i : i + batch_size]
        results_from_batch = await process_batch(current_batch)
        batch_results.extend(results_from_batch)
    monitor.end_timer("batch_item_processing_total")

    logger.info(f"📊 Processed {len(single_results)} items individually.")
    logger.info(f"📊 Processed {len(batch_results)} items in batches of {batch_size}.")
    monitor.report()

    single_duration = monitor.get_duration("single_item_processing_total")
    batch_duration = monitor.get_duration("batch_item_processing_total")
    if batch_duration > 0 and single_duration > 0:
        speedup = single_duration / batch_duration
        logger.info(f"🚀 Illustrative batch processing speedup: {speedup:.2f}x (depends heavily on actual work)")
    logger.info("✅ Batch processing example completed.")


async def memory_optimization_example():
    logger.info("💾 Memory Optimization Example (Generators vs Lists)")
    size = 100_000 # A larger size to better see memory differences

    def create_large_list(n: int) -> list[str]:
        return [f"item_detail_{i}" for i in range(n)]

    def create_generator(n: int): # Yields str
        for i in range(n):
            yield f"item_detail_{i}"

    # Measure list memory usage (approximate)
    large_list = create_large_list(size)
    list_memory_size = sys.getsizeof(large_list)
    # For a more accurate measure of deep content, one might iterate and sum sizes,
    # but getsizeof on the list container itself gives a basic idea.
    logger.info(f"📊 Approximate memory for list of {size} strings: {list_memory_size:,} bytes")
    del large_list # Free memory

    # Measure generator memory usage (approximate for the generator object itself)
    generator_obj = create_generator(size)
    generator_memory_size = sys.getsizeof(generator_obj)
    logger.info(f"📊 Approximate memory for generator object for {size} strings: {generator_memory_size:,} bytes")
    # Consume the generator to ensure it's doing work, though memory is used item by item
    count = 0
    for _ in generator_obj:
        count +=1
    assert count == size
    del generator_obj

    logger.info("   (Note: Generator memory is low for the object; items are processed one by one.)")
    logger.info("✅ Memory optimization (generator) example completed.")

async def main():
    logger.info("🚀 Performance Tuning Examples & Concepts")
    await connection_pooling_example()
    await batch_processing_example()
    await memory_optimization_example()

    logger.info("🏁 Performance Guidelines Summary:")
    logger.info("  - Choose transports wisely (UDS for local IPC).")
    logger.info("  - Design efficient Protobuf messages.")
    logger.info("  - Embrace `async/await` for all I/O in handlers.")
    logger.info("  - Avoid chatty RPC interfaces; batch operations where sensible.")
    logger.info("  - Profile your plugin to find real bottlenecks.")
    logger.info("✅ All performance examples completed.")

if __name__ == "__main__":
    asyncio.run(main())
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
