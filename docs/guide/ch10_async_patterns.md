# Chapter 10: Asynchronous Patterns

The `pyvider.rpcplugin` library is designed to be asynchronous from the ground up, leveraging Python's `asyncio` library. This allows for efficient handling of I/O-bound operations (like network communication for RPCs) and enables high concurrency in both client and server applications. Understanding common asynchronous patterns is key to effectively using and building upon this framework.

## Key `asyncio` Concepts in `pyvider.rpcplugin`

*   **`async def`**: All RPC handler methods you implement in your plugin server, as well as many methods within `RPCPluginClient` and `RPCPluginServer`, are defined as `async def`. This means they are coroutines and must be `await`ed.
*   **`await`**: Used to call asynchronous functions and wait for their completion without blocking the entire event loop. This is crucial for network calls, file I/O (if done asynchronously), and `asyncio.sleep()`.
*   **Event Loop**: `asyncio` manages an event loop that runs asynchronous tasks and callbacks. `pyvider.rpcplugin` integrates with this loop.
*   **Tasks (`asyncio.create_task`)**: Used to run coroutines concurrently. For instance, `RPCPluginClient` uses tasks to manage background operations like streaming STDIO logs from the plugin.
*   **`asyncio.gather`**: A utility to run multiple awaitables (often tasks) concurrently and wait for all of them to complete.
*   **Asynchronous Iterators (`async for`)**: Used for handling streaming RPCs, where multiple messages can be sent or received over time.

## Example: Advanced Async Patterns (`examples/ch10_async_patterns_demo.py`)

This example script demonstrates several common asynchronous programming patterns that are relevant when working with `pyvider.rpcplugin`, even though the example itself doesn't directly use `RPCPluginClient` or `RPCPluginServer` for these specific demonstrations. The patterns are applicable to how you might structure your client or server logic.

```python
#!/usr/bin/env python3
# examples/ch10_async_patterns_demo.py
import asyncio
from collections.abc import AsyncGenerator # For type hinting async generators
from example_utils import configure_for_example
configure_for_example() # Basic example setup
from pyvider.telemetry import logger

async def concurrent_requests_example():
    """Illustrates handling multiple operations concurrently using asyncio.gather."""
    logger.info("⚡ Concurrent Requests Example")

    async def mock_rpc_call(request_id: int) -> str:
        """Simulates an RPC call that takes some time."""
        delay = 0.1 * request_id  # Different requests take different times
        logger.info(f"  -> Starting mock RPC call {request_id} (will take {delay:.1f}s)")
        await asyncio.sleep(delay)
        response = f"Response for request {request_id}"
        logger.info(f"  <- Finished mock RPC call {request_id}")
        return response

    request_ids = range(1, 6) # Create 5 requests
    # Create a list of coroutine objects (tasks to be done)
    tasks = [mock_rpc_call(req_id) for req_id in request_ids]

    logger.info(f"🚀 Launching {len(tasks)} mock RPC calls concurrently...")
    # asyncio.gather runs all awaitables in the list concurrently.
    # It waits for all of them to complete and returns a list of their results.
    results = await asyncio.gather(*tasks)

    for result in results:
        logger.info(f"✅ Received: {result}")
    logger.info("✅ Concurrent requests example completed")

async def streaming_example():
    """Demonstrates consuming an asynchronous stream of data."""
    logger.info("📡 Streaming Example")

    async def mock_data_stream() -> AsyncGenerator[str, None]:
        """Simulates a server streaming data to a client."""
        for i in range(5):
            await asyncio.sleep(0.2) # Simulate delay between stream items
            item = f"Stream item {i + 1}"
            logger.info(f"  ~> Server yielding: {item}")
            yield item # Yield data item
        logger.info("  ~> Server stream finished.")

    logger.info("📊 Client processing stream data:")
    # 'async for' iterates over an asynchronous generator or iterable.
    # It awaits the next item from the stream.
    async for item in mock_data_stream():
        logger.info(f"  📦 Client received: {item}")
    logger.info("✅ Streaming example completed")

async def timeout_and_retry_example():
    """Illustrates basic timeout and retry logic for an unreliable async operation."""
    logger.info("⏱️  Timeout and Retry Example")

    async def unreliable_operation(attempt_number: int) -> str:
        """Simulates an operation that might fail or take too long."""
        logger.info(f"  Attempting operation (attempt {attempt_number})...")
        # Simulate potential failure
        if attempt_number < 3:
            await asyncio.sleep(0.5) # Simulate some work before failing
            raise Exception(f"Simulated failure on attempt {attempt_number}")
        # Simulate success on the 3rd attempt
        await asyncio.sleep(0.1)
        return f"Operation successful on attempt {attempt_number}!"

    max_retries = 3
    base_retry_delay = 0.1 # seconds

    for current_attempt in range(1, max_retries + 2): # Try up to max_retries + 1 times
        try:
            # asyncio.wait_for adds a timeout to an awaitable.
            # If the operation takes longer than 1.0 second, it raises asyncio.TimeoutError.
            result = await asyncio.wait_for(unreliable_operation(current_attempt), timeout=1.0)
            logger.info(f"✅ {result}")
            break # Success, exit retry loop
        except asyncio.TimeoutError:
            logger.warning(f"⏰ Operation attempt {current_attempt} timed out.")
            if current_attempt > max_retries:
                logger.error("Max retries reached after timeout. Giving up.")
                break
        except Exception as e:
            logger.warning(f"⚠️  Operation attempt {current_attempt} failed: {e}")
            if current_attempt > max_retries:
                logger.error("Max retries reached after failure. Giving up.")
                break

        # If not successful and more retries are allowed, wait before next attempt
        if current_attempt <= max_retries:
            delay = base_retry_delay * (2 ** (current_attempt - 1)) # Exponential backoff
            logger.info(f"😴 Waiting {delay:.2f}s before next retry...")
            await asyncio.sleep(delay)

    logger.info("✅ Timeout and retry example completed")

async def main():
    logger.info("🚀 Advanced Async Patterns Examples")
    await concurrent_requests_example()
    await asyncio.sleep(0.5) # Pause between examples for log readability
    await streaming_example()
    await asyncio.sleep(0.5)
    await timeout_and_retry_example()
    logger.info("✅ All async pattern examples completed")

if __name__ == "__main__":
    asyncio.run(main())
```

**Applying these patterns with `pyvider.rpcplugin`:**

*   **Concurrent Client Calls**: If your host application needs to communicate with multiple plugins simultaneously, or make multiple non-blocking calls to a single plugin, you can create `asyncio.Task` objects for each `client.start()` or `stub.YourMethod()` call and then use `await asyncio.gather(...)`.
*   **Server-Side Concurrency**: Your `RPCPluginServer` and its gRPC handlers are inherently asynchronous. If an RPC method needs to perform multiple I/O-bound operations (e.g., querying different databases, calling other microservices), you can use `await asyncio.gather(...)` within the handler method to perform these concurrently.
*   **Streaming RPCs**: If your `.proto` defines streaming methods (client-streaming, server-streaming, or bidirectional-streaming), your gRPC stubs and servicer methods will use asynchronous generators (`async for ... yield ...`). The `examples/ch05_echo_server.py` and `examples/ch07_echo_client.py` could be extended to show this if a streaming RPC was added to `echo.proto`. `RPCPluginClient` itself uses this for its STDIO log streaming feature.
*   **Timeouts**:
    *   `RPCPluginClient.start()` has built-in timeouts for handshake and connection phases, configured by `PLUGIN_HANDSHAKE_TIMEOUT` and `PLUGIN_CONNECTION_TIMEOUT`.
    *   For individual gRPC calls made via stubs, you can pass a `timeout` argument: `await stub.YourMethod(request, timeout=5.0)`.
    *   You can also use `asyncio.wait_for()` to wrap calls if more complex timeout logic is needed.
*   **Retries**:
    *   `RPCPluginClient.start()` has configurable retry logic for the initial connection and handshake (see `PLUGIN_CLIENT_RETRY_ENABLED` and related settings).
    *   For individual RPC calls that might fail due to transient issues, you may need to implement your own retry loop around the `stub.YourMethod()` call, similar to the `timeout_and_retry_example`. Libraries like `tenacity` can also simplify retry logic.

By effectively using these asynchronous patterns, you can build highly responsive and scalable plugin systems with `pyvider.rpcplugin`.
