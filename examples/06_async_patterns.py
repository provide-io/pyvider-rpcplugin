#!/usr/bin/env python3
# examples/06_async_patterns.py
"""Demonstrates async programming patterns and best practices with pyvider-rpcplugin."""

import asyncio
import sys
import time
from collections.abc import AsyncGenerator as AbcAsyncGenerator
from pathlib import Path
from types import TracebackType
from typing import Any, TypeVar  # Added Dict

import grpc
from attrs import define, field

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import (
    RPCPluginProtocol as TypesRPCPluginProtocol,
)

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from example_utils import configure_for_example, clear_plugin_env_vars # noqa: E402
from pyvider.rpcplugin import (  # noqa: E402
    plugin_client,
    plugin_protocol,
    plugin_server,
)
from pyvider.telemetry import logger  # noqa: E402


@define(frozen=True, slots=True)
class StreamReply:
    """A structured reply for a streaming RPC method."""

    response: str = field()
    message_id: int = field()


@define(frozen=True, slots=True)
class BatchReply:
    """A structured reply for a batch processing RPC method."""

    results: list[Any] = field()  # Changed list to List
    processed_count: int = field()


class AsyncStreamHandler:
    """Handler demonstrating async streaming patterns."""

    def __init__(self) -> None:
        self.active_streams = 0
        self.total_messages = 0

    async def ProcessStream(
        self,
        request_iterator: AbcAsyncGenerator[Any],
        context: grpc.aio.ServicerContext,
    ) -> AbcAsyncGenerator[StreamReply]:
        """Handle streaming requests asynchronously."""
        self.active_streams += 1

        logger.info(
            "Started processing stream",
            domain="async",
            action="stream_start",
            status="starting",
            active_streams=self.active_streams,
        )

        try:
            async for request in request_iterator:
                self.total_messages += 1

                # Simulate async processing
                await asyncio.sleep(0.01)

                message = getattr(request, "message", "empty")
                logger.debug(
                    "Processed stream message",
                    domain="async",
                    action="stream_message",
                    status="processed",
                    message_id=self.total_messages,
                    content_length=len(message),
                )

                # Yield response asynchronously
                yield StreamReply(
                    response=f"Processed: {message}",
                    message_id=self.total_messages,
                )

        finally:
            self.active_streams -= 1

            logger.info(
                "Completed processing stream",
                domain="async",
                action="stream_complete",
                status="success",
                active_streams=self.active_streams,
                total_messages=self.total_messages,
            )

    async def BatchProcess(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> BatchReply:
        """Handle batch processing with concurrent workers."""
        batch_size = getattr(request, "batch_size", 10)

        logger.info(
            "Starting batch processing",
            domain="async",
            action="batch_start",
            status="starting",
            batch_size=batch_size,
        )

        # Create concurrent tasks
        async def process_item(item_id: int) -> str:  # Added str return
            await asyncio.sleep(0.1)  # Simulate work
            return f"Item_{item_id}_processed"

        # Process batch concurrently
        tasks = [process_item(i) for i in range(batch_size)]
        results: list[str] = await asyncio.gather(*tasks)  # Annotated results

        logger.info(
            "Batch processing completed",
            domain="async",
            action="batch_complete",
            status="success",
            batch_size=batch_size,
            results_count=len(results),
        )

        return BatchReply(results=results, processed_count=len(results))


async def example_6_async_context_managers() -> None:
    """
    Example 6A: Demonstrates async context manager patterns.

    Shows how to use async context managers for proper resource
    management in async RPC applications.
    """
    print("\n" + "=" * 60)
    print("🔧 Example 6A: Async Context Manager Patterns")
    print(" Demonstrates: Proper async resource management")
    print("=" * 60)

    _TAsyncRPCManager = TypeVar("_TAsyncRPCManager", bound="AsyncRPCManager")

    class AsyncRPCManager:
        """Async context manager for RPC resources."""

        server: RPCPluginServer | None
        client: RPCPluginClient | None
        server_task: asyncio.Task | None

        def __init__(self, transport: str = "unix") -> None:
            self.transport = transport
            self.server = None
            self.client = None
            self.server_task = None
            self.dummy_handshaker_path: Path | None = None # For dummy client executable

        async def __aenter__(self: _TAsyncRPCManager) -> _TAsyncRPCManager:
            logger.info(
                "Entering async RPC context",
                domain="async",
                action="context_enter",
                status="starting",
                transport=self.transport,
            )

            # Configure for this specific server instance within the manager
            # Use a unique cookie to avoid clashes if multiple managers run
            manager_cookie = f"async-manager-cookie-{self.transport}-{time.monotonic_ns()}"
            clear_plugin_env_vars() # Clear before this specific config
            configure_for_example(
                PLUGIN_MAGIC_COOKIE_VALUE=manager_cookie,
                PLUGIN_SERVER_TRANSPORTS=[self.transport],
                PLUGIN_CLIENT_TRANSPORTS=[self.transport] # Client should match
            )

            # Setup server
            protocol: TypesRPCPluginProtocol = plugin_protocol()
            handler = AsyncStreamHandler() # Assuming this handler is okay for the dummy calls

            server_socket_path_str = None
            if self.transport == "unix":
                server_socket_path_str = f"/tmp/async_manager_{time.monotonic_ns()}.sock" # nosec B108

            self.server = plugin_server(
                protocol=protocol,
                handler=handler,
                transport=self.transport,
                transport_path=server_socket_path_str # Only for unix
            )

            # Start server
            self.server_task = asyncio.create_task(self.server.serve())
            await self.server.wait_for_server_ready(timeout=5.0)

            # Create a dummy handshaker script for the client to connect to this server
            from pyvider.rpcplugin.config import rpcplugin_config as current_config
            core_version = current_config.get("PLUGIN_CORE_VERSION")
            plugin_version = getattr(self.server, "_protocol_version", current_config.get_list("PLUGIN_PROTOCOL_VERSIONS")[0])
            network_type = self.transport
            address = getattr(getattr(self.server, "_transport", None), "endpoint", "error_getting_endpoint")
            if address == "error_getting_endpoint":
                 raise RuntimeError("Failed to get server endpoint for dummy handshaker")

            handshake_string = f"{core_version}|{plugin_version}|{network_type}|{address}|grpc|"

            self.dummy_handshaker_path = Path(f"./dummy_async_manager_{time.monotonic_ns()}.sh")
            with open(self.dummy_handshaker_path, "w") as f:
                f.write("#!/bin/sh\n")
                f.write(f'echo "{handshake_string}"\n')
            self.dummy_handshaker_path.chmod(0o755)

            # Create client - it will use the same configure_for_example settings
            # The client's _launch_process will set the correct magic cookie env var
            self.client = plugin_client(command=[str(self.dummy_handshaker_path.resolve())])
            await self.client.start() # Start the client

            logger.info(
                "Async RPC context ready",
                domain="async",
                action="context_enter",
                status="success",
                server_running=True,
                client_ready=True,
            )

            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: TracebackType | None,
        ) -> None:
            logger.info(
                "Exiting async RPC context",
                domain="async",
                action="context_exit",
                status="starting",
                has_exception=exc_type is not None,
            )

            # Cleanup client
            if self.client:
                await self.client.close()

            # Cleanup server
            if self.server:
                await self.server.stop()

            if self.server_task:
                await self.server_task

            if self.dummy_handshaker_path and self.dummy_handshaker_path.exists():
                self.dummy_handshaker_path.unlink()
                logger.debug(f"Cleaned up dummy handshaker: {self.dummy_handshaker_path}")


            logger.info(
                "Async RPC context cleanup completed",
                domain="async",
                action="context_exit",
                status="success",
            )

        async def make_call(self, method_name: str, data: str) -> str:
            """Make an async RPC call."""
            logger.info(
                f"Making async RPC call: {method_name}",
                domain="async",
                action="rpc_call",
                status="starting",
                method=method_name,
                data_length=len(data),
            )

            # Simulate RPC call processing
            await asyncio.sleep(0.1)

            result = f"Result for {method_name}: {data}"

            logger.info(
                "Async RPC call completed",
                domain="async",
                action="rpc_call",
                status="success",
                method=method_name,
                result_length=len(result),
            )

            return result

    # Demonstrate async context manager usage
    async with AsyncRPCManager("unix") as rpc:
        # Use RPC services within context
        await rpc.make_call("ProcessData", "sample_data_1")
        await rpc.make_call("ProcessData", "sample_data_2")

        logger.info(
            "Context manager example completed",
            domain="async",
            action="context_demo",
            status="success",
            calls_made=2,
            automatic_cleanup=True,
        )


async def example_6_concurrent_operations() -> None:
    """
    Example 6B: Demonstrates concurrent async operations.

    Shows how to handle multiple concurrent RPC operations
    efficiently using asyncio patterns.
    """
    print("\n" + "=" * 60)
    print("⚡ Example 6B: Concurrent Async Operations")
    print(" Demonstrates: High-concurrency async RPC patterns")
    print("=" * 60)

    async def simulate_rpc_operation(
        operation_id: int, duration: float
    ) -> dict[str, Any]:  # Changed dict to Dict
        """Simulate an async RPC operation."""
        start_time = time.time()

        logger.info(
            f"Starting operation {operation_id}",
            domain="async",
            action="concurrent_op",
            status="starting",
            operation_id=operation_id,
            estimated_duration=duration,
        )

        # Simulate async work
        await asyncio.sleep(duration)

        end_time = time.time()
        actual_duration = end_time - start_time

        logger.info(
            f"Completed operation {operation_id}",
            domain="async",
            action="concurrent_op",
            status="success",
            operation_id=operation_id,
            actual_duration=actual_duration,
        )

        return {
            "operation_id": operation_id,
            "duration": actual_duration,
            "result": f"Result_{operation_id}",
        }

    # Pattern 1: gather() for concurrent execution
    logger.info(
        "Pattern 1: Using asyncio.gather() for concurrent ops",
        domain="async",
        action="concurrency_pattern",
        status="starting",
        pattern="gather",
    )

    start_time = time.time()

    # Create multiple concurrent operations
    operations = [simulate_rpc_operation(i, 0.1 + (i * 0.05)) for i in range(5)]

    # Execute all operations concurrently
    results_gather: list[dict[str, Any]] = await asyncio.gather(
        *operations
    )  # Annotated results

    total_time = time.time() - start_time

    logger.info(
        "Concurrent operations completed with gather()",
        domain="async",
        action="concurrency_pattern",
        status="success",
        pattern="gather",
        operations_count=len(results_gather),
        total_time=total_time,
        efficiency_gain=f"{len(results_gather)}x faster than sequential",
    )

    # Pattern 2: as_completed() for processing results as they arrive
    logger.info(
        "Pattern 2: Using asyncio.as_completed() for streaming results",
        domain="async",
        action="concurrency_pattern",
        status="starting",
        pattern="as_completed",
    )

    operations_as_completed = [  # Renamed variable
        simulate_rpc_operation(i + 10, 0.2 - (i * 0.03)) for i in range(4)
    ]

    completed_count = 0
    async for coro in asyncio.as_completed(operations_as_completed):
        result_as_completed: dict[str, Any] = await coro  # Annotated result
        completed_count += 1

        logger.info(
            "Operation completed (streaming)",
            domain="async",
            action="streaming_result",
            status="success",
            operation_id=result_as_completed["operation_id"],
            completed_count=completed_count,
            total_operations=len(operations_as_completed),
        )

    # Pattern 3: Semaphore for controlling concurrency
    logger.info(
        "Pattern 3: Using semaphore for concurrency control",
        domain="async",
        action="concurrency_pattern",
        status="starting",
        pattern="semaphore",
    )

    # Limit to 2 concurrent operations
    semaphore = asyncio.Semaphore(2)

    async def controlled_operation(op_id: int) -> dict[str, Any]:  # Changed dict
        async with semaphore:  # Acquire semaphore
            return await simulate_rpc_operation(op_id + 20, 0.1)

    # Create more operations than semaphore allows
    controlled_ops = [controlled_operation(i) for i in range(6)]
    controlled_results: list[dict[str, Any]] = await asyncio.gather(
        *controlled_ops
    )  # Annotated

    logger.info(
        "Controlled concurrency completed",
        domain="async",
        action="concurrency_pattern",
        status="success",
        pattern="semaphore",
        max_concurrent=2,
        total_operations=len(controlled_results),
    )


async def example_6_async_generators() -> None:
    """
    Example 6C: Demonstrates async generator patterns.

    Shows how to use async generators for streaming data
    and handling large datasets efficiently.
    """
    print("\n" + "=" * 60)
    print("🌊 Example 6C: Async Generator Patterns")
    print(" Demonstrates: Streaming data with async generators")
    print("=" * 60)

    async def async_data_generator(
        count: int,
    ) -> AbcAsyncGenerator[dict[str, Any]]:  # Changed dict
        """Generate data asynchronously."""

        logger.info(
            "Starting async data generation",
            domain="async",
            action="generator_start",
            status="starting",
            expected_count=count,
        )

        for i in range(count):
            # Simulate async data generation
            await asyncio.sleep(0.05)

            data_item: dict[str, Any] = {  # Annotated
                "id": i,
                "data": f"generated_data_{i}",
                "timestamp": time.time(),
                "size": len(f"generated_data_{i}"),
            }

            logger.debug(
                f"Generated data item {i}",
                domain="async",
                action="generator_yield",
                status="yielding",
                item_id=i,
                progress=f"{i + 1}/{count}",
            )

            yield data_item

        logger.info(
            "Async data generation completed",
            domain="async",
            action="generator_complete",
            status="success",
            total_generated=count,
        )

    # Pattern 1: Processing async generator with async for
    logger.info(
        "Processing async generator with async for loop",
        domain="async",
        action="generator_pattern",
        status="starting",
        pattern="async_for",
    )

    processed_count = 0
    total_size = 0

    async for data_item_for in async_data_generator(5):  # Renamed data_item
        # Process each item as it's generated
        processed_count += 1
        total_size += data_item_for["size"]  # Used renamed var

        logger.info(
            "Processed streamed data item",
            domain="async",
            action="stream_process",
            status="processed",
            item_id=data_item_for["id"],  # Used renamed var
            processed_count=processed_count,
            cumulative_size=total_size,
        )

    logger.info(
        "Async for loop processing completed",
        domain="async",
        action="generator_pattern",
        status="success",
        pattern="async_for",
        total_processed=processed_count,
        total_size=total_size,
    )

    # Pattern 2: Collecting async generator results
    logger.info(
        "Collecting async generator results",
        domain="async",
        action="generator_pattern",
        status="starting",
        pattern="collect_all",
    )

    collected_items: list[dict[str, Any]] = []  # Annotated
    async for item_collect in async_data_generator(3):  # Renamed item
        collected_items.append(item_collect)  # Used renamed var

    logger.info(
        "Async generator collection completed",
        domain="async",
        action="generator_pattern",
        status="success",
        pattern="collect_all",
        collected_count=len(collected_items),
        memory_usage="all_items_in_memory",
    )


async def example_6_async_error_handling() -> None:
    """
    Example 6D: Demonstrates async error handling patterns.

    Shows proper error handling techniques for async RPC
    operations including timeouts and cancellation.
    """
    print("\n" + "=" * 60)
    print("🚨 Example 6D: Async Error Handling Patterns")
    print(" Demonstrates: Robust async error handling")
    print("=" * 60)

    async def potentially_failing_operation(
        fail_probability: float, operation_id: int
    ) -> str:
        """Operation that may fail or timeout."""

        logger.info(
            f"Starting potentially failing operation {operation_id}",
            domain="async",
            action="risky_operation",
            status="starting",
            operation_id=operation_id,
            fail_probability=fail_probability,
        )

        # Simulate variable processing time
        processing_time = 0.1 + (operation_id * 0.1)
        await asyncio.sleep(processing_time)

        # Simulate random failures
        import random

        if random.random() < fail_probability:  # nosec B311 # random is not used for security/crypto here, just for demo/jitter.
            raise Exception(f"Operation {operation_id} failed randomly")

        return f"Success_result_{operation_id}"

    # Pattern 1: Timeout handling
    logger.info(
        "Pattern 1: Timeout handling with asyncio.wait_for()",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="timeout",
    )

    try:
        # Set timeout for operation
        result_timeout: str = await asyncio.wait_for(  # Annotated
            potentially_failing_operation(0.0, 1), timeout=0.5
        )

        logger.info(
            "Operation completed within timeout",
            domain="async",
            action="error_pattern",
            status="success",
            pattern="timeout",
            result=result_timeout,
        )

    except TimeoutError:
        logger.warning(
            "Operation timed out",
            domain="async",
            action="error_pattern",
            status="timeout",
            pattern="timeout",
        )

    # Pattern 2: Exception handling with retries
    logger.info(
        "Pattern 2: Exception handling with retry logic",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="retry",
    )

    max_retries = 3
    retry_delay = 0.1

    for attempt in range(max_retries):
        try:
            result_retry: str = await potentially_failing_operation(
                0.7, attempt + 10
            )  # Annotated

            logger.info(
                "Operation succeeded after retries",
                domain="async",
                action="error_pattern",
                status="success",
                pattern="retry",
                attempt=attempt + 1,
                result=result_retry,
            )
            break

        except Exception as e:
            if attempt == max_retries - 1:
                logger.error(
                    "Operation failed after all retries",
                    domain="async",
                    action="error_pattern",
                    status="failed",
                    pattern="retry",
                    attempts=max_retries,
                    error=str(e),
                )
            else:
                logger.warning(
                    f"Operation failed, retrying (attempt {attempt + 1})",
                    domain="async",
                    action="error_pattern",
                    status="retry",
                    pattern="retry",
                    attempt=attempt + 1,
                    error=str(e),
                    retry_delay=retry_delay,
                )
                await asyncio.sleep(retry_delay)

    # Pattern 3: Graceful task cancellation
    logger.info(
        "Pattern 3: Graceful task cancellation",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="cancellation",
    )

    # Start a long-running task
    long_task: asyncio.Task[str] = asyncio.create_task(  # Annotated
        potentially_failing_operation(0.0, 100)
    )

    try:
        # Cancel after short delay
        await asyncio.sleep(0.05)
        long_task.cancel()

        # Wait for cancellation to complete
        await long_task

    except asyncio.CancelledError:
        logger.info(
            "Task cancelled gracefully",
            domain="async",
            action="error_pattern",
            status="cancelled",
            pattern="cancellation",
        )

    # Pattern 4: Exception groups (Python 3.11+)
    logger.info(
        "Pattern 4: Handling multiple operation failures",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="multiple_failures",
    )

    # Create multiple operations that may fail
    risky_operations = [potentially_failing_operation(0.5, i) for i in range(20, 25)]

    # Use gather with return_exceptions=True
    results_multiple: list[
        str | BaseException
    ] = await asyncio.gather(  # Annotated
        *risky_operations, return_exceptions=True
    )

    success_count = 0
    failure_count = 0

    for i, res_item in enumerate(results_multiple):  # Renamed result to res_item
        if isinstance(res_item, Exception):
            failure_count += 1
            logger.warning(
                f"Operation {i + 20} failed",
                domain="async",
                action="multiple_results",
                status="failed",
                operation_id=i + 20,
                error=str(res_item),  # Used renamed var
            )
        else:
            success_count += 1
            logger.debug(
                f"Operation {i + 20} succeeded",
                domain="async",
                action="multiple_results",
                status="success",
                operation_id=i + 20,
                result=res_item,  # Used renamed var
            )

    logger.info(
        "Multiple operation handling completed",
        domain="async",
        action="error_pattern",
        status="summary",
        pattern="multiple_failures",
        total_operations=len(results_multiple),
        success_count=success_count,
        failure_count=failure_count,
        success_rate=f"{(success_count / len(results_multiple) * 100):.1f}%",
    )


async def main() -> None:
    """Run all async pattern examples."""
    print("⚙️ pyvider-rpcplugin Async Patterns Examples")
    print("============================================")

    try:
        # Run each async pattern example
        await example_6_async_context_managers()
        await example_6_concurrent_operations()
        await example_6_async_generators()
        await example_6_async_error_handling()

        print("\n" + "=" * 60)
        print("✅ All Async Pattern Examples Completed Successfully!")
        print("=" * 60)
        print("\n⚙️ Async Best Practices:")
        print("  • Use async context managers for resource management")
        print("  • Leverage asyncio.gather() for concurrent operations")
        print("  • Implement proper timeout and cancellation handling")
        print("  • Use async generators for streaming large datasets")
        print("  • Handle exceptions gracefully with retries when appropriate")
        print("\n📖 Next Steps:")
        print("  • See example 07_error_handling.py for comprehensive error patterns")
        print("  • Try example 10_performance_tuning.py for async optimization")
        print("  • Check docs/architecture.md for async design patterns")

    except Exception as e:
        logger.error(
            "Async patterns example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e),
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
