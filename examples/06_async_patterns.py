#!/usr/bin/env python3
# examples/06_async_patterns.py
"""Demonstrates async programming patterns and best practices with pyvider-rpcplugin."""

import asyncio
import sys
import time
from pathlib import Path
from typing import AsyncGenerator

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    create_basic_protocol,
)
from pyvider.telemetry import logger  # noqa: E402


class AsyncStreamHandler:
    """Handler demonstrating async streaming patterns."""
    
    def __init__(self):
        self.active_streams = 0
        self.total_messages = 0
    
    async def ProcessStream(self, request_iterator, context):
        """Handle streaming requests asynchronously."""
        self.active_streams += 1
        
        logger.info(
            "Started processing stream",
            domain="async",
            action="stream_start",
            status="starting",
            active_streams=self.active_streams
        )
        
        try:
            async for request in request_iterator:
                self.total_messages += 1
                
                # Simulate async processing
                await asyncio.sleep(0.01)
                
                message = getattr(request, 'message', 'empty')
                logger.debug(
                    "Processed stream message",
                    domain="async",
                    action="stream_message",
                    status="processed",
                    message_id=self.total_messages,
                    content_length=len(message)
                )
                
                # Yield response asynchronously
                yield type('StreamReply', (), {
                    'response': f"Processed: {message}",
                    'message_id': self.total_messages
                })()
                
        finally:
            self.active_streams -= 1
            
            logger.info(
                "Completed processing stream",
                domain="async",
                action="stream_complete",
                status="success",
                active_streams=self.active_streams,
                total_messages=self.total_messages
            )
    
    async def BatchProcess(self, request, context):
        """Handle batch processing with concurrent workers."""
        batch_size = getattr(request, 'batch_size', 10)
        
        logger.info(
            "Starting batch processing",
            domain="async",
            action="batch_start",
            status="starting",
            batch_size=batch_size
        )
        
        # Create concurrent tasks
        async def process_item(item_id: int):
            await asyncio.sleep(0.1)  # Simulate work
            return f"Item_{item_id}_processed"
        
        # Process batch concurrently
        tasks = [process_item(i) for i in range(batch_size)]
        results = await asyncio.gather(*tasks)
        
        logger.info(
            "Batch processing completed",
            domain="async",
            action="batch_complete",
            status="success",
            batch_size=batch_size,
            results_count=len(results)
        )
        
        return type('BatchReply', (), {
            'results': results,
            'processed_count': len(results)
        })()


async def example_6_async_context_managers():
    """
    Example 6A: Demonstrates async context manager patterns.
    
    Shows how to use async context managers for proper resource
    management in async RPC applications.
    """
    print("\n" + "=" * 60)
    print("🔧 Example 6A: Async Context Manager Patterns")
    print(" Demonstrates: Proper async resource management")
    print("=" * 60)
    
    class AsyncRPCManager:
        """Async context manager for RPC resources."""
        
        def __init__(self, transport: str = "unix"):
            self.transport = transport
            self.server = None
            self.client = None
            self.server_task = None
        
        async def __aenter__(self):
            logger.info(
                "Entering async RPC context",
                domain="async",
                action="context_enter",
                status="starting",
                transport=self.transport
            )
            
            # Setup server
            protocol = create_basic_protocol()
            handler = AsyncStreamHandler()
            
            self.server = plugin_server(
                protocol=protocol,
                handler=handler,
                transport=self.transport
            )
            
            # Start server
            self.server_task = asyncio.create_task(self.server.serve())
            await asyncio.sleep(0.5)  # Let server initialize
            
            # Create client
            # plugin_client expects a server_path (executable).
            # The self.transport argument of AsyncRPCManager is not directly used here
            # for the client factory in its current form.
            self.client = plugin_client(server_path="./dummy_server.sh")
            
            logger.info(
                "Async RPC context ready",
                domain="async",
                action="context_enter",
                status="success",
                server_running=True,
                client_ready=True
            )
            
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            logger.info(
                "Exiting async RPC context",
                domain="async",
                action="context_exit",
                status="starting",
                has_exception=exc_type is not None
            )
            
            # Cleanup client
            if self.client:
                await self.client.close()
            
            # Cleanup server
            if self.server:
                await self.server.stop()
            
            if self.server_task:
                await self.server_task
            
            logger.info(
                "Async RPC context cleanup completed",
                domain="async",
                action="context_exit",
                status="success"
            )
        
        async def make_call(self, method_name: str, data: str):
            """Make an async RPC call."""
            logger.info(
                f"Making async RPC call: {method_name}",
                domain="async",
                action="rpc_call",
                status="starting",
                method=method_name,
                data_length=len(data)
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
                result_length=len(result)
            )
            
            return result
    
    # Demonstrate async context manager usage
    async with AsyncRPCManager("unix") as rpc:
        # Use RPC services within context
        result1 = await rpc.make_call("ProcessData", "sample_data_1")
        result2 = await rpc.make_call("ProcessData", "sample_data_2")
        
        logger.info(
            "Context manager example completed",
            domain="async",
            action="context_demo",
            status="success",
            calls_made=2,
            automatic_cleanup=True
        )


async def example_6_concurrent_operations():
    """
    Example 6B: Demonstrates concurrent async operations.
    
    Shows how to handle multiple concurrent RPC operations
    efficiently using asyncio patterns.
    """
    print("\n" + "=" * 60)
    print("⚡ Example 6B: Concurrent Async Operations")
    print(" Demonstrates: High-concurrency async RPC patterns")
    print("=" * 60)
    
    async def simulate_rpc_operation(operation_id: int, duration: float):
        """Simulate an async RPC operation."""
        start_time = time.time()
        
        logger.info(
            f"Starting operation {operation_id}",
            domain="async",
            action="concurrent_op",
            status="starting",
            operation_id=operation_id,
            estimated_duration=duration
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
            actual_duration=actual_duration
        )
        
        return {
            'operation_id': operation_id,
            'duration': actual_duration,
            'result': f'Result_{operation_id}'
        }
    
    # Pattern 1: gather() for concurrent execution
    logger.info(
        "Pattern 1: Using asyncio.gather() for concurrent ops",
        domain="async",
        action="concurrency_pattern",
        status="starting",
        pattern="gather"
    )
    
    start_time = time.time()
    
    # Create multiple concurrent operations
    operations = [
        simulate_rpc_operation(i, 0.1 + (i * 0.05)) 
        for i in range(5)
    ]
    
    # Execute all operations concurrently
    results = await asyncio.gather(*operations)
    
    total_time = time.time() - start_time
    
    logger.info(
        "Concurrent operations completed with gather()",
        domain="async",
        action="concurrency_pattern",
        status="success",
        pattern="gather",
        operations_count=len(results),
        total_time=total_time,
        efficiency_gain=f"{len(results)}x faster than sequential"
    )
    
    # Pattern 2: as_completed() for processing results as they arrive
    logger.info(
        "Pattern 2: Using asyncio.as_completed() for streaming results",
        domain="async",
        action="concurrency_pattern",
        status="starting",
        pattern="as_completed"
    )
    
    operations = [
        simulate_rpc_operation(i + 10, 0.2 - (i * 0.03)) 
        for i in range(4)
    ]
    
    completed_count = 0
    async for coro in asyncio.as_completed(operations):
        result = await coro
        completed_count += 1
        
        logger.info(
            "Operation completed (streaming)",
            domain="async",
            action="streaming_result",
            status="success",
            operation_id=result['operation_id'],
            completed_count=completed_count,
            total_operations=len(operations)
        )
    
    # Pattern 3: Semaphore for controlling concurrency
    logger.info(
        "Pattern 3: Using semaphore for concurrency control",
        domain="async",
        action="concurrency_pattern",
        status="starting",
        pattern="semaphore"
    )
    
    # Limit to 2 concurrent operations
    semaphore = asyncio.Semaphore(2)
    
    async def controlled_operation(op_id: int):
        async with semaphore:  # Acquire semaphore
            return await simulate_rpc_operation(op_id + 20, 0.1)
    
    # Create more operations than semaphore allows
    controlled_ops = [controlled_operation(i) for i in range(6)]
    controlled_results = await asyncio.gather(*controlled_ops)
    
    logger.info(
        "Controlled concurrency completed",
        domain="async",
        action="concurrency_pattern",
        status="success",
        pattern="semaphore",
        max_concurrent=2,
        total_operations=len(controlled_results)
    )


async def example_6_async_generators():
    """
    Example 6C: Demonstrates async generator patterns.
    
    Shows how to use async generators for streaming data
    and handling large datasets efficiently.
    """
    print("\n" + "=" * 60)
    print("🌊 Example 6C: Async Generator Patterns")
    print(" Demonstrates: Streaming data with async generators")
    print("=" * 60)
    
    async def async_data_generator(count: int) -> AsyncGenerator[dict, None]:
        """Generate data asynchronously."""
        
        logger.info(
            "Starting async data generation",
            domain="async",
            action="generator_start",
            status="starting",
            expected_count=count
        )
        
        for i in range(count):
            # Simulate async data generation
            await asyncio.sleep(0.05)
            
            data_item = {
                'id': i,
                'data': f'generated_data_{i}',
                'timestamp': time.time(),
                'size': len(f'generated_data_{i}')
            }
            
            logger.debug(
                f"Generated data item {i}",
                domain="async",
                action="generator_yield",
                status="yielding",
                item_id=i,
                progress=f"{i+1}/{count}"
            )
            
            yield data_item
        
        logger.info(
            "Async data generation completed",
            domain="async",
            action="generator_complete",
            status="success",
            total_generated=count
        )
    
    # Pattern 1: Processing async generator with async for
    logger.info(
        "Processing async generator with async for loop",
        domain="async",
        action="generator_pattern",
        status="starting",
        pattern="async_for"
    )
    
    processed_count = 0
    total_size = 0
    
    async for data_item in async_data_generator(5):
        # Process each item as it's generated
        processed_count += 1
        total_size += data_item['size']
        
        logger.info(
            "Processed streamed data item",
            domain="async",
            action="stream_process",
            status="processed",
            item_id=data_item['id'],
            processed_count=processed_count,
            cumulative_size=total_size
        )
    
    logger.info(
        "Async for loop processing completed",
        domain="async",
        action="generator_pattern",
        status="success",
        pattern="async_for",
        total_processed=processed_count,
        total_size=total_size
    )
    
    # Pattern 2: Collecting async generator results
    logger.info(
        "Collecting async generator results",
        domain="async",
        action="generator_pattern",
        status="starting",
        pattern="collect_all"
    )
    
    collected_items = []
    async for item in async_data_generator(3):
        collected_items.append(item)
    
    logger.info(
        "Async generator collection completed",
        domain="async",
        action="generator_pattern",
        status="success",
        pattern="collect_all",
        collected_count=len(collected_items),
        memory_usage="all_items_in_memory"
    )


async def example_6_async_error_handling():
    """
    Example 6D: Demonstrates async error handling patterns.
    
    Shows proper error handling techniques for async RPC
    operations including timeouts and cancellation.
    """
    print("\n" + "=" * 60)
    print("🚨 Example 6D: Async Error Handling Patterns")
    print(" Demonstrates: Robust async error handling")
    print("=" * 60)
    
    async def potentially_failing_operation(fail_probability: float, operation_id: int):
        """Operation that may fail or timeout."""
        
        logger.info(
            f"Starting potentially failing operation {operation_id}",
            domain="async",
            action="risky_operation",
            status="starting",
            operation_id=operation_id,
            fail_probability=fail_probability
        )
        
        # Simulate variable processing time
        processing_time = 0.1 + (operation_id * 0.1)
        await asyncio.sleep(processing_time)
        
        # Simulate random failures
        import random
        if random.random() < fail_probability:
            raise Exception(f"Operation {operation_id} failed randomly")
        
        return f"Success_result_{operation_id}"
    
    # Pattern 1: Timeout handling
    logger.info(
        "Pattern 1: Timeout handling with asyncio.wait_for()",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="timeout"
    )
    
    try:
        # Set timeout for operation
        result = await asyncio.wait_for(
            potentially_failing_operation(0.0, 1),
            timeout=0.5
        )
        
        logger.info(
            "Operation completed within timeout",
            domain="async",
            action="error_pattern",
            status="success",
            pattern="timeout",
            result=result
        )
        
    except asyncio.TimeoutError:
        logger.warning(
            "Operation timed out",
            domain="async",
            action="error_pattern",
            status="timeout",
            pattern="timeout"
        )
    
    # Pattern 2: Exception handling with retries
    logger.info(
        "Pattern 2: Exception handling with retry logic",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="retry"
    )
    
    max_retries = 3
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            result = await potentially_failing_operation(0.7, attempt + 10)
            
            logger.info(
                "Operation succeeded after retries",
                domain="async",
                action="error_pattern",
                status="success",
                pattern="retry",
                attempt=attempt + 1,
                result=result
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
                    error=str(e)
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
                    retry_delay=retry_delay
                )
                await asyncio.sleep(retry_delay)
    
    # Pattern 3: Graceful task cancellation
    logger.info(
        "Pattern 3: Graceful task cancellation",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="cancellation"
    )
    
    # Start a long-running task
    long_task = asyncio.create_task(
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
            pattern="cancellation"
        )
    
    # Pattern 4: Exception groups (Python 3.11+)
    logger.info(
        "Pattern 4: Handling multiple operation failures",
        domain="async",
        action="error_pattern",
        status="starting",
        pattern="multiple_failures"
    )
    
    # Create multiple operations that may fail
    risky_operations = [
        potentially_failing_operation(0.5, i) 
        for i in range(20, 25)
    ]
    
    # Use gather with return_exceptions=True
    results = await asyncio.gather(*risky_operations, return_exceptions=True)
    
    success_count = 0
    failure_count = 0
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            failure_count += 1
            logger.warning(
                f"Operation {i + 20} failed",
                domain="async",
                action="multiple_results",
                status="failed",
                operation_id=i + 20,
                error=str(result)
            )
        else:
            success_count += 1
            logger.debug(
                f"Operation {i + 20} succeeded",
                domain="async",
                action="multiple_results",
                status="success",
                operation_id=i + 20,
                result=result
            )
    
    logger.info(
        "Multiple operation handling completed",
        domain="async",
        action="error_pattern",
        status="summary",
        pattern="multiple_failures",
        total_operations=len(results),
        success_count=success_count,
        failure_count=failure_count,
        success_rate=f"{(success_count/len(results)*100):.1f}%"
    )


async def main():
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
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
