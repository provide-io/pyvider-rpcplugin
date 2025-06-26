#!/usr/bin/env python3
"""
Advanced Async Patterns - Best practices for async RPC operations.
"""

import asyncio
from collections.abc import AsyncGenerator

from example_utils import configure_for_example

configure_for_example()

from pyvider.telemetry import logger


async def concurrent_requests_example():
    """Example: Handling concurrent RPC requests."""
    logger.info("⚡ Concurrent Requests Example")

    async def mock_rpc_call(request_id: int) -> str:
        """Mock RPC call with variable delay."""
        delay = 0.1 * request_id  # Simulate different processing times
        await asyncio.sleep(delay)
        return f"Response for request {request_id}"

    # Process multiple requests concurrently
    request_ids = range(1, 6)
    tasks = [mock_rpc_call(req_id) for req_id in request_ids]

    logger.info(f"🚀 Starting {len(tasks)} concurrent requests")
    results = await asyncio.gather(*tasks)

    for result in results:
        logger.info(f"✅ {result}")

    logger.info("✅ Concurrent requests completed")


async def streaming_example():
    """Example: Async streaming patterns."""
    logger.info("📡 Streaming Example")

    async def mock_stream_data() -> AsyncGenerator[str]:
        """Mock streaming data generator."""
        for i in range(5):
            await asyncio.sleep(0.1)
            yield f"Stream item {i + 1}"

    logger.info("📊 Processing stream data:")
    async for item in mock_stream_data():
        logger.info(f"  📦 Received: {item}")

    logger.info("✅ Streaming example completed")


async def timeout_and_retry_example():
    """Example: Timeout and retry patterns."""
    logger.info("⏱️  Timeout and Retry Example")

    async def unreliable_operation(attempt: int) -> str:
        """Mock unreliable operation."""
        if attempt < 3:
            await asyncio.sleep(0.2)
            raise Exception(f"Attempt {attempt} failed")
        return f"Success on attempt {attempt}"

    # Retry with exponential backoff
    max_retries = 3
    base_delay = 0.1

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"🔄 Attempt {attempt}")
            result = await asyncio.wait_for(unreliable_operation(attempt), timeout=1.0)
            logger.info(f"✅ {result}")
            break
        except TimeoutError:
            logger.warning(f"⏰ Attempt {attempt} timed out")
        except Exception as e:
            logger.warning(f"⚠️  Attempt {attempt} failed: {e}")

        if attempt < max_retries:
            delay = base_delay * (2 ** (attempt - 1))
            logger.info(f"😴 Waiting {delay}s before retry")
            await asyncio.sleep(delay)

    logger.info("✅ Timeout and retry example completed")


async def main():
    """Run async pattern examples."""
    logger.info("🚀 Advanced Async Patterns")

    await concurrent_requests_example()
    await streaming_example()
    await timeout_and_retry_example()

    logger.info("✅ All async pattern examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍⚡
