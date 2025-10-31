#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Advanced Async Patterns - Best practices for async RPC operations."""

import asyncio
from collections.abc import AsyncGenerator

from example_utils import configure_for_example  # type: ignore[import-not-found]

configure_for_example()

from provide.foundation import logger  # noqa: E402


async def concurrent_requests_example() -> None:
    """Example: Handling concurrent RPC requests."""
    logger.info("⚡ Concurrent Requests Example")

    async def mock_rpc_call(request_id: int) -> str:
        """Simulates an RPC call that takes some time."""
        delay = 0.1 * request_id  # Different requests take different times
        logger.info(f"  -> Starting mock RPC call {request_id} (will take {delay:.1f}s)")
        await asyncio.sleep(delay)
        response = f"Response for request {request_id}"
        logger.info(f"  <- Finished mock RPC call {request_id}")
        return response

    request_ids = range(1, 6)  # Create 5 requests
    # Create a list of coroutine objects (tasks to be done)
    tasks = [mock_rpc_call(req_id) for req_id in request_ids]

    logger.info(f"🚀 Launching {len(tasks)} mock RPC calls concurrently...")
    # asyncio.gather runs all awaitables in the list concurrently.
    # It waits for all of them to complete and returns a list of their results.
    results = await asyncio.gather(*tasks)

    for result in results:
        logger.info(f"  ✅ {result}")


async def streaming_example() -> None:
    """Demonstrates consuming an asynchronous stream of data."""
    logger.info("📡 Streaming Example")

    async def mock_data_stream() -> AsyncGenerator[str]:
        """Simulates a server streaming data to a client."""
        for i in range(5):
            await asyncio.sleep(0.2)  # Simulate delay between stream items
            item = f"Stream item {i + 1}"
            logger.info(f"  ~> Server yielding: {item}")
            yield item  # Yield data item
        logger.info("  ~> Server stream finished.")

    logger.info("📊 Client processing stream data:")
    # 'async for' iterates over an asynchronous generator or iterable.
    # It awaits the next item from the stream.
    async for item in mock_data_stream():
        logger.info(f"  ✅ Received: {item}")


async def timeout_and_retry_example() -> None:
    """Illustrates basic timeout and retry logic for an unreliable async operation."""
    logger.info("⏱️  Timeout and Retry Example")

    async def unreliable_operation(attempt_number: int) -> str:
        """Simulates an operation that might fail or take too long."""
        logger.info(f"  Attempting operation (attempt {attempt_number})...")
        # Simulate potential failure
        if attempt_number < 3:
            await asyncio.sleep(0.5)  # Simulate some work before failing
            raise Exception(f"Simulated failure on attempt {attempt_number}")
        # Simulate success on the 3rd attempt
        await asyncio.sleep(0.1)
        return f"Operation successful on attempt {attempt_number}!"

    max_retries = 3
    base_retry_delay = 0.1  # seconds

    for current_attempt in range(1, max_retries + 2):  # Try up to max_retries + 1 times
        try:
            # asyncio.wait_for adds a timeout to an awaitable. If the operation
            # takes longer than 1.0 second, it raises asyncio.TimeoutError.
            result = await asyncio.wait_for(unreliable_operation(current_attempt), timeout=1.0)
            break  # Success, exit retry loop
        except TimeoutError:
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
            delay = base_retry_delay * (2 ** (current_attempt - 1))  # Exponential backoff
            logger.info(f"😴 Waiting {delay:.2f}s before next retry...")
            await asyncio.sleep(delay)


async def main() -> None:
    """Run async pattern examples."""
    logger.info("🚀 Advanced Async Patterns Examples")

    await concurrent_requests_example()
    await asyncio.sleep(0.5)  # Pause between examples for log readability
    await streaming_example()
    await asyncio.sleep(0.5)
    await timeout_and_retry_example()


if __name__ == "__main__":
    asyncio.run(main())

# 🔌📞🔚
