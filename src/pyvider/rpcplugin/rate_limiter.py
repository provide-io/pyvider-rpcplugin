#
# src/pyvider/rpcplugin/rate_limiter.py
#

"""
Rate Limiting Utilities for Pyvider RPC Plugin.

This module provides a token bucket rate limiter implementation suitable for
asynchronous applications, helping to manage request load and prevent abuse.
"""

import asyncio
import time
from typing import final

from pyvider.telemetry import logger


@final
class TokenBucketRateLimiter:
    """
    A Token Bucket rate limiter for asyncio applications.

    This limiter allows for bursts up to a specified capacity and refills tokens
    at a constant rate. It is designed to be thread-safe using an asyncio.Lock.
    """

    def __init__(self, capacity: float, refill_rate: float) -> None:
        """
        Initialize the TokenBucketRateLimiter.

        Args:
            capacity: The maximum number of tokens the bucket can hold
                      (burst capacity).
            refill_rate: The rate at which tokens are refilled per second.
        """
        if capacity <= 0:
            raise ValueError("Capacity must be positive.")
        if refill_rate <= 0:
            raise ValueError("Refill rate must be positive.")

        self._capacity: float = float(capacity)
        self._refill_rate: float = float(refill_rate)
        self._tokens: float = float(capacity)  # Start with a full bucket
        self._last_refill_timestamp: float = time.monotonic()
        self._lock: asyncio.Lock = asyncio.Lock()
        logger.debug(
            "🔩🗑️ TokenBucketRateLimiter initialized: "
            f"capacity={capacity}, refill_rate={refill_rate}"
        )

    async def _refill_tokens(self) -> None:
        """
        Refills tokens based on the elapsed time since the last refill.
        This method is not locked internally; caller must hold the lock.
        """
        now = time.monotonic()
        elapsed_time = now - self._last_refill_timestamp
        if elapsed_time > 0:  # only refill if time has passed
            tokens_to_add = elapsed_time * self._refill_rate
            # logger.debug(
            #     f"🔩🗑️ Refilling: elapsed={elapsed_time:.4f}s, "
            #     f"tokens_to_add={tokens_to_add:.4f}, "
            #     f"current_tokens={self._tokens:.4f}"
            # )
            self._tokens = min(self._capacity, self._tokens + tokens_to_add)
            self._last_refill_timestamp = now
            # logger.debug(
            #     f"🔩🗑️ Refilled: new_tokens={self._tokens:.4f}, "
            #     f"last_refill_timestamp={self._last_refill_timestamp:.4f}"
            # )

    async def is_allowed(self) -> bool:
        """
        Check if a request is allowed based on available tokens.

        This method is asynchronous and thread-safe. It refills tokens
        based on elapsed time and then attempts to consume a token.

        Returns:
            True if the request is allowed, False otherwise.
        """
        async with self._lock:
            await self._refill_tokens()  # Refill before checking

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                logger.debug(
                    "🔩🗑️✅ Request allowed. Tokens remaining: "
                    f"{self._tokens:.2f}/{self._capacity:.2f}"
                )
                return True
            else:
                logger.warning(
                    "🔩🗑️❌ Request denied. No tokens available. Tokens: "
                    f"{self._tokens:.2f}/{self._capacity:.2f}"
                )
                return False

    async def get_current_tokens(self) -> float:
        """Returns the current number of tokens, for testing/monitoring."""
        async with self._lock:
            # It might be useful to refill before getting, to get the most
            # up-to-date count
            # await self._refill_tokens()
            return self._tokens


async def main() -> None:
    limiter = TokenBucketRateLimiter(capacity=5, refill_rate=1)  # 5 tokens, 1 token/sec

    for i in range(10):
        if await limiter.is_allowed():
            logger.info(f"Request {i + 1} allowed.")
        else:
            logger.info(f"Request {i + 1} denied.")

        if i == 5:  # After 6 requests (0-5)
            logger.info("Waiting for 2 seconds to allow tokens to refill...")
            await asyncio.sleep(2)

    logger.info(f"Final tokens: {await limiter.get_current_tokens()}")


if __name__ == "__main__":
    # This example won't run directly as-is without an event loop manager
    # if used outside of an existing asyncio context.
    # To run:
    # loop = asyncio.get_event_loop()
    # loop.run_until_complete(main())
    pass


# 🐍🏗️🔌
