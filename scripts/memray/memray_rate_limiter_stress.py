#!/usr/bin/env python
# SPDX-FileCopyrightText: Copyright (c) 2026 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Memray stress test for rate limiting interceptor hot path."""

import asyncio
import os
from typing import Any

os.environ["PLUGIN_LOG_LEVEL"] = "ERROR"

from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

from pyvider.rpcplugin.server.core import RateLimitingInterceptor


class _MockHandlerCallDetails:
    """Minimal mock for grpc.HandlerCallDetails."""

    __slots__ = ("invocation_metadata", "method")

    def __init__(self, method: str = "/test.Service/Method") -> None:
        self.method = method
        self.invocation_metadata = []


class _MockRpcMethodHandler:
    """Minimal mock for grpc.RpcMethodHandler."""


async def _mock_continuation(handler_call_details: Any) -> Any:
    """Mock continuation that returns a handler."""
    return _MockRpcMethodHandler()


async def main() -> None:
    """Stress test rate limiting interceptor."""

    # Create rate limiter with very high rate to avoid exhaustion.
    # Suppress per-request debug logging inside is_allowed().
    try:
        limiter = TokenBucketRateLimiter(
            capacity=1_000_000,
            refill_rate=1_000_000.0,
            logger=None,
        )
    except TypeError:
        limiter = TokenBucketRateLimiter(
            capacity=1_000_000,
            refill_rate=1_000_000.0,
        )
        limiter._logger = None
    interceptor = RateLimitingInterceptor(limiter)
    details = _MockHandlerCallDetails()

    # --- Warmup ---
    for _ in range(100):
        await interceptor.intercept_service(_mock_continuation, details)

    # --- Stress: intercept_service (50K cycles) ---
    for _i in range(50_000):
        await interceptor.intercept_service(_mock_continuation, details)

    # --- Stress: varying method names (10K cycles) ---
    method_details = [_MockHandlerCallDetails(f"/test.Service/Method{i % 20}") for i in range(20)]
    for i in range(10_000):
        await interceptor.intercept_service(_mock_continuation, method_details[i % 20])

    print("Rate limiter stress test complete: 60K total cycles")


if __name__ == "__main__":
    asyncio.run(main())
