#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Performance Tuning - Performance benchmarking and optimization patterns."""

import asyncio
from collections.abc import Generator  # Added for create_generator
import time
from typing import Any  # Import Any

from example_utils import configure_for_example  # type: ignore[import-not-found]

configure_for_example()

from provide.foundation import logger  # noqa: E402


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
            await pool.release_connection(conn)  # Assuming conn is the id str
            return f"Request {request_id} completed"

        tasks.append(use_connection(i))

    await asyncio.gather(*tasks)
    monitor.end_timer("connection_test")

    monitor.report()


async def batch_processing_example() -> None:
    """Example: Batch processing optimization."""

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


async def memory_optimization_example() -> None:
    """Example: Memory optimization techniques."""
    logger.info("💾 Memory Optimization Example")

    import sys

    # Generator vs list comparison
    def create_large_list(size: int) -> list[str]:
        """Create large list (memory intensive)."""
        return [f"item_{i}" for i in range(size)]

    def create_generator(size: int) -> Generator[str]:
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
    logger.info(f"💰 Memory savings: {memory_savings:,} bytes ({memory_savings / list_size * 100:.1f}%)")


async def main() -> None:
    """Run performance tuning examples."""
    logger.info("🚀 Performance Tuning Examples")

    await connection_pooling_example()
    await batch_processing_example()
    await memory_optimization_example()

    logger.info("🏁 Performance Guidelines:")
    logger.info("  🏊 Use connection pooling for high-concurrency scenarios")
    logger.info("  💾 Use generators for large datasets to save memory")
    logger.info("  ⏱️  Profile your application to identify bottlenecks")
    logger.info("  📊 Monitor key metrics in production")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔌📞🔚
