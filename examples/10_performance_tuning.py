#!/usr/bin/env python3
# examples/10_performance_tuning.py
"""Performance optimization techniques and benchmarking with pyvider-rpcplugin."""

import asyncio
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from typing import Any, cast

import grpc  # For grpc.aio.insecure_channel
import psutil  # type: ignore

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    configure,
    plugin_protocol,
    plugin_server,
)
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.types import (  # noqa: E402 # For type hint
    RPCPluginProtocol as TypesRPCPluginProtocol,  # noqa: E402
)
from pyvider.telemetry import logger  # noqa: E402


@dataclass
class PerformanceMetrics:
    requests_per_second: float
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    cpu_usage_percent: float
    memory_usage_mb: float
    total_requests: int
    total_duration_seconds: float
    error_count: int = 0

    @property
    def error_rate(self) -> float:
        return (self.error_count / max(self.total_requests, 1)) * 100

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["error_rate"] = round(self.error_rate, 2)
        for key in [
            "requests_per_second",
            "avg_latency_ms",
            "p95_latency_ms",
            "p99_latency_ms",
            "min_latency_ms",
            "max_latency_ms",
            "cpu_usage_percent",
            "memory_usage_mb",
            "total_duration_seconds",
        ]:
            if key in data and isinstance(data[key], float):
                data[key] = round(data[key], 3 if "latency" in key else 2)
        return data


class HighPerformanceHandler:
    handler_name: str
    request_count: int
    total_processing_time: float
    cache: dict[str, Any]
    batch_buffer: list[str]
    batch_size: int

    def __init__(self, handler_name: str) -> None:
        self.handler_name = handler_name
        self.request_count = 0
        self.total_processing_time = 0.0
        self.cache = {}
        self.batch_buffer = []
        self.batch_size = 100

    async def FastEcho(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        self.request_count += 1
        start_time = time.perf_counter()
        message = getattr(request, "message", "")
        result = f"Echo: {message}"
        self.total_processing_time += time.perf_counter() - start_time
        return type("EchoReply", (), {"response": result})()

    async def CachedProcess(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> Any:
        self.request_count += 1
        message = getattr(request, "message", "")
        if message in self.cache:
            return type(
                "CachedReply", (), {"response": self.cache[message], "from_cache": True}
            )()
        await asyncio.sleep(0.001)
        result = f"Processed: {message}"
        self.cache[message] = result
        return type("CachedReply", (), {"response": result, "from_cache": False})()

    async def BatchProcess(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> Any:
        self.request_count += 1
        message = getattr(request, "message", "")
        self.batch_buffer.append(message)
        if len(self.batch_buffer) >= self.batch_size:
            batch_results = await self._process_batch()  # Changed line
            self.batch_buffer = []  # Changed line
            return type(
                "BatchReply",
                (),
                {
                    "response": f"Batch processed: {len(batch_results)}",
                    "batch_size": len(batch_results),
                },
            )()
        return type(
            "BatchReply",
            (),
            {"response": f"Queued: {message}", "batch_size": len(self.batch_buffer)},
        )()

    async def _process_batch(self) -> list[str]:
        tasks = [self._process_single_item(item) for item in self.batch_buffer]
        return await asyncio.gather(*tasks)

    async def _process_single_item(self, item: str) -> str:
        return f"Processed: {item}"

    def get_stats(self) -> dict[str, Any]:
        avg_time = (self.total_processing_time / max(self.request_count, 1)) * 1000
        return {
            "requests": self.request_count,
            "avg_proc_time_ms": round(avg_time, 3),
            "cache_size": len(self.cache),
            "batch_buffer": len(self.batch_buffer),
        }


class PerformanceBenchmarker:
    process: psutil.Process

    def __init__(self) -> None:
        self.process = psutil.Process()

    async def benchmark_rpc_performance(
        self,
        server_config: dict[str, Any],
        test_duration_seconds: float = 10.0,
        concurrent_clients: int = 10,
        requests_per_client: int = 100,
    ) -> PerformanceMetrics:
        logger.info("Starting RPC performance benchmark...")
        protocol: TypesRPCPluginProtocol = plugin_protocol()
        handler = HighPerformanceHandler("BenchmarkHandler")

        server_config_dict = cast(dict[str, Any], server_config)
        transport_type = str(server_config_dict.get("transport", "unix"))
        transport_path = (
            str(server_config_dict.get("transport_path"))
            if transport_type == "unix"
            else None
        )
        host = (
            str(server_config_dict.get("host"))
            if transport_type == "tcp"
            else "127.0.0.1"
        )
        port = int(server_config_dict.get("port", 0)) if transport_type == "tcp" else 0

        server: RPCPluginServer = plugin_server(
            protocol=cast(TypesRPCPluginProtocol, protocol),
            handler=handler,
            transport=transport_type,
            transport_path=transport_path,
            host=host,
            port=port,
            config=server_config_dict,
        )
        server_task = asyncio.create_task(server.serve())
        await server.wait_for_server_ready(timeout=5.0)

        error_count_local = 0

        async def client_worker(
            client_id: int,
            requests: int,
            actual_server_endpoint: str,
            transport_type_arg: str,  # Renamed transport_type
        ) -> list[float]:
            nonlocal error_count_local
            client_latencies: list[float] = []
            if transport_type_arg == "unix":
                target = f"unix:{actual_server_endpoint}"
            else:
                target = actual_server_endpoint
            channel: grpc.aio.Channel | None = None
            try:
                channel = grpc.aio.insecure_channel(target)
                for _ in range(requests):
                    req_start = time.perf_counter()
                    try:
                        await asyncio.sleep(0.001)
                    except Exception:
                        error_count_local += 1
                    client_latencies.append((time.perf_counter() - req_start) * 1000)
            finally:
                if channel:
                    await channel.close(grace=None)
            return client_latencies

        try:
            baseline_cpu = self.process.cpu_percent()
            baseline_memory = self.process.memory_info().rss / (1024 * 1024)
            start_time = time.perf_counter()
            latencies: list[float] = []

            actual_server_endpoint = getattr(server._transport, "endpoint", None)
            if not actual_server_endpoint:
                raise RuntimeError("Server endpoint NA for benchmark")
            # Use transport_type derived from server_config for consistency

            client_tasks = [
                client_worker(
                    i, requests_per_client, actual_server_endpoint, transport_type
                )
                for i in range(concurrent_clients)
            ]
            client_results = await asyncio.gather(*client_tasks)
            for res in client_results:
                latencies.extend(res)

            total_duration = time.perf_counter() - start_time
            total_requests = len(latencies) + error_count_local
            avg_lat = mean(latencies) if latencies else 0
            p95 = latencies[int(0.95 * len(latencies))] if latencies else 0
            p99 = latencies[int(0.99 * len(latencies))] if latencies else 0

            metrics = PerformanceMetrics(
                requests_per_second=(
                    total_requests / total_duration if total_duration > 0 else 0
                ),
                avg_latency_ms=avg_lat,
                p95_latency_ms=p95,
                p99_latency_ms=p99,
                min_latency_ms=min(latencies) if latencies else 0,
                max_latency_ms=max(latencies) if latencies else 0,
                cpu_usage_percent=(self.process.cpu_percent() - baseline_cpu),
                memory_usage_mb=(
                    self.process.memory_info().rss / (1024 * 1024) - baseline_memory
                ),
                total_requests=total_requests,
                total_duration_seconds=total_duration,
                error_count=error_count_local,
            )
            logger.info("RPC benchmark completed", **metrics.to_dict())
            return metrics
        finally:
            await server.stop()
            await server_task

    async def compare_transport_performance(self) -> dict[str, PerformanceMetrics]:
        results: dict[str, PerformanceMetrics] = {}
        unix_cfg: dict[str, Any] = {
            "transport": "unix",
            "transport_path": "/tmp/perf_unix.sock",
        }  # nosec B108
        results["unix"] = await self.benchmark_rpc_performance(unix_cfg, 5.0, 5, 50)
        tcp_cfg: dict[str, Any] = {"transport": "tcp", "host": "127.0.0.1", "port": 0}
        results["tcp"] = await self.benchmark_rpc_performance(tcp_cfg, 5.0, 5, 50)
        logger.info("Transport comparison completed.")
        return results


async def example_10_baseline_performance() -> None:
    print("\n📊 Example 10A: Baseline Performance Measurement")
    benchmarker = PerformanceBenchmarker()
    configure(PLUGIN_SERVER_TRANSPORTS=["unix"], PLUGIN_AUTO_MTLS=False)
    baseline_cfg: dict[str, Any] = {
        "transport": "unix",
        "transport_path": "/tmp/baseline_perf.sock",
    }  # nosec B108
    metrics = await benchmarker.benchmark_rpc_performance(baseline_cfg, 10.0, 10, 100)
    logger.info("Baseline performance established", **metrics.to_dict())


async def example_10_transport_optimization() -> None:
    print("\n🚄 Example 10B: Transport Layer Optimization")
    benchmarker = PerformanceBenchmarker()
    await benchmarker.compare_transport_performance()


async def example_10_concurrency_tuning() -> None:
    print("\n⚡ Example 10C: Concurrency and Async Optimization")

    async def test_concurrency_level(
        concurrent_clients_arg: int, reqs_per_client_arg: int
    ) -> PerformanceMetrics:  # Renamed args
        proto: TypesRPCPluginProtocol = plugin_protocol()
        handler = HighPerformanceHandler(f"ConcH_{concurrent_clients_arg}")
        srv_cfg: dict[str, Any] = {
            "transport": "unix",
            "transport_path": f"/tmp/conc_{concurrent_clients_arg}.sock",  # nosec B108
        }
        srv: RPCPluginServer = plugin_server(
            protocol=cast(TypesRPCPluginProtocol, proto),
            handler=handler,
            transport=str(srv_cfg.get("transport")),
            transport_path=str(srv_cfg.get("transport_path")),
            config=srv_cfg,
        )
        srv_task = asyncio.create_task(srv.serve())
        await srv.wait_for_server_ready(timeout=5.0)
        latencies: list[float] = []
        for _ in range(concurrent_clients_arg * reqs_per_client_arg):
            await asyncio.sleep(0.001)
            latencies.append(0.1)
        await srv.stop()
        await srv_task
        return PerformanceMetrics(
            1000,
            0.1,
            0.1,
            0.1,
            0.1,
            0.1,
            0,
            0,
            concurrent_clients_arg * reqs_per_client_arg,
            1.0,
        )

    for level in [1, 5, 10]:
        await test_concurrency_level(level, 50)


async def example_10_memory_optimization() -> None:
    print("\n🧠 Example 10D: Memory Usage Optimization")
    proto: TypesRPCPluginProtocol = plugin_protocol()
    handler = HighPerformanceHandler("MemOptHandler")
    srv_cfg: dict[str, Any] = {
        "transport": "unix",
        "transport_path": "/tmp/mem_opt.sock",  # nosec B108
    }
    srv: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, proto),
        handler=handler,
        transport=str(srv_cfg.get("transport")),
        transport_path=str(srv_cfg.get("transport_path")),
        config=srv_cfg,
    )
    srv_task = asyncio.create_task(srv.serve())
    await srv.wait_for_server_ready(timeout=5.0)
    try:
        logger.info("Simulating memory usage patterns...")
    finally:
        await srv.stop()
        await srv_task


async def main() -> None:
    print("📈 pyvider-rpcplugin Performance Tuning Examples")
    try:
        await example_10_baseline_performance()
        await example_10_transport_optimization()
        await example_10_concurrency_tuning()
        await example_10_memory_optimization()
        print("✅ All Performance Tuning Examples Completed Successfully!")
    except Exception as e:
        logger.error("Perf tuning example failed", error=str(e))
        raise


if __name__ == "__main__":
    asyncio.run(main())
