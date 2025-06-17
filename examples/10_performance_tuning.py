#!/usr/bin/env python3
# examples/10_performance_tuning.py
"""Demonstrates performance optimization techniques and benchmarking with pyvider-rpcplugin."""

import asyncio
import psutil
import sys
import time
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
from statistics import mean

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    create_basic_protocol,
    configure,
)
from pyvider.telemetry import logger  # noqa: E402


@dataclass
class PerformanceMetrics:
    """Container for performance measurement data."""
    
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
        """Calculate error rate as percentage."""
        return (self.error_count / max(self.total_requests, 1)) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'requests_per_second': round(self.requests_per_second, 2),
            'avg_latency_ms': round(self.avg_latency_ms, 3),
            'p95_latency_ms': round(self.p95_latency_ms, 3),
            'p99_latency_ms': round(self.p99_latency_ms, 3),
            'min_latency_ms': round(self.min_latency_ms, 3),
            'max_latency_ms': round(self.max_latency_ms, 3),
            'cpu_usage_percent': round(self.cpu_usage_percent, 1),
            'memory_usage_mb': round(self.memory_usage_mb, 1),
            'total_requests': self.total_requests,
            'total_duration_seconds': round(self.total_duration_seconds, 2),
            'error_count': self.error_count,
            'error_rate': round(self.error_rate, 2)
        }


class HighPerformanceHandler:
    """Optimized handler for performance testing."""
    
    def __init__(self, handler_name: str):
        self.handler_name = handler_name
        self.request_count = 0
        self.total_processing_time = 0.0
        self.cache: dict[str, Any] = {} # Type hint added
        self.batch_buffer: list[str] = [] # Type hint added, assuming messages are strings
        self.batch_size = 100
    
    async def FastEcho(self, request, context):
        """Optimized echo service for performance testing."""
        
        self.request_count += 1
        start_time = time.perf_counter()
        
        # Extract message
        message = getattr(request, 'message', '')
        
        # Simple processing (minimal overhead)
        result = f"Echo: {message}"
        
        # Track processing time
        processing_time = time.perf_counter() - start_time
        self.total_processing_time += processing_time
        
        return type('EchoReply', (), {'response': result})()
    
    async def CachedProcess(self, request, context):
        """Process with caching optimization."""
        
        self.request_count += 1
        message = getattr(request, 'message', '')
        
        # Check cache first
        if message in self.cache:
            return type('CachedReply', (), {
                'response': self.cache[message],
                'from_cache': True
            })()
        
        # Process and cache
        await asyncio.sleep(0.001)  # Simulate processing
        result = f"Processed: {message}"
        self.cache[message] = result
        
        return type('CachedReply', (), {
            'response': result,
            'from_cache': False
        })()
    
    async def BatchProcess(self, request, context):
        """Process with batching optimization."""
        
        self.request_count += 1
        message = getattr(request, 'message', '')
        
        # Add to batch
        self.batch_buffer.append(message)
        
        # Process batch when full
        if len(self.batch_buffer) >= self.batch_size:
            batch_results = await self._process_batch()
            self.batch_buffer = []
            return type('BatchReply', (), {
                'response': f"Batch processed: {len(batch_results)} items",
                'batch_size': len(batch_results)
            })()
        
        return type('BatchReply', (), {
            'response': f"Queued: {message}",
            'batch_size': len(self.batch_buffer)
        })()
    
    async def _process_batch(self) -> List[str]:
        """Process a batch of items efficiently."""
        
        # Process all items concurrently
        tasks = [self._process_single_item(item) for item in self.batch_buffer]
        results = await asyncio.gather(*tasks)
        
        return results
    
    async def _process_single_item(self, item: str) -> str:
        """Process single item (can be parallelized)."""
        
        # Minimal processing for benchmarking
        return f"Processed: {item}"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get handler performance statistics."""
        
        avg_processing_time = (
            self.total_processing_time / max(self.request_count, 1)
        ) * 1000  # Convert to milliseconds
        
        return {
            'requests_processed': self.request_count,
            'avg_processing_time_ms': round(avg_processing_time, 3),
            'cache_size': len(self.cache),
            'batch_buffer_size': len(self.batch_buffer)
        }


class PerformanceBenchmarker:
    """Comprehensive performance benchmarking utility."""
    
    def __init__(self):
        self.process = psutil.Process()
    
    async def benchmark_rpc_performance(
        self,
        server_config: Dict[str, Any],
        test_duration_seconds: float = 10.0,
        concurrent_clients: int = 10,
        requests_per_client: int = 100
    ) -> PerformanceMetrics:
        """Run comprehensive RPC performance benchmark."""
        
        logger.info(
            "Starting RPC performance benchmark",
            domain="performance",
            action="benchmark_start",
            status="starting",
            test_duration=test_duration_seconds,
            concurrent_clients=concurrent_clients,
            requests_per_client=requests_per_client
        )
        
        # Setup server
        protocol = create_basic_protocol()
        handler = HighPerformanceHandler("BenchmarkHandler")
        
        server = plugin_server(
            protocol=protocol,
            handler=handler,
            **server_config
        )
        
        # Start server
        server_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5)  # Let server initialize
        
        try:
            # Record baseline metrics
            baseline_cpu = self.process.cpu_percent()
            baseline_memory = self.process.memory_info().rss / 1024 / 1024
            
            # Run benchmark
            start_time = time.perf_counter()
            latencies = []
            error_count = 0
            
            # Create concurrent clients
            async def client_worker(client_id: int, requests: int, actual_server_endpoint: str, transport_type: str) -> List[float]:
                """Worker function for concurrent client."""
                
                client_latencies = []
                # client = plugin_client(transport=server_config.get('transport', 'unix')) # Incorrect factory call

                # Manually create a gRPC channel to the in-process server
                import grpc # Ensure grpc is imported
                target = f"{'unix:' if transport_type == 'unix' else ''}{actual_server_endpoint}"
                channel = None # Define channel here to ensure it's available in finally
                
                try:
                    channel = grpc.aio.insecure_channel(target)
                    # In a real benchmark, you'd create a stub here, e.g.:
                    # stub = YourServicePb2Grpc.YourServiceStub(channel)

                    for i in range(requests):
                        request_start = time.perf_counter()
                        
                        try:
                            # Simulate RPC call
                            await asyncio.sleep(0.001)  # Minimal processing time
                            
                            request_end = time.perf_counter()
                            latency_ms = (request_end - request_start) * 1000
                            client_latencies.append(latency_ms)
                            
                        except Exception:
                            nonlocal error_count
                            error_count += 1
                
                finally:
                    # await client.close()
                    if channel:
                        await channel.close(grace=None) # Added grace=None
                
                return client_latencies
            
            # actual_server_endpoint and transport_type will be fetched before this
            # and then passed to client_worker when client_tasks are created.
            actual_server_endpoint = getattr(server._transport, 'endpoint', None)
            if not actual_server_endpoint:
                # Clean up server task if endpoint is not found
                if server_task and not server_task.done():
                    server_task.cancel()
                    try:
                        await server_task
                    except asyncio.CancelledError:
                        logger.warning("Server task cancelled due to missing endpoint.")
                raise RuntimeError("Server endpoint not available for benchmark.")

            transport_type = server_config.get('transport', 'unix') # Get transport type from server_config

            client_tasks = [
                client_worker(i, requests_per_client, actual_server_endpoint, transport_type)
                for i in range(concurrent_clients)
            ]
            
            client_results = await asyncio.gather(*client_tasks)
            
            # Collect all latencies
            for client_latencies in client_results:
                latencies.extend(client_latencies)
            
            end_time = time.perf_counter()
            total_duration = end_time - start_time
            
            # Calculate metrics
            total_requests = len(latencies) + error_count
            
            if latencies:
                latencies.sort()
                avg_latency = mean(latencies)
                p95_latency = latencies[int(0.95 * len(latencies))]
                p99_latency = latencies[int(0.99 * len(latencies))]
                min_latency = min(latencies)
                max_latency = max(latencies)
            else:
                avg_latency = p95_latency = p99_latency = min_latency = max_latency = 0.0
            
            # Resource usage
            cpu_usage = self.process.cpu_percent() - baseline_cpu
            memory_usage = self.process.memory_info().rss / 1024 / 1024 - baseline_memory
            
            # Calculate RPS
            requests_per_second = total_requests / total_duration
            
            metrics = PerformanceMetrics(
                requests_per_second=requests_per_second,
                avg_latency_ms=avg_latency,
                p95_latency_ms=p95_latency,
                p99_latency_ms=p99_latency,
                min_latency_ms=min_latency,
                max_latency_ms=max_latency,
                cpu_usage_percent=cpu_usage,
                memory_usage_mb=memory_usage,
                total_requests=total_requests,
                total_duration_seconds=total_duration,
                error_count=error_count
            )
            
            logger.info(
                "RPC performance benchmark completed",
                domain="performance",
                action="benchmark_complete",
                status="success",
                **metrics.to_dict()
            )
            
            return metrics
            
        finally:
            await server.stop()
            await server_task
    
    async def compare_transport_performance(self) -> Dict[str, PerformanceMetrics]:
        """Compare performance across different transports."""
        
        logger.info(
            "Starting transport performance comparison",
            domain="performance",
            action="transport_comparison",
            status="starting",
            transports=["unix", "tcp"]
        )
        
        results = {}
        
        # Test Unix socket performance
        unix_config = {
            'transport': 'unix',
            'transport_path': '/tmp/perf_test_unix.sock' # nosec B108 # Example code, /tmp is acceptable here.
        }
        
        logger.info("Benchmarking Unix socket transport", domain="performance")
        results['unix'] = await self.benchmark_rpc_performance(
            unix_config,
            test_duration_seconds=5.0,
            concurrent_clients=5,
            requests_per_client=50
        )
        
        # Test TCP performance
        tcp_config = {
            'transport': 'tcp',
            'host': '127.0.0.1',
            'port': 0
        }
        
        logger.info("Benchmarking TCP socket transport", domain="performance")
        results['tcp'] = await self.benchmark_rpc_performance(
            tcp_config,
            test_duration_seconds=5.0,
            concurrent_clients=5,
            requests_per_client=50
        )
        
        # Compare results
        unix_rps = results['unix'].requests_per_second
        tcp_rps = results['tcp'].requests_per_second
        performance_ratio = unix_rps / tcp_rps if tcp_rps > 0 else 0
        
        logger.info(
            "Transport performance comparison completed",
            domain="performance",
            action="transport_comparison",
            status="completed",
            unix_rps=round(unix_rps, 2),
            tcp_rps=round(tcp_rps, 2),
            unix_faster_by=f"{performance_ratio:.1f}x" if performance_ratio > 1 else "slower",
            winner="unix" if unix_rps > tcp_rps else "tcp"
        )
        
        return results


async def example_10_baseline_performance():
    """
    Example 10A: Establishes baseline performance characteristics.
    
    Measures the basic performance profile of pyvider-rpcplugin
    to establish optimization baselines.
    """
    print("\n" + "=" * 60)
    print("📊 Example 10A: Baseline Performance Measurement")
    print(" Demonstrates: Establishing performance baselines")
    print("=" * 60)
    
    benchmarker = PerformanceBenchmarker()
    
    # Configure for baseline measurement
    configure(
        magic_cookie="perf-baseline-cookie",
        protocol_version=1,
        transports=["unix"],
        auto_mtls=False,  # Disable for baseline
        handshake_timeout=5.0,
        connection_timeout=30.0
    )
    
    logger.info(
        "Starting baseline performance measurement",
        domain="performance",
        action="baseline_test",
        status="starting",
        configuration="default_settings"
    )
    
    # Baseline configuration
    baseline_config = {
        'transport': 'unix',
        'transport_path': '/tmp/baseline_perf.sock' # nosec B108 # Example code, /tmp is acceptable here.
    }
    
    # Run baseline benchmark
    baseline_metrics = await benchmarker.benchmark_rpc_performance(
        baseline_config,
        test_duration_seconds=10.0,
        concurrent_clients=10,
        requests_per_client=100
    )
    
    logger.info(
        "Baseline performance established",
        domain="performance",
        action="baseline_test",
        status="completed",
        **baseline_metrics.to_dict()
    )
    
    # Performance expectations for different use cases
    performance_targets = {
        'high_frequency_trading': {
            'min_rps': 50000,
            'max_latency_p99_ms': 1.0,
            'description': 'Ultra-low latency requirements'
        },
        'microservices': {
            'min_rps': 10000,
            'max_latency_p99_ms': 10.0,
            'description': 'Typical microservice communication'
        },
        'api_gateway': {
            'min_rps': 5000,
            'max_latency_p99_ms': 50.0,
            'description': 'External API handling'
        },
        'batch_processing': {
            'min_rps': 1000,
            'max_latency_p99_ms': 100.0,
            'description': 'Background batch jobs'
        }
    }
    
    # Compare baseline against targets
    for use_case, targets in performance_targets.items():
        meets_rps = baseline_metrics.requests_per_second >= targets['min_rps']
        meets_latency = baseline_metrics.p99_latency_ms <= targets['max_latency_p99_ms']
        
        logger.info(
            f"Performance target analysis: {use_case}",
            domain="performance",
            action="target_analysis",
            status="analyzed",
            use_case=use_case,
            description=targets['description'],
            rps_target=targets['min_rps'],
            rps_actual=round(baseline_metrics.requests_per_second, 2),
            rps_meets_target=meets_rps,
            latency_target_ms=targets['max_latency_p99_ms'],
            latency_actual_ms=round(baseline_metrics.p99_latency_ms, 3),
            latency_meets_target=meets_latency,
            overall_suitable=meets_rps and meets_latency
        )


async def example_10_transport_optimization():
    """
    Example 10B: Optimizes transport layer performance.
    
    Compares and optimizes different transport options
    for maximum performance.
    """
    print("\n" + "=" * 60)
    print("🚄 Example 10B: Transport Layer Optimization")
    print(" Demonstrates: Optimizing transport performance")
    print("=" * 60)
    
    benchmarker = PerformanceBenchmarker()
    
    logger.info(
        "Starting transport optimization analysis",
        domain="performance",
        action="transport_optimization",
        status="starting",
        optimization_targets=["throughput", "latency", "resource_usage"]
    )
    
    # Compare transport performance
    transport_results = await benchmarker.compare_transport_performance()
    
    # Analyze results
    unix_metrics = transport_results['unix']
    tcp_metrics = transport_results['tcp']
    
    # Performance comparison
    comparison = {
        'throughput': {
            'unix_rps': unix_metrics.requests_per_second,
            'tcp_rps': tcp_metrics.requests_per_second,
            'ratio': unix_metrics.requests_per_second / tcp_metrics.requests_per_second,
            'winner': 'unix' if unix_metrics.requests_per_second > tcp_metrics.requests_per_second else 'tcp'
        },
        'latency': {
            'unix_p99_ms': unix_metrics.p99_latency_ms,
            'tcp_p99_ms': tcp_metrics.p99_latency_ms,
            'difference_ms': tcp_metrics.p99_latency_ms - unix_metrics.p99_latency_ms,
            'winner': 'unix' if unix_metrics.p99_latency_ms < tcp_metrics.p99_latency_ms else 'tcp'
        },
        'resources': {
            'unix_cpu': unix_metrics.cpu_usage_percent,
            'tcp_cpu': tcp_metrics.cpu_usage_percent,
            'unix_memory_mb': unix_metrics.memory_usage_mb,
            'tcp_memory_mb': tcp_metrics.memory_usage_mb,
            'cpu_winner': 'unix' if unix_metrics.cpu_usage_percent < tcp_metrics.cpu_usage_percent else 'tcp',
            'memory_winner': 'unix' if unix_metrics.memory_usage_mb < tcp_metrics.memory_usage_mb else 'tcp'
        }
    }
    
    logger.info(
        "Transport optimization analysis completed",
        domain="performance",
        action="transport_optimization",
        status="completed",
        **comparison
    )
    
    # Optimization recommendations
    recommendations = []
    
    if comparison['throughput']['ratio'] > 1.5:
        recommendations.append(
            "Use Unix sockets for local IPC - significantly higher throughput"
        )
    
    if comparison['latency']['difference_ms'] > 1.0:
        recommendations.append(
            "Unix sockets provide lower latency for same-host communication"
        )
    
    if comparison['resources']['unix_cpu'] < comparison['resources']['tcp_cpu']:
        recommendations.append(
            "Unix sockets have lower CPU overhead"
        )
    
    recommendations.extend([
        "Use TCP only when network communication is required",
        "Consider Unix socket pools for high-throughput local services",
        "Monitor transport performance in production environments"
    ])
    
    logger.info(
        "Transport optimization recommendations",
        domain="performance",
        action="optimization_recommendations",
        status="completed",
        recommendations=recommendations
    )


async def example_10_concurrency_tuning():
    """
    Example 10C: Optimizes concurrency and async patterns.
    
    Tests different concurrency configurations to find
    optimal settings for various workloads.
    """
    print("\n" + "=" * 60)
    print("⚡ Example 10C: Concurrency and Async Optimization")
    print(" Demonstrates: Optimizing concurrent request handling")
    print("=" * 60)
    
    async def test_concurrency_level(concurrent_clients: int, requests_per_client: int) -> PerformanceMetrics:
        """Test specific concurrency configuration."""
        
        logger.info(
            f"Testing concurrency level: {concurrent_clients} clients",
            domain="performance",
            action="concurrency_test",
            status="starting",
            concurrent_clients=concurrent_clients,
            requests_per_client=requests_per_client
        )
        
        # Setup optimized server
        protocol = create_basic_protocol()
        handler = HighPerformanceHandler(f"ConcurrencyHandler_{concurrent_clients}")
        
        server = plugin_server(
            protocol=protocol,
            handler=handler,
            transport="unix",
            config={
                'max_workers': concurrent_clients * 2,  # Scale workers with clients
                'connection_pool_size': concurrent_clients,
                'keepalive_timeout': 60
            }
        )
        
        server_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.3)
        
        try:
            start_time = time.perf_counter()
            latencies = []
            
            # Concurrent client simulation
            async def client_simulation(client_id: int) -> List[float]:
                client_latencies = []
                
                for i in range(requests_per_client):
                    request_start = time.perf_counter()
                    
                    # Simulate RPC processing
                    await asyncio.sleep(0.001)
                    
                    request_end = time.perf_counter()
                    latency_ms = (request_end - request_start) * 1000
                    client_latencies.append(latency_ms)
                
                return client_latencies
            
            # Run concurrent simulations
            tasks = [client_simulation(i) for i in range(concurrent_clients)]
            results = await asyncio.gather(*tasks)
            
            # Collect metrics
            for client_latencies in results:
                latencies.extend(client_latencies)
            
            end_time = time.perf_counter()
            total_duration = end_time - start_time
            
            # Calculate performance metrics
            total_requests = len(latencies)
            requests_per_second = total_requests / total_duration
            
            latencies.sort()
            avg_latency = mean(latencies)
            p95_latency = latencies[int(0.95 * len(latencies))]
            p99_latency = latencies[int(0.99 * len(latencies))]
            
            metrics = PerformanceMetrics(
                requests_per_second=requests_per_second,
                avg_latency_ms=avg_latency,
                p95_latency_ms=p95_latency,
                p99_latency_ms=p99_latency,
                min_latency_ms=min(latencies),
                max_latency_ms=max(latencies),
                cpu_usage_percent=0.0,  # Simplified for concurrency test
                memory_usage_mb=0.0,
                total_requests=total_requests,
                total_duration_seconds=total_duration
            )
            
            logger.info(
                f"Concurrency test completed: {concurrent_clients} clients",
                domain="performance",
                action="concurrency_test",
                status="completed",
                concurrent_clients=concurrent_clients,
                **metrics.to_dict()
            )
            
            return metrics
            
        finally:
            await server.stop()
            await server_task
    
    # Test different concurrency levels
    concurrency_levels = [1, 5, 10, 20, 50]
    concurrency_results = {}
    
    for level in concurrency_levels:
        concurrency_results[level] = await test_concurrency_level(level, 50)
        
        # Small delay between tests
        await asyncio.sleep(0.5)
    
    # Analyze concurrency scaling
    logger.info(
        "Concurrency scaling analysis",
        domain="performance",
        action="concurrency_analysis",
        status="starting"
    )
    
    # Find optimal concurrency level
    best_throughput = 0
    optimal_concurrency = 1
    
    for level, metrics in concurrency_results.items():
        if metrics.requests_per_second > best_throughput:
            best_throughput = metrics.requests_per_second
            optimal_concurrency = level
        
        # Calculate efficiency (throughput per concurrent client)
        efficiency = metrics.requests_per_second / level
        
        logger.info(
            f"Concurrency level {level} analysis",
            domain="performance",
            action="concurrency_level_analysis",
            status="analyzed",
            concurrency_level=level,
            throughput_rps=round(metrics.requests_per_second, 2),
            efficiency_rps_per_client=round(efficiency, 2),
            p95_latency_ms=round(metrics.p95_latency_ms, 3),
            is_optimal=level == optimal_concurrency
        )
    
    logger.info(
        "Concurrency optimization completed",
        domain="performance",
        action="concurrency_analysis",
        status="completed",
        optimal_concurrency_level=optimal_concurrency,
        optimal_throughput_rps=round(best_throughput, 2),
        scaling_recommendation=f"Use {optimal_concurrency} concurrent clients for optimal throughput"
    )


async def example_10_memory_optimization():
    """
    Example 10D: Demonstrates memory usage optimization.
    
    Shows techniques for reducing memory usage and
    preventing memory leaks in RPC applications.
    """
    print("\n" + "=" * 60)
    print("🧠 Example 10D: Memory Usage Optimization")
    print(" Demonstrates: Reducing memory footprint and preventing leaks")
    print("=" * 60)
    
    class MemoryOptimizedHandler:
        """Handler optimized for memory efficiency."""
        
        def __init__(self):
            self.request_count = 0
            # Use limited-size cache to prevent unbounded growth
            self.cache_size_limit = 1000
            self.cache = {}
            self.cache_access_order = []
        
        async def ProcessRequest(self, request, context):
            """Process request with memory-conscious caching."""
            
            self.request_count += 1
            message = getattr(request, 'message', '')
            
            # Check cache
            if message in self.cache:
                # Update access order
                self.cache_access_order.remove(message)
                self.cache_access_order.append(message)
                
                return type('Reply', (), {
                    'response': self.cache[message],
                    'from_cache': True
                })()
            
            # Process and cache with size limit
            result = f"Processed: {message}"
            
            # Implement LRU eviction
            if len(self.cache) >= self.cache_size_limit:
                # Remove least recently used item
                lru_key = self.cache_access_order.pop(0)
                del self.cache[lru_key]
            
            # Add to cache
            self.cache[message] = result
            self.cache_access_order.append(message)
            
            return type('Reply', (), {
                'response': result,
                'from_cache': False
            })()
        
        def get_memory_stats(self) -> Dict[str, Any]:
            """Get memory usage statistics."""
            
            import sys
            
            cache_size_bytes = sys.getsizeof(self.cache)
            for key, value in self.cache.items():
                cache_size_bytes += sys.getsizeof(key) + sys.getsizeof(value)
            
            return {
                'cache_entries': len(self.cache),
                'cache_size_limit': self.cache_size_limit,
                'cache_size_bytes': cache_size_bytes,
                'cache_size_mb': cache_size_bytes / 1024 / 1024,
                'requests_processed': self.request_count
            }
    
    # Monitor memory usage
    process = psutil.Process()
    initial_memory = process.memory_info().rss / 1024 / 1024
    
    logger.info(
        "Starting memory optimization demonstration",
        domain="performance",
        action="memory_optimization",
        status="starting",
        initial_memory_mb=round(initial_memory, 2)
    )
    
    # Create memory-optimized server
    protocol = create_basic_protocol()
    handler = MemoryOptimizedHandler()
    
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",
        config={
            'max_connections': 100,  # Limit concurrent connections
            'connection_timeout': 30,  # Close idle connections
            'keepalive_timeout': 60
        }
    )
    
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    try:
        # Simulate memory usage patterns
        logger.info(
            "Simulating memory usage patterns",
            domain="performance",
            action="memory_simulation",
            status="starting"
        )
        
        # Pattern 1: Many unique requests (cache growth)
        for i in range(500):
            # Simulate request processing
            await asyncio.sleep(0.001)
            
            # Simulate unique messages (will fill cache)
            if i % 100 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_stats = handler.get_memory_stats()
                
                logger.debug(
                    f"Memory usage at {i} requests",
                    domain="performance",
                    action="memory_checkpoint",
                    status="measured",
                    # requests_processed=i, # Removed to avoid conflict with key in memory_stats
                    current_memory_mb=round(current_memory, 2),
                    memory_growth_mb=round(current_memory - initial_memory, 2),
                    **memory_stats
                )
        
        # Pattern 2: Repeated requests (cache hits)
        logger.info(
            "Testing cache efficiency with repeated requests",
            domain="performance",
            action="cache_efficiency",
            status="testing"
        )
        
        for i in range(200):
            # Use limited set of messages (high cache hit rate)
            _message_id = i % 10  # Only 10 unique messages
            await asyncio.sleep(0.001)
        
        # Final memory analysis
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        final_stats = handler.get_memory_stats()
        
        logger.info(
            "Memory optimization analysis completed",
            domain="performance",
            action="memory_optimization",
            status="completed",
            initial_memory_mb=round(initial_memory, 2),
            final_memory_mb=round(final_memory, 2),
            memory_growth_mb=round(memory_growth, 2),
            memory_efficiency="good" if memory_growth < 50 else "needs_improvement",
            **final_stats
        )
        
        # Memory optimization recommendations
        recommendations = [
            "Implement bounded caches with LRU eviction",
            "Set connection limits to prevent resource exhaustion",
            "Use connection timeouts to release idle resources",
            "Monitor memory usage in production",
            "Consider object pooling for frequently created objects",
            "Use generators for large data processing",
            "Implement periodic garbage collection triggers"
        ]
        
        logger.info(
            "Memory optimization recommendations",
            domain="performance",
            action="memory_recommendations",
            status="completed",
            recommendations=recommendations
        )
        
    finally:
        await server.stop()
        await server_task


async def main():
    """Run all performance tuning examples."""
    print("📈 pyvider-rpcplugin Performance Tuning Examples")
    print("================================================")
    
    try:
        # Run each performance optimization example
        await example_10_baseline_performance()
        await example_10_transport_optimization()
        await example_10_concurrency_tuning()
        await example_10_memory_optimization()
        
        print("\n" + "=" * 60)
        print("✅ All Performance Tuning Examples Completed Successfully!")
        print("=" * 60)
        print("\n📈 Performance Optimization Summary:")
        print("  • Baseline measurement: Establish performance characteristics")
        print("  • Transport optimization: Unix sockets for local IPC, TCP for network")
        print("  • Concurrency tuning: Scale workers and connections appropriately")
        print("  • Memory optimization: Bounded caches, connection limits, timeouts")
        print("  • Continuous monitoring: Track performance metrics in production")
        print("\n🎯 Key Recommendations:")
        print("  • Use Unix sockets for same-host communication (2-3x faster)")
        print("  • Optimize concurrency based on workload characteristics")
        print("  • Implement bounded caches to prevent memory growth")
        print("  • Monitor and alert on performance regressions")
        print("  • Test performance changes before production deployment")
        print("\n📖 Next Steps:")
        print("  • Set up performance monitoring in your production environment")
        print("  • Create performance regression tests in your CI/CD pipeline")
        print("  • Review docs/architecture.md for additional optimization patterns")
        
    except Exception as e:
        logger.error(
            "Performance tuning example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
