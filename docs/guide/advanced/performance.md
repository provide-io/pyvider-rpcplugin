# Performance Tuning

Optimize plugin performance for production workloads with profiling, benchmarking, connection pooling, memory management, and scaling techniques.

## Overview

Performance tuning ensures plugin systems can handle high traffic loads efficiently. Key areas include CPU optimization, memory management, network efficiency, and scaling strategies for maximum throughput with minimal latency.

### Key Performance Areas

- **CPU Optimization**: Efficient processing and multi-threading
- **Memory Management**: Minimize allocation overhead and garbage collection
- **Network Efficiency**: Connection pooling and protocol optimization
- **I/O Performance**: Async operations and buffer management
- **Scaling Strategies**: Horizontal and vertical scaling patterns

### Quick Performance Setup

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.performance import PerformanceConfig
from provide.foundation import logger

async def optimized_server():
    """High-performance server configuration."""
    
    # Performance-optimized configuration
    perf_config = PerformanceConfig(
        max_connections=1000,
        connection_timeout=5.0,
        keepalive_enabled=True,
        buffer_size=64 * 1024,  # 64KB buffers
        worker_threads=4,       # Match CPU cores
        enable_compression=True
    )
    
    server = plugin_server(
        services=[OptimizedService()],
        performance_config=perf_config,
        enable_profiling=True,
        metrics_enabled=True
    )
    
    logger.info("🚀 Starting high-performance server")
    await server.serve()
```

## CPU Optimization

### 1. **Multi-Threading Configuration**
Optimize thread usage for CPU-bound operations while maintaining async efficiency.

```python
from pyvider.rpcplugin.performance import CPUConfig

cpu_config = CPUConfig(
    worker_threads=8,           # Match CPU cores
    async_io_threads=4,         # I/O worker threads
    enable_thread_affinity=True, # Pin threads to cores
    cpu_intensive_threshold=0.1  # 100ms threshold
)

# Server with CPU optimization
server = plugin_server(
    services=[CPUIntensiveService()],
    cpu_config=cpu_config
)
```

### 2. **Async Performance Patterns**
Efficient async patterns for high-concurrency scenarios.

```python
import asyncio
from typing import List

class OptimizedService:
    def __init__(self):
        # Pre-create semaphores and pools
        self.processing_semaphore = asyncio.Semaphore(100)
        self.batch_size = 50
    
    async def process_batch_requests(self, requests: List):
        """Process multiple requests concurrently."""
        
        async def process_single(request):
            async with self.processing_semaphore:
                return await self.process_request(request)
        
        # Process in batches to control memory usage
        results = []
        for i in range(0, len(requests), self.batch_size):
            batch = requests[i:i + self.batch_size]
            batch_results = await asyncio.gather(
                *[process_single(req) for req in batch],
                return_exceptions=True
            )
            results.extend(batch_results)
        
        return results
```

### 3. **CPU Profiling**
Monitor and identify CPU bottlenecks in production.

```python
from pyvider.rpcplugin.profiling import CPUProfiler
import cProfile

# Production-safe profiling
profiler = CPUProfiler(
    sampling_rate=0.01,     # 1% sampling
    profile_duration=60,    # Profile for 1 minute
    output_format="json"
)

async def profile_service_performance():
    async with profiler.profile_context("service_method"):
        result = await service.expensive_operation()
        return result
```

## Memory Optimization

### 1. **Memory Pool Management**
Reuse objects and buffers to minimize garbage collection overhead.

```python
from pyvider.rpcplugin.memory import MemoryPool, BufferPool

# Object pooling for frequent allocations
class OptimizedService:
    def __init__(self):
        self.request_pool = MemoryPool(
            create_func=lambda: RequestObject(),
            reset_func=lambda obj: obj.reset(),
            max_size=1000
        )
        
        self.buffer_pool = BufferPool(
            buffer_size=64 * 1024,  # 64KB buffers
            pool_size=100
        )
    
    async def process_request(self, data):
        # Reuse pooled objects
        request_obj = self.request_pool.acquire()
        buffer = self.buffer_pool.acquire()
        
        try:
            request_obj.parse(data)
            result = await self.process_with_buffer(request_obj, buffer)
            return result
        finally:
            # Return objects to pool
            self.request_pool.release(request_obj)
            self.buffer_pool.release(buffer)
```

### 2. **Garbage Collection Tuning**
Optimize garbage collection for server workloads.

```python
import gc
from pyvider.rpcplugin.memory import GCOptimizer

# Configure GC for server workloads
gc_optimizer = GCOptimizer(
    generation_thresholds=(1000, 20, 20),  # More aggressive collection
    gc_frequency="adaptive",               # Adjust based on allocation rate
    disable_gc_during_requests=True       # Prevent GC during critical sections
)

# Apply optimizations
gc_optimizer.apply_server_optimizations()

# Manual GC control during idle periods
async def periodic_gc_cleanup():
    while True:
        await asyncio.sleep(30)  # Every 30 seconds during idle
        if server.is_idle():
            gc.collect(2)  # Full collection during idle
```

### 3. **Memory Monitoring**
Track memory usage patterns and detect leaks.

```python
from pyvider.rpcplugin.monitoring import MemoryMonitor

memory_monitor = MemoryMonitor(
    check_interval=10.0,        # Check every 10 seconds
    warning_threshold=0.8,      # Warn at 80% memory usage
    critical_threshold=0.95,    # Alert at 95% memory usage
    track_object_counts=True    # Track object type counts
)

async def monitor_memory_health():
    async with memory_monitor.monitoring_context():
        stats = memory_monitor.get_current_stats()
        
        if stats.usage_percent > 0.8:
            logger.warning("High memory usage detected", extra={
                "usage_percent": stats.usage_percent,
                "largest_objects": stats.largest_object_types[:5]
            })
```

## Network Optimization

### 1. **Connection Pooling**
Efficient connection reuse and management.

```python
from pyvider.rpcplugin.network import ConnectionPool

# High-performance connection pool
conn_pool = ConnectionPool(
    max_connections=2000,       # High connection limit
    max_idle_connections=500,   # Keep connections alive
    connection_timeout=5.0,     # Quick timeout
    keepalive_time=60.0,        # 1 minute keepalive
    tcp_nodelay=True,          # Disable Nagle algorithm
    tcp_keepalive=True         # Enable TCP keepalive
)

# Client with connection pooling
async with plugin_client(
    connection_pool=conn_pool,
    enable_connection_reuse=True
) as client:
    # Connections are automatically pooled and reused
    results = await asyncio.gather(*[
        client.service.method(i) for i in range(1000)
    ])
```

### 2. **Protocol Optimization**
Optimize gRPC protocol settings for performance.

```python
from pyvider.rpcplugin.protocol import ProtocolConfig

protocol_config = ProtocolConfig(
    # Message size limits
    max_send_message_length=100 * 1024 * 1024,  # 100MB
    max_receive_message_length=100 * 1024 * 1024,
    
    # Compression
    compression="gzip",                          # Enable compression
    compression_level=6,                         # Balanced compression
    
    # Flow control
    http2_window_size=16 * 1024 * 1024,         # 16MB window
    http2_max_frame_size=16 * 1024,             # 16KB frames
    
    # Performance tuning
    keepalive_time=30,                          # 30 second keepalive
    keepalive_timeout=5,                        # 5 second timeout
    max_connection_idle=60,                     # 1 minute idle timeout
    max_connection_age=120                      # 2 minute max age
)
```

### 3. **Streaming Optimization**
Efficient patterns for streaming data.

```python
class StreamOptimizedService:
    def __init__(self):
        self.stream_buffer_size = 64 * 1024  # 64KB chunks
        self.max_concurrent_streams = 100
    
    async def stream_large_data(self, request_iterator):
        """Efficiently stream large datasets."""
        
        async def process_chunk(chunk):
            # Process chunk without blocking
            return await self.process_data_chunk(chunk)
        
        # Control concurrency to prevent memory exhaustion
        semaphore = asyncio.Semaphore(self.max_concurrent_streams)
        
        async for request in request_iterator:
            async with semaphore:
                chunk = await process_chunk(request.data)
                yield StreamResponse(
                    data=chunk,
                    chunk_size=len(chunk)
                )
```

## Benchmarking and Profiling

### 1. **Performance Benchmarks**
Establish baseline performance metrics.

```python
from pyvider.rpcplugin.benchmark import PerformanceBenchmark
import asyncio
import time

async def benchmark_plugin_performance():
    """Comprehensive performance benchmark."""
    
    benchmark = PerformanceBenchmark()
    
    # Throughput test
    throughput_results = await benchmark.measure_throughput(
        test_func=lambda: client.service.simple_method(),
        duration=60.0,        # 1 minute test
        concurrent_clients=50 # 50 concurrent clients
    )
    
    # Latency test
    latency_results = await benchmark.measure_latency(
        test_func=lambda: client.service.simple_method(),
        num_samples=10000     # 10,000 samples
    )
    
    # Memory usage test
    memory_results = await benchmark.measure_memory_usage(
        test_func=lambda: client.service.memory_intensive_method(),
        num_iterations=1000
    )
    
    # Generate performance report
    report = benchmark.generate_report({
        "throughput": throughput_results,
        "latency": latency_results, 
        "memory": memory_results
    })
    
    logger.info("Performance benchmark completed", extra=report)
    return report
```

### 2. **Production Profiling**
Safe profiling in production environments.

```python
from pyvider.rpcplugin.profiling import ProductionProfiler

# Low-overhead profiling for production
profiler = ProductionProfiler(
    sampling_rate=0.001,    # 0.1% sampling
    profile_duration=300,   # 5 minute windows
    auto_upload=True,       # Upload to monitoring system
    retention_days=7        # Keep profiles for 7 days
)

# Profile critical paths
@profiler.profile_method("critical_service_method")
async def critical_service_method(self, request):
    # Method implementation
    result = await self.process_request(request)
    return result
```

## Scaling Strategies

### 1. **Horizontal Scaling**
Scale across multiple processes and servers.

```python
from pyvider.rpcplugin.scaling import ProcessPool, LoadBalancer

# Multi-process plugin server
process_pool = ProcessPool(
    num_processes=8,        # One per CPU core
    process_recycling=1000, # Restart after 1000 requests
    shared_memory=True,     # Use shared memory for data
    load_balancing="round_robin"
)

# Load balancer for multiple plugin instances
load_balancer = LoadBalancer(
    backend_servers=[
        "plugin-server-1:50051",
        "plugin-server-2:50051", 
        "plugin-server-3:50051"
    ],
    health_check_interval=5.0,
    load_balancing_algorithm="least_connections"
)
```

### 2. **Vertical Scaling**
Optimize resource usage on single machines.

```python
from pyvider.rpcplugin.scaling import ResourceOptimizer

resource_optimizer = ResourceOptimizer(
    cpu_cores="auto",           # Use all available cores
    memory_limit="80%",         # Use 80% of available RAM
    disk_cache_size="20%",      # 20% of RAM for disk cache
    network_buffers="adaptive"  # Adaptive network buffer sizing
)

# Apply system-level optimizations
resource_optimizer.apply_optimizations()

# Server with vertical scaling optimizations
server = plugin_server(
    services=[ScalableService()],
    resource_optimizer=resource_optimizer,
    enable_auto_scaling=True
)
```

### 3. **Auto-Scaling**
Automatically adjust resources based on load.

```python
from pyvider.rpcplugin.scaling import AutoScaler

auto_scaler = AutoScaler(
    min_instances=2,          # Minimum plugin instances
    max_instances=20,         # Maximum plugin instances
    target_cpu_utilization=70, # Scale at 70% CPU
    target_memory_utilization=80, # Scale at 80% memory
    scale_up_threshold=2,     # Scale up after 2 minutes
    scale_down_threshold=10   # Scale down after 10 minutes
)

# Enable auto-scaling
await auto_scaler.start_monitoring()
```

## Configuration Tuning

### Development vs Production
```python
# Development configuration - optimized for debugging
dev_config = PerformanceConfig(
    max_connections=10,
    enable_profiling=True,
    debug_mode=True,
    metrics_detailed=True
)

# Production configuration - optimized for throughput
prod_config = PerformanceConfig(
    max_connections=5000,
    enable_profiling=False,    # Disable in production
    compression_enabled=True,
    connection_pooling=True,
    batch_processing=True,
    metrics_sampling=0.01      # 1% sampling
)

# Load balancer configuration
lb_config = PerformanceConfig(
    max_connections=10000,
    enable_session_affinity=True,
    health_check_enabled=True,
    circuit_breaker_enabled=True
)
```

## Monitoring and Metrics

### Performance Metrics
```python
from pyvider.rpcplugin.metrics import PerformanceMetrics
from provide.foundation import logger

# Track key performance indicators
metrics = PerformanceMetrics()

async def track_performance():
    while True:
        current_stats = metrics.get_current_stats()
        
        # Log performance metrics
        logger.info("Performance metrics", extra={
            "requests_per_second": current_stats.requests_per_second,
            "average_latency_ms": current_stats.average_latency_ms,
            "memory_usage_mb": current_stats.memory_usage_mb,
            "cpu_utilization_percent": current_stats.cpu_utilization,
            "active_connections": current_stats.active_connections
        })
        
        # Alert on performance degradation
        if current_stats.requests_per_second < expected_rps * 0.8:
            logger.warning("Performance degradation detected")
        
        await asyncio.sleep(30)  # Report every 30 seconds
```

### Health Checks
```python
from pyvider.rpcplugin.health import PerformanceHealthCheck

health_check = PerformanceHealthCheck(
    max_response_time=100,      # 100ms max response
    max_cpu_usage=80,           # 80% max CPU
    max_memory_usage=85,        # 85% max memory
    min_throughput=1000         # 1000 RPS minimum
)

async def performance_health_monitor():
    health_status = await health_check.check_health()
    
    if not health_status.is_healthy:
        logger.error("Performance health check failed", extra={
            "failed_checks": health_status.failed_checks,
            "recommendations": health_status.recommendations
        })
```

## Best Practices

1. **Profile Before Optimizing**: Measure to identify actual bottlenecks
2. **Optimize Hot Paths**: Focus on code paths that run most frequently  
3. **Use Connection Pooling**: Reuse connections to reduce setup overhead
4. **Control Concurrency**: Limit concurrent operations to prevent resource exhaustion
5. **Monitor Continuously**: Track performance metrics in production
6. **Test Under Load**: Use realistic load testing for performance validation
7. **Cache Strategically**: Cache expensive computations and frequently accessed data
8. **Batch Operations**: Group operations to reduce per-request overhead

## Troubleshooting Performance Issues

### High Latency
```python
# Identify latency sources
if average_latency > target_latency:
    logger.warning("High latency detected")
    
    # Check common causes
    latency_breakdown = profiler.get_latency_breakdown()
    for component, latency in latency_breakdown.items():
        if latency > threshold:
            logger.info(f"High latency in {component}: {latency}ms")
```

### Memory Leaks
```python
# Monitor memory growth patterns
previous_memory = current_memory = get_memory_usage()

async def detect_memory_leaks():
    global previous_memory, current_memory
    
    while True:
        current_memory = get_memory_usage()
        
        # Check for steady growth
        if current_memory > previous_memory * 1.1:  # 10% growth
            logger.warning("Potential memory leak detected", extra={
                "previous_mb": previous_memory,
                "current_mb": current_memory,
                "growth_percent": (current_memory/previous_memory - 1) * 100
            })
        
        previous_memory = current_memory
        await asyncio.sleep(300)  # Check every 5 minutes
```

### CPU Bottlenecks
```python
# Identify CPU-intensive operations
cpu_profiler = CPUProfiler()
hot_spots = cpu_profiler.get_hot_spots()

for function_name, cpu_time in hot_spots[:10]:  # Top 10 hot spots
    logger.info(f"CPU hot spot: {function_name} ({cpu_time:.2f}s)")
```

## Next Steps

- **[Custom Protocols](custom-protocols.md)** - Advanced protocol development
- **[Lifecycle Management](lifecycle.md)** - Plugin lifecycle optimization  
- **[Middleware](middleware.md)** - Performance middleware patterns
- **[Server Configuration](../server/index.md)** - Server-side performance tuning