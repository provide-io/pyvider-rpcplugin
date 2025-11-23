# Observability and Performance

Comprehensive monitoring, tracing, metrics, and performance optimization for production-ready RPC plugins.

## Overview

Effective observability combines distributed tracing, metrics collection, and performance optimization to provide complete visibility into plugin behavior and performance characteristics. This guide covers OpenTelemetry integration, profiling, benchmarking, and optimization strategies.

**Key capabilities:**
- Distributed tracing across service boundaries
- Custom metrics for RPC operations
- CPU, memory, and network optimization
- Production-safe profiling and benchmarking
- Horizontal and vertical scaling patterns

## Quick Start

=== "Tracing"

    ```python
    from pyvider.rpcplugin.telemetry import get_rpc_tracer
    from opentelemetry import trace

    tracer = get_rpc_tracer()

    class TracedHandler:
        async def process_request(self, request, context):
            with tracer.start_as_current_span(
                "process_request",
                kind=trace.SpanKind.SERVER
            ) as span:
                span.set_attribute("request.id", request.id)
                result = await self._do_work(request)
                return result
    ```

=== "Metrics"

    ```python
    from opentelemetry import metrics

    meter = metrics.get_meter("pyvider.rpcplugin")

    request_counter = meter.create_counter(
        "rpc.requests.total",
        description="Total RPC requests"
    )

    request_duration = meter.create_histogram(
        "rpc.request.duration",
        description="Request duration in ms",
        unit="ms"
    )
    ```

=== "Performance"

    ```python
    from pyvider.rpcplugin import plugin_server
    from pyvider.rpcplugin.performance import PerformanceConfig

    perf_config = PerformanceConfig(
        max_connections=1000,
        connection_timeout=5.0,
        buffer_size=64 * 1024,
        worker_threads=4,
        enable_compression=True
    )

    server = plugin_server(
        services=[OptimizedService()],
        performance_config=perf_config
    )
    ```

## Distributed Tracing

### Server-Side Instrumentation

```python
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from provide.foundation import logger
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

tracer = get_rpc_tracer()

class InstrumentedHandler:
    async def process_request(self, request, context):
        with tracer.start_as_current_span(
            "process_request",
            kind=trace.SpanKind.SERVER
        ) as span:
            # Add request attributes
            span.set_attribute("request.id", request.id)
            span.set_attribute("request.type", request.type)

            try:
                # Nested span for internal operations
                with tracer.start_as_current_span("database_query") as db_span:
                    db_span.set_attribute("db.operation", "select")
                    result = await self._query_database(request)

                span.set_attribute("response.status", "success")
                return result

            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
```

### Client-Side Tracing

```python
from pyvider.rpcplugin import plugin_client
from opentelemetry import propagate

async def make_traced_call(client, request):
    with tracer.start_as_current_span(
        "rpc_call",
        kind=trace.SpanKind.CLIENT
    ) as span:
        span.set_attribute("rpc.service", "MyService")
        span.set_attribute("rpc.method", "ProcessRequest")

        # Propagate trace context
        headers = {}
        propagate.inject(headers)

        response = await client.call_with_headers(
            "ProcessRequest",
            request,
            metadata=headers
        )
        return response
```

### Trace Context Propagation

```python
from opentelemetry import propagate, trace
from opentelemetry.propagators.b3 import B3MultiFormat

# Configure propagator
propagate.set_global_textmap(B3MultiFormat())

class DistributedTracingHandler:
    async def handle_request(self, request, context):
        # Extract trace context from incoming request
        metadata = dict(context.invocation_metadata())
        ctx = propagate.extract(metadata)

        # Continue trace with extracted context
        with tracer.start_as_current_span(
            "handle_request",
            context=ctx,
            kind=trace.SpanKind.SERVER
        ) as span:
            result = await self.process(request)
            return result
```

## Metrics Collection

### Core Metrics

```python
from opentelemetry import metrics

class MetricsHandler:
    def __init__(self):
        meter = metrics.get_meter(__name__)

        # Request metrics
        self.request_counter = meter.create_counter(
            "rpc.requests.total",
            description="Total RPC requests"
        )

        self.request_duration = meter.create_histogram(
            "rpc.request.duration",
            description="Request duration",
            unit="ms"
        )

        self.active_connections = meter.create_up_down_counter(
            "rpc.connections.active",
            description="Active connections"
        )

    async def process_request(self, request, context):
        start_time = asyncio.get_event_loop().time()

        self.request_counter.add(1, {
            "method": context.method,
            "client": context.peer()
        })

        try:
            result = await self._process(request)

            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            self.request_duration.record(duration_ms, {
                "method": context.method,
                "status": "success"
            })

            return result

        except Exception as e:
            self.request_duration.record(duration_ms, {
                "method": context.method,
                "status": "error",
                "error_type": type(e).__name__
            })
            raise
```

### Log Correlation

```python
from provide.foundation import logger

class CorrelatedLoggingHandler:
    async def process_request(self, request):
        span = trace.get_current_span()
        span_context = span.get_span_context()

        # Log with trace correlation
        logger.info(
            "Processing request",
            request_id=request.id,
            trace_id=format(span_context.trace_id, '032x'),
            span_id=format(span_context.span_id, '016x')
        )

        with logger.contextualize(trace_id=format(span_context.trace_id, '032x')):
            await self._do_work(request)
```

## Exporters and Backends

=== "Jaeger"

    ```python
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    jaeger_exporter = JaegerExporter(
        agent_host_name="localhost",
        agent_port=6831,
    )

    trace.set_tracer_provider(TracerProvider())
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(jaeger_exporter)
    )
    ```

=== "OTLP"

    ```python
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    trace_exporter = OTLPSpanExporter(
        endpoint="localhost:4317",
        headers=(("api-key", "your-api-key"),)
    )

    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(trace_exporter)
    )
    ```

=== "Prometheus"

    ```python
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    from opentelemetry.sdk.metrics import MeterProvider

    prometheus_reader = PrometheusMetricReader()
    metrics.set_meter_provider(
        MeterProvider(metric_readers=[prometheus_reader])
    )
    ```

## CPU Optimization

### Multi-Threading Configuration

```python
from pyvider.rpcplugin.performance import CPUConfig

cpu_config = CPUConfig(
    worker_threads=8,           # Match CPU cores
    async_io_threads=4,         # I/O worker threads
    enable_thread_affinity=True
)

server = plugin_server(
    services=[CPUIntensiveService()],
    cpu_config=cpu_config
)
```

### Async Performance Patterns

```python
class OptimizedService:
    def __init__(self):
        self.processing_semaphore = asyncio.Semaphore(100)
        self.batch_size = 50

    async def process_batch_requests(self, requests):
        async def process_single(request):
            async with self.processing_semaphore:
                return await self.process_request(request)

        # Process in batches to control memory
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

## Memory Optimization

### Object Pooling

```python
from pyvider.rpcplugin.memory import MemoryPool, BufferPool

class OptimizedService:
    def __init__(self):
        self.request_pool = MemoryPool(
            create_func=lambda: RequestObject(),
            reset_func=lambda obj: obj.reset(),
            max_size=1000
        )

        self.buffer_pool = BufferPool(
            buffer_size=64 * 1024,
            pool_size=100
        )

    async def process_request(self, data):
        request_obj = self.request_pool.acquire()
        buffer = self.buffer_pool.acquire()

        try:
            request_obj.parse(data)
            result = await self.process_with_buffer(request_obj, buffer)
            return result
        finally:
            self.request_pool.release(request_obj)
            self.buffer_pool.release(buffer)
```

### Garbage Collection Tuning

```python
import gc
from pyvider.rpcplugin.memory import GCOptimizer

gc_optimizer = GCOptimizer(
    generation_thresholds=(1000, 20, 20),
    gc_frequency="adaptive",
    disable_gc_during_requests=True
)

gc_optimizer.apply_server_optimizations()

async def periodic_gc_cleanup():
    while True:
        await asyncio.sleep(30)
        if server.is_idle():
            gc.collect(2)  # Full collection during idle
```

## Network Optimization

### Connection Pooling

```python
from pyvider.rpcplugin.network import ConnectionPool

conn_pool = ConnectionPool(
    max_connections=2000,
    max_idle_connections=500,
    connection_timeout=5.0,
    keepalive_time=60.0,
    tcp_nodelay=True,
    tcp_keepalive=True
)

async with plugin_client(
    connection_pool=conn_pool,
    enable_connection_reuse=True
) as client:
    results = await asyncio.gather(*[
        client.service.method(i) for i in range(1000)
    ])
```

### Protocol Optimization

```python
from pyvider.rpcplugin.protocol import ProtocolConfig

protocol_config = ProtocolConfig(
    max_send_message_length=100 * 1024 * 1024,
    max_receive_message_length=100 * 1024 * 1024,
    compression="gzip",
    compression_level=6,
    http2_window_size=16 * 1024 * 1024,
    keepalive_time=30,
    keepalive_timeout=5
)
```

## Profiling and Benchmarking

### Production Profiling

```python
from pyvider.rpcplugin.profiling import ProductionProfiler

profiler = ProductionProfiler(
    sampling_rate=0.001,    # 0.1% sampling
    profile_duration=300,   # 5 minute windows
    auto_upload=True
)

@profiler.profile_method("critical_service_method")
async def critical_service_method(self, request):
    result = await self.process_request(request)
    return result
```

### Performance Benchmarks

```python
from pyvider.rpcplugin.benchmark import PerformanceBenchmark

async def benchmark_plugin_performance():
    benchmark = PerformanceBenchmark()

    # Throughput test
    throughput_results = await benchmark.measure_throughput(
        test_func=lambda: client.service.simple_method(),
        duration=60.0,
        concurrent_clients=50
    )

    # Latency test
    latency_results = await benchmark.measure_latency(
        test_func=lambda: client.service.simple_method(),
        num_samples=10000
    )

    report = benchmark.generate_report({
        "throughput": throughput_results,
        "latency": latency_results
    })

    return report
```

## Scaling Strategies

=== "Horizontal"

    ```python
    from pyvider.rpcplugin.scaling import LoadBalancer

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

=== "Vertical"

    ```python
    from pyvider.rpcplugin.scaling import ResourceOptimizer

    resource_optimizer = ResourceOptimizer(
        cpu_cores="auto",
        memory_limit="80%",
        disk_cache_size="20%",
        network_buffers="adaptive"
    )

    resource_optimizer.apply_optimizations()

    server = plugin_server(
        services=[ScalableService()],
        resource_optimizer=resource_optimizer,
        enable_auto_scaling=True
    )
    ```

=== "Auto-Scaling"

    ```python
    from pyvider.rpcplugin.scaling import AutoScaler

    auto_scaler = AutoScaler(
        min_instances=2,
        max_instances=20,
        target_cpu_utilization=70,
        target_memory_utilization=80,
        scale_up_threshold=2,
        scale_down_threshold=10
    )

    await auto_scaler.start_monitoring()
    ```

## Monitoring and Alerting

### Performance Metrics

```python
from pyvider.rpcplugin.metrics import PerformanceMetrics
from provide.foundation import logger

metrics = PerformanceMetrics()

async def track_performance():
    while True:
        stats = metrics.get_current_stats()

        logger.info("Performance metrics", extra={
            "requests_per_second": stats.requests_per_second,
            "average_latency_ms": stats.average_latency_ms,
            "memory_usage_mb": stats.memory_usage_mb,
            "cpu_utilization_percent": stats.cpu_utilization,
            "active_connections": stats.active_connections
        })

        if stats.requests_per_second < expected_rps * 0.8:
            logger.warning("Performance degradation detected")

        await asyncio.sleep(30)
```

### Health Checks

```python
from pyvider.rpcplugin.health import PerformanceHealthCheck

health_check = PerformanceHealthCheck(
    max_response_time=100,
    max_cpu_usage=80,
    max_memory_usage=85,
    min_throughput=1000
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

### Observability

1. **Use semantic conventions** for span attributes
2. **Avoid high cardinality** in metric labels
3. **Sample appropriately** - balance observability with performance
4. **Add context to errors** - include trace IDs in error messages
5. **Correlate logs with traces** - use structured logging with trace context

### Performance

1. **Profile before optimizing** - measure to identify bottlenecks
2. **Optimize hot paths** - focus on frequently executed code
3. **Use connection pooling** - reuse connections to reduce overhead
4. **Control concurrency** - limit concurrent operations
5. **Monitor continuously** - track metrics in production
6. **Test under load** - validate with realistic workloads

## Troubleshooting

### High Latency

```python
# Identify latency sources
if average_latency > target_latency:
    latency_breakdown = profiler.get_latency_breakdown()
    for component, latency in latency_breakdown.items():
        if latency > threshold:
            logger.info(f"High latency in {component}: {latency}ms")
```

### Memory Leaks

```python
from pyvider.rpcplugin.monitoring import MemoryMonitor

memory_monitor = MemoryMonitor(
    check_interval=10.0,
    warning_threshold=0.8,
    critical_threshold=0.95,
    track_object_counts=True
)

async with memory_monitor.monitoring_context():
    stats = memory_monitor.get_current_stats()
    if stats.usage_percent > 0.8:
        logger.warning("High memory usage", extra={
            "usage_percent": stats.usage_percent,
            "largest_objects": stats.largest_object_types[:5]
        })
```

### Trace Sampling

```python
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

# Production: Sample 1% of traces
sampler = TraceIdRatioBased(0.01)

trace.set_tracer_provider(
    TracerProvider(sampler=sampler)
)
```

## Related Topics

- [Lifecycle Management](lifecycle.md) - Plugin lifecycle optimization
- [Middleware](middleware.md) - Performance middleware patterns
- [Foundation Integration](foundation-integration.md) - Advanced integration patterns
- [Configuration](../config/configuration-guide.md) - Performance configuration
