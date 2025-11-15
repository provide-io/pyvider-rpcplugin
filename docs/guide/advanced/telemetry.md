# Telemetry and Observability

The `pyvider.rpcplugin` framework provides built-in OpenTelemetry integration for comprehensive observability of your RPC services. This enables distributed tracing, metrics collection, and logging correlation across your plugin architecture.

## Overview

OpenTelemetry support allows you to:

- **Trace requests** across client-server boundaries
- **Collect metrics** on RPC performance and errors
- **Correlate logs** with traces for debugging
- **Export telemetry** to various backends (Jaeger, Prometheus, etc.)
- **Monitor health** and performance in production

## Basic Setup

### Installation

Install OpenTelemetry dependencies:

```bash
pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation-grpc
```

### Getting the Tracer

The framework provides a configured tracer:

```python
from pyvider.rpcplugin.telemetry import get_rpc_tracer

tracer = get_rpc_tracer()
```

## Instrumentation

### Server-Side Tracing

Instrument your server handlers with tracing:

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_protocol
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from provide.foundation import logger
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

tracer = get_rpc_tracer()

class TracedHandler:
    """Handler with OpenTelemetry tracing."""

    async def process_request(self, request, context):
        """Process request with tracing."""
        with tracer.start_as_current_span(
            "process_request",
            kind=trace.SpanKind.SERVER
        ) as span:
            # Add span attributes
            span.set_attribute("request.id", request.id)
            span.set_attribute("request.type", request.type)

            try:
                # Log with trace correlation
                logger.info(
                    "Processing request",
                    request_id=request.id,
                    trace_id=span.get_span_context().trace_id
                )

                # Simulate processing
                result = await self._do_processing(request)

                span.set_attribute("response.status", "success")
                return result

            except Exception as e:
                # Record exception in trace
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
                logger.error(
                    "Request processing failed",
                    error=str(e),
                    trace_id=span.get_span_context().trace_id
                )
                raise

    async def _do_processing(self, request):
        """Internal processing with nested span."""
        with tracer.start_as_current_span("database_query") as span:
            span.set_attribute("db.operation", "select")
            span.set_attribute("db.table", "users")

            # Simulate database query
            await asyncio.sleep(0.1)
            return {"status": "success", "data": "..."}

async def main():
    protocol = plugin_protocol()
    handler = TracedHandler()
    server = plugin_server(protocol=protocol, handler=handler)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

### Client-Side Tracing

Add tracing to client calls:

```python
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from opentelemetry import trace, propagate

tracer = get_rpc_tracer()

async def make_traced_call(client, request):
    """Make RPC call with distributed tracing."""
    with tracer.start_as_current_span(
        "rpc_call",
        kind=trace.SpanKind.CLIENT
    ) as span:
        # Add span attributes
        span.set_attribute("rpc.service", "MyService")
        span.set_attribute("rpc.method", "ProcessRequest")
        span.set_attribute("request.id", request.id)

        # Inject trace context for distributed tracing
        headers = {}
        propagate.inject(headers)

        try:
            # Make the RPC call with trace context
            response = await client.call_with_headers(
                "ProcessRequest",
                request,
                metadata=headers
            )

            span.set_attribute("response.status", response.status)
            return response

        except Exception as e:
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            raise
```

## Metrics Collection

### Setting Up Metrics

Configure OpenTelemetry metrics:

```python
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.prometheus import PrometheusMetricReader

# Set up Prometheus metrics exporter
prometheus_reader = PrometheusMetricReader()
metrics.set_meter_provider(
    MeterProvider(metric_readers=[prometheus_reader])
)

meter = metrics.get_meter("pyvider.rpcplugin")
```

### Creating Custom Metrics

Add custom metrics to your handlers:

```python
class MetricsHandler:
    """Handler with custom metrics."""

    def __init__(self):
        meter = metrics.get_meter(__name__)

        # Create metrics
        self.request_counter = meter.create_counter(
            "rpc.requests.total",
            description="Total number of RPC requests"
        )

        self.request_duration = meter.create_histogram(
            "rpc.request.duration",
            description="RPC request duration in milliseconds",
            unit="ms"
        )

        self.active_connections = meter.create_up_down_counter(
            "rpc.connections.active",
            description="Number of active connections"
        )

    async def process_request(self, request, context):
        """Process request with metrics."""
        start_time = asyncio.get_event_loop().time()

        # Increment request counter
        self.request_counter.add(1, {
            "method": context.method,
            "client": context.peer()
        })

        try:
            result = await self._process(request)

            # Record duration
            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            self.request_duration.record(duration_ms, {
                "method": context.method,
                "status": "success"
            })

            return result

        except Exception as e:
            # Record error metrics
            duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
            self.request_duration.record(duration_ms, {
                "method": context.method,
                "status": "error",
                "error_type": type(e).__name__
            })
            raise
```

## Exporters Configuration

### Jaeger Exporter

Export traces to Jaeger:

```python
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Configure Jaeger exporter
jaeger_exporter = JaegerExporter(
    agent_host_name="localhost",
    agent_port=6831,
)

# Set up tracer provider with Jaeger
trace.set_tracer_provider(TracerProvider())
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(jaeger_exporter)
)
```

### OTLP Exporter

Export to OpenTelemetry Collector:

```python
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

# Configure OTLP exporters
trace_exporter = OTLPSpanExporter(
    endpoint="localhost:4317",
    headers=(("api-key", "your-api-key"),)
)

metric_exporter = OTLPMetricExporter(
    endpoint="localhost:4317",
    headers=(("api-key", "your-api-key"),)
)
```

## Distributed Tracing

### Context Propagation

Propagate trace context across service boundaries:

```python
from opentelemetry import propagate, trace
from opentelemetry.propagators.b3 import B3MultiFormat

# Set B3 propagator for compatibility with other systems
propagate.set_global_textmap(B3MultiFormat())

class DistributedTracingHandler:
    """Handler with distributed tracing support."""

    async def handle_request(self, request, context):
        """Extract and propagate trace context."""
        # Extract trace context from incoming request
        metadata = dict(context.invocation_metadata())
        ctx = propagate.extract(metadata)

        # Continue trace with extracted context
        with tracer.start_as_current_span(
            "handle_request",
            context=ctx,
            kind=trace.SpanKind.SERVER
        ) as span:
            # Process request in trace context
            result = await self.process(request)

            # If making downstream calls, inject context
            downstream_headers = {}
            propagate.inject(downstream_headers)

            await self.call_downstream(downstream_headers)
            return result
```

### Trace Sampling

Configure trace sampling to reduce overhead:

```python
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

# Sample 10% of traces
sampler = TraceIdRatioBased(0.1)

trace.set_tracer_provider(
    TracerProvider(sampler=sampler)
)
```

## Log Correlation

### Structured Logging with Trace IDs

Correlate logs with traces using Foundation's logger:

```python
from provide.foundation import logger
from opentelemetry import trace

class CorrelatedLoggingHandler:
    """Handler with trace-correlated logging."""

    async def process_request(self, request):
        """Process with correlated logging."""
        span = trace.get_current_span()
        span_context = span.get_span_context()

        # Log with trace correlation
        logger.info(
            "Processing request",
            request_id=request.id,
            trace_id=format(span_context.trace_id, '032x'),
            span_id=format(span_context.span_id, '016x'),
            trace_flags=span_context.trace_flags
        )

        # All logs within this span will have trace context
        with logger.contextualize(trace_id=format(span_context.trace_id, '032x')):
            await self._do_work(request)
```

## Performance Monitoring

### RPC Performance Dashboard

Create a performance monitoring setup:

```python
class PerformanceMonitor:
    """Monitor RPC performance with telemetry."""

    def __init__(self):
        meter = metrics.get_meter(__name__)

        # Performance metrics
        self.latency_histogram = meter.create_histogram(
            "rpc.latency",
            description="RPC latency distribution",
            unit="ms"
        )

        self.throughput_counter = meter.create_counter(
            "rpc.throughput",
            description="RPC throughput"
        )

        self.error_rate = meter.create_counter(
            "rpc.errors",
            description="RPC error rate"
        )

        # Resource metrics
        self.memory_usage = meter.create_observable_gauge(
            "process.memory.usage",
            callbacks=[self._get_memory_usage],
            description="Process memory usage",
            unit="bytes"
        )

    def _get_memory_usage(self, options):
        """Callback for memory usage metric."""
        import psutil
        process = psutil.Process()
        return [(process.memory_info().rss, {})]

    async def record_request(self, method, duration_ms, success):
        """Record request metrics."""
        self.throughput_counter.add(1, {"method": method})

        self.latency_histogram.record(
            duration_ms,
            {"method": method, "success": str(success)}
        )

        if not success:
            self.error_rate.add(1, {"method": method})
```

## Best Practices

### 1. Use Semantic Conventions

Follow OpenTelemetry semantic conventions:

```python
span.set_attribute("rpc.system", "grpc")
span.set_attribute("rpc.service", service_name)
span.set_attribute("rpc.method", method_name)
span.set_attribute("rpc.grpc.status_code", status_code)
```

### 2. Avoid High Cardinality

Don't use unbounded values as metric labels:

```python
# Bad: High cardinality
self.counter.add(1, {"user_id": user_id})  # Millions of unique values

# Good: Bounded cardinality
self.counter.add(1, {"user_tier": user_tier})  # Few distinct values
```

### 3. Sample Appropriately

Balance observability with performance:

```python
# Development: Sample everything
sampler = AlwaysOnSampler()

# Production: Sample a percentage
sampler = TraceIdRatioBased(0.01)  # 1% sampling
```

### 4. Add Context to Errors

Include trace context in error messages:

```python
span = trace.get_current_span()
error_message = f"Operation failed [trace_id={format(span.get_span_context().trace_id, '032x')}]"
```

## Troubleshooting

### Traces Not Appearing

1. Verify exporter configuration
2. Check network connectivity to collector
3. Ensure spans are being ended properly
4. Verify sampling configuration

### High Performance Overhead

1. Reduce sampling rate
2. Use async exporters
3. Batch span exports
4. Reduce span attributes

### Missing Trace Context

1. Verify propagator configuration
2. Check header injection/extraction
3. Ensure context is passed through async boundaries

## Related Topics

- [Performance Tuning](performance/) - Optimize service performance
- [Health Checks](../server/health-checks/) - Monitor service health
- [Logging Configuration](../config/logging/) - Configure structured logging
- [Production Setup](../config/production/) - Production deployment guide