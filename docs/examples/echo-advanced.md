# Advanced Echo Service - Production Patterns

This guide demonstrates advanced patterns for building production-ready RPC services, extending the [Basic](echo-basic.md) and [Intermediate](echo-intermediate.md) echo examples.

## Bidirectional Streaming

Bidirectional streaming enables real-time, two-way communication:

```protobuf
service EchoService {
  // Bidirectional streaming - real-time conversation
  rpc BidirectionalEcho(stream EchoRequest) returns (stream EchoResponse);
}
```

Server implementation:

```python
async def BidirectionalEcho(
    self,
    request_iterator: AsyncIterator[echo_pb2.EchoRequest],
    context: grpc.aio.ServicerContext
) -> AsyncIterator[echo_pb2.EchoResponse]:
    """Bidirectional streaming - real-time conversation."""
    sequence = 0

    async for request in request_iterator:
        sequence += 1
        logger.debug(f"Bidi echo received: {request.message}")

        # Echo back immediately
        response = echo_pb2.EchoResponse(
            reply=f"Echo: {request.message}"
        )
        yield response

        # Handle special commands
        if request.message.lower() == "ping":
            await asyncio.sleep(0.5)
            yield echo_pb2.EchoResponse(reply="Pong!")
```

## Error Handling

### Server-Side Validation

```python
async def Echo(self, request, context):
    # Validate input
    if not request.message or len(request.message) > 1000:
        await context.abort(
            grpc.StatusCode.INVALID_ARGUMENT,
            "Message must be 1-1000 characters"
        )

    # Handle processing errors
    try:
        result = await process_message(request.message)
        return echo_pb2.EchoResponse(reply=result)
    except ValueError as e:
        await context.abort(
            grpc.StatusCode.INVALID_ARGUMENT,
            f"Invalid input: {e}"
        )
    except Exception as e:
        logger.error(f"Processing failed: {e}", exc_info=True)
        await context.abort(
            grpc.StatusCode.INTERNAL,
            "Internal server error"
        )
```

### Client-Side Retry

```python
async def call_echo_with_retry(
    self,
    message: str,
    max_retries: int = 3
) -> str | None:
    for attempt in range(max_retries):
        try:
            return await self.call_echo(message)
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
            raise
    return None
```

## Health Monitoring

### Server Health Checks

```python
from pyvider.rpcplugin import plugin_server

server = plugin_server(
    protocol=echo_protocol_instance,
    handler=handler,
    config={
        "PLUGIN_HEALTH_SERVICE_ENABLED": True
    }
)
```

### Client Health Monitoring

```python
from grpc_health.v1 import health_pb2, health_pb2_grpc

health_stub = health_pb2_grpc.HealthStub(client.grpc_channel)
health_response = await health_stub.Check(
    health_pb2.HealthCheckRequest(service="echo.EchoService")
)

if health_response.status == health_pb2.HealthCheckResponse.SERVING:
    logger.info("Service is healthy")
```

## Rate Limiting

### Server-Side Rate Limiting

```python
from pyvider.rpcplugin import plugin_server

server = plugin_server(
    protocol=echo_protocol,
    handler=handler,
    config={
        "PLUGIN_RATE_LIMIT_ENABLED": True,
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 100.0,
        "PLUGIN_RATE_LIMIT_BURST_CAPACITY": 200
    }
)
```

### Per-Client Rate Limiting

```python
class RateLimitedEchoHandler(echo_pb2_grpc.EchoServiceServicer):
    def __init__(self):
        self.limiters = {}  # client_id -> TokenBucketRateLimiter

    async def Echo(self, request, context):
        client_id = context.peer()  # Get client identity

        limiter = self.limiters.setdefault(
            client_id,
            TokenBucketRateLimiter(
                capacity=10.0,
                refill_rate=1.0
            )
        )

        if not await limiter.is_allowed():
            await context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "Rate limit exceeded"
            )

        return await self.process_echo(request)
```

## Metrics and Telemetry

### Adding Metrics

```python
from pyvider.rpcplugin.telemetry import get_rpc_tracer

tracer = get_rpc_tracer()

async def Echo(self, request, context):
    with tracer.start_as_current_span("echo.process"):
        logger.info(
            "Processing echo request",
            extra={
                "message_length": len(request.message),
                "client_id": context.peer()
            }
        )
        return await self.process_echo(request)
```

### Request Tracking

```python
import uuid
import time

class TrackedEchoHandler(echo_pb2_grpc.EchoServiceServicer):
    def __init__(self):
        self.request_count = 0
        self.total_latency = 0.0

    async def Echo(self, request, context):
        request_id = str(uuid.uuid4())
        start_time = time.time()

        try:
            self.request_count += 1
            result = await self.process_echo(request)

            latency = time.time() - start_time
            self.total_latency += latency

            logger.info(
                "Request completed",
                extra={
                    "request_id": request_id,
                    "latency_ms": latency * 1000,
                    "total_requests": self.request_count,
                    "avg_latency_ms": (self.total_latency / self.request_count) * 1000
                }
            )

            return result
        except Exception as e:
            logger.error(
                "Request failed",
                extra={"request_id": request_id, "error": str(e)},
                exc_info=True
            )
            raise
```

## Production Configuration

### mTLS Security

```python
from pyvider.rpcplugin import plugin_server

server = plugin_server(
    protocol=echo_protocol,
    handler=handler,
    config={
        "PLUGIN_AUTO_MTLS": True,
        "PLUGIN_SERVER_CERT": "file:///etc/ssl/certs/server.crt",
        "PLUGIN_SERVER_KEY": "file:///etc/ssl/private/server.key",
        "PLUGIN_CA_CERT": "file:///etc/ssl/certs/ca.crt"
    }
)
```

### Resource Limits

```python
server = plugin_server(
    protocol=echo_protocol,
    handler=handler,
    config={
        "PLUGIN_GRPC_MAX_CONCURRENT_STREAMS": 100,
        "PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE": 4 * 1024 * 1024,  # 4MB
        "PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE": 4 * 1024 * 1024,
        "PLUGIN_GRPC_KEEPALIVE_TIME_MS": 30000,
        "PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS": 5000
    }
)
```

## Testing

### Unit Testing

```python
import pytest
from unittest.mock import Mock

@pytest.mark.asyncio
async def test_echo_handler():
    handler = EchoHandler()
    request = echo_pb2.EchoRequest(message="test")
    context = Mock()

    response = await handler.Echo(request, context)

    assert "test" in response.reply
    assert response.reply.startswith("Server echoed:")
```

### Integration Testing

```python
@pytest.mark.asyncio
async def test_echo_service_integration():
    # Start server in background
    server_task = asyncio.create_task(run_echo_server())
    await asyncio.sleep(1)  # Wait for server start

    try:
        # Connect client
        client = EchoClient("path/to/server.py")
        await client.start()

        # Test RPC
        reply = await client.call_echo("Integration test")
        assert reply is not None
        assert "Integration test" in reply

    finally:
        await client.close()
        server_task.cancel()
```

## Next Steps

- **[Production Config](production-config-discussion.md)** - Deployment patterns
- **[Security Guide](../guide/security/mtls.md)** - Comprehensive security setup
- **[Performance Tuning](performance-tuning-concepts.md)** - Optimization techniques
- **[Telemetry Demo](telemetry-demo.md)** - Observability integration

## Reference

- **Basic Example**: [Echo Basic](echo-basic.md)
- **Intermediate Patterns**: [Echo Intermediate](echo-intermediate.md)
- **Source Code**: `examples/echo_server.py`, `examples/echo_client.py`
