# Echo Service Example

A comprehensive example demonstrating RPC plugin development from basic unary calls to production-focused patterns with streaming, error handling, and observability.

!!! note "Documentation vs. Actual Code" This documentation provides **simplified code examples** focused on teaching core concepts. The actual files (`examples/echo_server.py` and `examples/echo_client.py`) contain production-focused patterns with additional error handling, environment setup, and utility functions.

````
**To run the actual working example:**
```bash
python examples/echo_client.py
```
````

## Overview

The Echo service demonstrates the full spectrum of pyvider-rpcplugin capabilities:

- **Unary RPC** - Client sends message, server echoes back
- **Streaming Patterns** - Server streaming, client streaming, bidirectional streaming
- **Error Handling** - Validation, retry logic, graceful degradation
- **Production Features** - Health monitoring, rate limiting, metrics, security
- **Testing** - Unit and integration test patterns

## Service Definition

The service is defined in `examples/proto/echo.proto`:

```protobuf
syntax = "proto3";

package echo;

service EchoService {
  // Unary RPC - simple request/response
  rpc Echo(EchoRequest) returns (EchoResponse);

  // Streaming patterns
  rpc ServerStreamEcho(EchoRequest) returns (stream EchoResponse);
  rpc ClientStreamEcho(stream EchoRequest) returns (EchoResponse);
  rpc BidirectionalEcho(stream EchoRequest) returns (stream EchoResponse);
}

message EchoRequest {
  string message = 1;
}

message EchoResponse {
  string reply = 1;
}
```

## Implementation

=== "Basic Setup"

````
### Server Implementation

The server implements three key components:

**1. Service Handler**

```python
class EchoHandler(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        logger.info(f"Received Echo request: '{request.message}'")
        reply_message = f"Server echoed: {request.message}"
        return echo_pb2.EchoResponse(reply=reply_message)
```

**2. Protocol Wrapper**

```python
class EchoProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return echo_pb2_grpc, "echo.EchoService"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        echo_pb2_grpc.add_EchoServiceServicer_to_server(handler, server)
        logger.info("EchoService handler registered with gRPC server")
```

**3. Server Initialization**

```python
async def main() -> None:
    logger.info("Starting Echo Plugin Server...")

    handler = EchoHandler()
    echo_protocol_instance = cast(TypesRPCPluginProtocol, EchoProtocol())

    server: RPCPluginServer = plugin_server(
        protocol=echo_protocol_instance,
        handler=handler,
    )

    await server.serve()
```

### Client Implementation

**1. Client Setup**

```python
class EchoClient:
    def __init__(self, server_script_path: str) -> None:
        self.server_script_path = server_script_path
        self.client_config = {
            "env": {
                "PLUGIN_MAGIC_COOKIE_KEY": rpcplugin_config.plugin_magic_cookie_key,
                "PLUGIN_MAGIC_COOKIE_VALUE": rpcplugin_config.plugin_magic_cookie_value,
                "PLUGIN_LOG_LEVEL": rpcplugin_config.plugin_log_level,
                "PLUGIN_AUTO_MTLS": str(rpcplugin_config.plugin_auto_mtls).lower(),
            }
        }

    async def start(self) -> bool:
        self._client = RPCPluginClient(
            command=[sys.executable, self.server_script_path],
            config=self.client_config,
        )
        await self._client.start()
        self._stub = echo_pb2_grpc.EchoServiceStub(self._client.grpc_channel)
        return True
```

**2. Making RPC Calls**

```python
async def call_echo(self, message: str) -> str | None:
    request = echo_pb2.EchoRequest(message=message)
    response = await self._stub.Echo(request)
    return response.reply
```
````

=== "Streaming Patterns"

````
### Server Streaming

Server sends multiple responses for a single request:

```python
async def ServerStreamEcho(
    self,
    request: echo_pb2.EchoRequest,
    context: grpc.aio.ServicerContext
) -> AsyncIterator[echo_pb2.EchoResponse]:
    """Server streaming - sends multiple responses."""
    logger.info(f"Server stream echo started: {request.message}")

    for i in range(5):
        if context.cancelled():
            logger.info("Client cancelled server stream")
            break

        response = echo_pb2.EchoResponse(
            reply=f"Echo #{i+1}: {request.message}"
        )
        yield response
        await asyncio.sleep(1)
```

**Client usage:**

```python
async for response in stub.ServerStreamEcho(request):
    print(f"Received: {response.reply}")
```

### Client Streaming

Client sends multiple requests, server responds once:

```python
async def ClientStreamEcho(
    self,
    request_iterator: AsyncIterator[echo_pb2.EchoRequest],
    context: grpc.aio.ServicerContext
) -> echo_pb2.EchoResponse:
    """Client streaming - collects messages and responds."""
    messages = []

    async for request in request_iterator:
        messages.append(request.message)
        logger.debug(f"Received message: {request.message}")

    summary = f"Received {len(messages)} messages: {', '.join(messages)}"
    return echo_pb2.EchoResponse(reply=summary)
```

**Client usage:**

```python
async def request_generator():
    for msg in ["Hello", "World", "RPC"]:
        yield echo_pb2.EchoRequest(message=msg)
        await asyncio.sleep(0.5)

response = await stub.ClientStreamEcho(request_generator())
print(f"Summary: {response.reply}")
```

### Bidirectional Streaming

Real-time two-way communication:

```python
async def BidirectionalEcho(
    self,
    request_iterator: AsyncIterator[echo_pb2.EchoRequest],
    context: grpc.aio.ServicerContext
) -> AsyncIterator[echo_pb2.EchoResponse]:
    """Bidirectional streaming - real-time conversation."""
    async for request in request_iterator:
        logger.debug(f"Bidi echo received: {request.message}")

        # Echo back immediately
        yield echo_pb2.EchoResponse(reply=f"Echo: {request.message}")

        # Handle special commands
        if request.message.lower() == "ping":
            await asyncio.sleep(0.5)
            yield echo_pb2.EchoResponse(reply="Pong!")
```

### Best Practices

**Handle Cancellation:**

```python
async def ServerStreamEcho(self, request, context):
    for i in range(100):
        if context.cancelled():
            logger.info("Stream cancelled by client")
            return
        yield create_response(i)
```

**Add Timeouts:**

```python
async def call_server_stream(self, message: str):
    try:
        async for response in asyncio.wait_for(
            self._stub.ServerStreamEcho(request),
            timeout=30.0
        ):
            process(response)
    except TimeoutError:
        logger.error("Stream timed out")
```

**Use Backpressure:**

```python
async def controlled_stream(self):
    semaphore = asyncio.Semaphore(10)  # Max 10 in-flight

    async for request in request_iterator:
        async with semaphore:
            await process_request(request)
```
````

=== "Error Handling"

````
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
````

=== "Production Features"

````
### Health Monitoring

**Server Configuration:**

```python
server = plugin_server(
    protocol=echo_protocol_instance,
    handler=handler,
    config={
        "PLUGIN_HEALTH_SERVICE_ENABLED": True
    }
)
```

**Client Health Check:**

```python
from grpc_health.v1 import health_pb2, health_pb2_grpc

health_stub = health_pb2_grpc.HealthStub(client.grpc_channel)
health_response = await health_stub.Check(
    health_pb2.HealthCheckRequest(service="echo.EchoService")
)

if health_response.status == health_pb2.HealthCheckResponse.SERVING:
    logger.info("Service is healthy")
```

### Rate Limiting

**Server-Side Configuration:**

```python
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

**Per-Client Rate Limiting:**

```python
class RateLimitedEchoHandler(echo_pb2_grpc.EchoServiceServicer):
    def __init__(self):
        self.limiters = {}  # client_id -> TokenBucketRateLimiter

    async def Echo(self, request, context):
        client_id = context.peer()

        limiter = self.limiters.setdefault(
            client_id,
            TokenBucketRateLimiter(capacity=10.0, refill_rate=1.0)
        )

        if not await limiter.is_allowed():
            await context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "Rate limit exceeded"
            )

        return await self.process_echo(request)
```

### Metrics and Telemetry

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

### Security (mTLS)

```python
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
````

=== "Testing"

````
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
````

## Running the Example

From the project root directory:

```bash
python examples/echo_client.py
```

The client will automatically:

1. Launch `echo_server.py` as a subprocess
1. Perform the handshake protocol
1. Establish a gRPC connection
1. Make Echo RPC calls
1. Clean up and terminate the server

### Expected Output

```
2025-01-15 10:30:45.123 [info     ] Client will use server script: .../examples/echo_server.py
2025-01-15 10:30:45.200 [info     ] Starting Echo Plugin Server...
2025-01-15 10:30:45.201 [info     ] EchoService handler registered with gRPC server
2025-01-15 10:30:45.250 [info     ] Client started and connected successfully
2025-01-15 10:30:45.251 [info     ] Sending Echo request to server: 'Hello from pyvider client!'
2025-01-15 10:30:45.252 [info     ] Handler: Received Echo request: 'Hello from pyvider client!'
2025-01-15 10:30:45.253 [info     ] Received Echo reply from server: 'Server echoed: Hello from pyvider client!'
```

## Key Concepts Demonstrated

### Plugin Architecture

- Server runs as independent subprocess
- Client manages server lifecycle
- Clean separation of concerns

### Foundation Integration

- Structured logging with `provide.foundation.logger`
- Configuration via environment variables
- Type-safe configuration access

### gRPC Integration

- Protocol Buffer message definitions
- Async/await RPC patterns
- Stub-based client calls
- Streaming (server, client, bidirectional)

### Production Readiness

- Health monitoring
- Rate limiting
- Metrics and telemetry
- mTLS security
- Error handling and retry logic

## Common Issues

### Server Not Found

If you get "Could not find echo_server.py":

```bash
# Make sure you're running from project root
cd /path/to/pyvider-rpcplugin
python examples/echo_client.py
```

### Import Errors

If you get "ModuleNotFoundError":

- The `example_utils.configure_for_example()` call should handle path setup
- Ensure you're running from the project root directory

### Connection Timeout

If the client times out:

- Check the server logs for errors
- Verify no other process is using the socket/port
- Try increasing timeout: `await asyncio.wait_for(self._client.start(), timeout=30.0)`

### Stream Cancellation Issues

If streams don't properly cancel:

- Ensure you're checking `context.cancelled()` in server-side streaming methods
- Use proper timeout values with `asyncio.wait_for()`
- Clean up resources in `finally` blocks

## Next Steps

### Explore More Features

- **[Security Guide](../guide/security/mtls.md)** - Comprehensive mTLS setup
- **[Performance Tuning](../guide/advanced/observability.md)** - Optimization techniques
- **[Production Configuration](../guide/config/advanced.md)** - Deployment patterns

### Study Core Concepts

- **[RPC Architecture](../guide/concepts/architecture-and-handshake.md)** - Understanding the plugin model
- **[Transport Configuration](../guide/concepts/transports.md)** - Unix sockets vs TCP
- **[Security Model](../guide/concepts/security.md)** - Authentication and encryption

### Additional Examples

- **[Quick Start Examples](quick-start.md)** - Focused code samples for specific features
- **[Direct Connection Example](../guide/client/direct-connections.md)** - Connect to existing server

## Source Code

- Server: `examples/echo_server.py`
- Client: `examples/echo_client.py`
- Protocol: `examples/proto/echo.proto`
