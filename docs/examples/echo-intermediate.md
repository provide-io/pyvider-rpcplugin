# Intermediate Echo Service - Streaming Patterns

This guide shows how to extend the [Basic Echo Service](echo-basic.md) with streaming RPC patterns.

## Overview

Building on the basic unary Echo service, this guide demonstrates:
- **Server Streaming** - Server sends multiple responses
- **Client Streaming** - Client sends multiple requests
- **Request/Response Patterns** - Handling streams effectively

## Adding Server Streaming

Extend the proto definition:

```protobuf
service EchoService {
  rpc Echo(EchoRequest) returns (EchoResponse);

  // Server streaming - returns multiple echo responses
  rpc ServerStreamEcho(EchoRequest) returns (stream EchoResponse);
}
```

Implement in the handler:

```python
async def ServerStreamEcho(
    self,
    request: echo_pb2.EchoRequest,
    context: grpc.aio.ServicerContext
) -> AsyncIterator[echo_pb2.EchoResponse]:
    """Server streaming - sends multiple responses."""
    logger.info(f"Server stream echo started: {request.message}")

    # Send 5 echo responses with delay
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

Client usage:

```python
async for response in stub.ServerStreamEcho(request):
    print(f"Received: {response.reply}")
```

## Adding Client Streaming

Extend the proto definition:

```protobuf
service EchoService {
  // Client streaming - collects messages and returns summary
  rpc ClientStreamEcho(stream EchoRequest) returns (EchoResponse);
}
```

Implement in the handler:

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

Client usage:

```python
async def request_generator():
    for msg in ["Hello", "World", "RPC"]:
        yield echo_pb2.EchoRequest(message=msg)
        await asyncio.sleep(0.5)

response = await stub.ClientStreamEcho(request_generator())
print(f"Summary: {response.reply}")
```

## Best Practices

### 1. Handle Cancellation

Always check if the client cancelled the stream:

```python
async def ServerStreamEcho(self, request, context):
    for i in range(100):
        if context.cancelled():
            logger.info("Stream cancelled by client")
            return
        yield create_response(i)
```

### 2. Add Timeouts

Protect against slow or stalled streams:

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

### 3. Use Backpressure

Control message flow to prevent overwhelming the receiver:

```python
async def controlled_stream(self):
    semaphore = asyncio.Semaphore(10)  # Max 10 in-flight

    async for request in request_iterator:
        async with semaphore:
            await process_request(request)
```

## Implementation Steps

To add streaming to your echo service:

1. **Update Protocol Buffer** - Add streaming RPC definitions
2. **Regenerate Code** - Run `protoc` to update `_pb2` files
3. **Implement Handlers** - Add streaming methods to servicer
4. **Update Client** - Add streaming call methods
5. **Test Thoroughly** - Test cancellation, timeouts, errors

## Next Steps

- **[Echo Advanced](echo-advanced.md)** - Bidirectional streaming and advanced patterns
- **[Async Patterns](async-patterns-demo.md)** - Deep dive into asyncio patterns
- **[Error Handling](error-handling-demo.md)** - Robust error management

## Reference

- **Basic Example**: [Echo Basic](echo-basic.md)
- **Source Code**: `examples/echo_server.py`, `examples/echo_client.py`
- **gRPC Streaming**: [gRPC Python Documentation](https://grpc.io/docs/languages/python/basics/#streaming-rpcs)
