# Rate Limiting

Rate limiting is a critical feature for protecting RPC servers from being overwhelmed by excessive requests. The `pyvider.rpcplugin` framework provides built-in rate limiting capabilities using a token bucket algorithm.

## Overview

The rate limiting feature uses Foundation's `TokenBucketRateLimiter` to control request throughput. This implementation:

- **Prevents server overload** by limiting requests per second
- **Provides burst capacity** for handling traffic spikes
- **Returns appropriate gRPC errors** when limits are exceeded
- **Integrates seamlessly** with the server interceptor chain

## Configuration

Rate limiting is configured through environment variables or the configuration API:

### Environment Variables

```bash
# Enable rate limiting
export PLUGIN_RATE_LIMIT_ENABLED=true

# Set requests per second limit
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0

# Set burst capacity (bucket size)
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=200
```

### Programmatic Configuration

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Configure rate limiting
rpcplugin_config.plugin_rate_limit_enabled = True
rpcplugin_config.plugin_rate_limit_requests_per_second = 100.0
rpcplugin_config.plugin_rate_limit_burst_capacity = 200
```

## How It Works

### Token Bucket Algorithm

The rate limiter uses a token bucket algorithm:

1. **Token Generation**: Tokens are added to the bucket at a fixed rate (requests per second)
2. **Request Handling**: Each request consumes one token from the bucket
3. **Burst Capacity**: The bucket can hold a maximum number of tokens (burst capacity)
4. **Request Rejection**: When the bucket is empty, requests are rejected

### Server Integration

The `RPCPluginServer` automatically creates a `RateLimitingInterceptor` when rate limiting is enabled:

```python
from pyvider.rpcplugin.server import RPCPluginServer, RateLimitingInterceptor
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

class RPCPluginServer:
    async def _create_grpc_server(self) -> None:
        interceptors = []

        # Add rate limiting interceptor if enabled
        if rpcplugin_config.plugin_rate_limit_enabled:
            rate_limiter = TokenBucketRateLimiter(
                tokens_per_second=rpcplugin_config.plugin_rate_limit_requests_per_second,
                bucket_size=rpcplugin_config.plugin_rate_limit_burst_capacity
            )
            interceptors.append(RateLimitingInterceptor(rate_limiter))

        self._server = grpc.aio.Server(interceptors=interceptors)
```

## Implementation Example

### Basic Rate-Limited Server

```python
#!/usr/bin/env python3
import asyncio
import os
from pyvider.rpcplugin import plugin_server, plugin_protocol
from provide.foundation import logger

# Configure rate limiting via environment
os.environ.update({
    "PLUGIN_RATE_LIMIT_ENABLED": "true",
    "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "10",
    "PLUGIN_RATE_LIMIT_BURST_CAPACITY": "20"
})

class MyHandler:
    async def process_request(self, request):
        """Process incoming request."""
        logger.info("Processing request", request_id=request.id)
        # Your business logic here
        return {"status": "success"}

async def main():
    protocol = plugin_protocol()
    handler = MyHandler()

    # Server automatically applies rate limiting based on configuration
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting rate-limited server (10 req/s, burst: 20)")
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

### Custom Rate Limiting

For more control, you can create custom rate limiting interceptors:

```python
from pyvider.rpcplugin.server import RateLimitingInterceptor
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
import grpc.aio

class CustomRateLimiter(grpc.aio.ServerInterceptor):
    """Custom rate limiter with per-method limits."""

    def __init__(self):
        # Different limits for different methods
        self.limiters = {
            "ExpensiveMethod": TokenBucketRateLimiter(5, 10),   # 5 req/s
            "CheapMethod": TokenBucketRateLimiter(100, 200),    # 100 req/s
            "default": TokenBucketRateLimiter(50, 100)          # 50 req/s default
        }

    async def intercept_service(self, continuation, handler_call_details):
        method_name = handler_call_details.method.split('/')[-1]
        limiter = self.limiters.get(method_name, self.limiters["default"])

        if not await limiter.acquire():
            context = handler_call_details.invocation_metadata()
            await context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                f"Rate limit exceeded for {method_name}"
            )

        return await continuation(handler_call_details)

# Use custom rate limiter
server = plugin_server(
    protocol=protocol,
    handler=handler,
    config={"interceptors": [CustomRateLimiter()]}
)
```

## Client-Side Handling

Clients should handle rate limit errors gracefully:

```python
import grpc
from pyvider.rpcplugin import plugin_client
import asyncio
from provide.foundation import logger

async def make_request_with_retry(client, request):
    """Make request with exponential backoff on rate limit."""
    max_retries = 5
    base_delay = 1.0

    for attempt in range(max_retries):
        try:
            return await client.some_method(request)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"Rate limited, retrying in {delay}s",
                    attempt=attempt + 1
                )
                await asyncio.sleep(delay)
            else:
                raise

    raise Exception("Max retries exceeded")
```

## Monitoring and Metrics

### Logging Rate Limit Events

The rate limiter logs important events:

```python
from provide.foundation import logger

class MonitoredRateLimiter(RateLimitingInterceptor):
    """Rate limiter with monitoring."""

    async def intercept_service(self, continuation, handler_call_details):
        if not await self._rate_limiter.acquire():
            # Log rate limit event
            logger.warning(
                "Rate limit exceeded",
                method=handler_call_details.method,
                remaining_tokens=self._rate_limiter.available_tokens,
                bucket_size=self._rate_limiter.bucket_size
            )
            # ... abort with RESOURCE_EXHAUSTED

        return await continuation(handler_call_details)
```

### OpenTelemetry Integration

Track rate limiting metrics with OpenTelemetry:

```python
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from opentelemetry import metrics

meter = metrics.get_meter(__name__)
rate_limit_counter = meter.create_counter(
    "rpc.rate_limit.rejections",
    description="Number of requests rejected due to rate limiting"
)

class TelemetryRateLimiter(RateLimitingInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        if not await self._rate_limiter.acquire():
            # Record metric
            rate_limit_counter.add(1, {
                "method": handler_call_details.method
            })
            # ... handle rate limit
```

## Best Practices

### 1. Set Appropriate Limits

Consider your server's capacity and expected traffic patterns:

```python
# Development environment
PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=10
PLUGIN_RATE_LIMIT_BURST_CAPACITY=20

# Production environment
PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000
PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000
```

### 2. Monitor and Adjust

Regularly review rate limiting metrics and adjust limits based on:
- Server resource utilization
- Client retry patterns
- Business requirements

### 3. Provide Clear Error Messages

Help clients understand rate limit errors:

```python
await context.abort(
    grpc.StatusCode.RESOURCE_EXHAUSTED,
    "Rate limit exceeded: max 100 requests per second. "
    "Please retry with exponential backoff."
)
```

### 4. Consider Per-Client Limits

For multi-tenant systems, implement per-client rate limiting:

```python
class PerClientRateLimiter(grpc.aio.ServerInterceptor):
    def __init__(self):
        self.client_limiters = {}

    def get_client_id(self, context):
        # Extract client ID from headers or auth token
        metadata = dict(context.invocation_metadata())
        return metadata.get('client-id', 'unknown')

    async def intercept_service(self, continuation, handler_call_details):
        client_id = self.get_client_id(handler_call_details.context)

        if client_id not in self.client_limiters:
            self.client_limiters[client_id] = TokenBucketRateLimiter(
                tokens_per_second=100,
                bucket_size=200
            )

        limiter = self.client_limiters[client_id]
        # ... apply rate limiting
```

## Troubleshooting

### Common Issues

1. **Rate limits too restrictive**
   - Symptom: Clients frequently receive RESOURCE_EXHAUSTED errors
   - Solution: Increase `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` or `PLUGIN_RATE_LIMIT_BURST_CAPACITY`

2. **Server still overloaded despite rate limiting**
   - Symptom: High server resource usage even with rate limiting enabled
   - Solution: Reduce rate limits or investigate expensive operations

3. **Rate limiting not working**
   - Symptom: No rate limit errors even under high load
   - Solution: Verify `PLUGIN_RATE_LIMIT_ENABLED=true` and check interceptor registration

### Debug Logging

Enable debug logging to troubleshoot rate limiting:

```python
import logging

# Enable debug logging for rate limiter
logging.getLogger("provide.foundation.utils.rate_limiting").setLevel(logging.DEBUG)
logging.getLogger("pyvider.rpcplugin.server").setLevel(logging.DEBUG)
```

## Related Topics

- [Server Configuration](../config/index.md) - General server configuration options
- [Health Checks](health-checks.md) - Monitor server health under load
- [Performance Tuning](../advanced/performance.md) - Optimize server performance
- [Error Handling](../client/error-handling.md) - Client-side error handling patterns