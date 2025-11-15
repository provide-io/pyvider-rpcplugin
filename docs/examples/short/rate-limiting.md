# Rate Limiting Example

**Complexity**: 🟢 Beginner | **Lines**: ~25 | **Source Code:** `examples/short/rate_limiting.py`

A server with automatic rate limiting using token bucket algorithm - protects your service from being overwhelmed by too many requests.

```python
#!/usr/bin/env python3
"""
Server with rate limiting (25 lines).

Demonstrates enabling request rate limiting.
"""
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server, configure
from provide.foundation import logger


async def main():
    """Run server with rate limiting."""
    # Enable rate limiting: 100 requests/sec, burst capacity 200
    configure(
        rate_limit_enabled=True,
        rate_limit_requests_per_second=100.0,
        rate_limit_burst_capacity=200
    )

    protocol = plugin_protocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with rate limiting: 100 req/s...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- **`configure(rate_limit_enabled=True)`** enables automatic server-side rate limiting
- **`rate_limit_requests_per_second`** sets sustained request rate (100 req/s in this example)
- **`rate_limit_burst_capacity`** allows temporary bursts above sustained rate (200 tokens)
- **Token bucket algorithm** - uses Foundation's `TokenBucketRateLimiter` under the hood
- **Automatic rejection** - requests exceeding limits get `RESOURCE_EXHAUSTED` gRPC status

## Related Examples

- [Basic Server](basic-server/) - Simple server without rate limiting
- [Full Rate Limiting Guide](../../guide/config/rate-limiting/)
## What's Next?

### Next Steps

1. **Tune Limits** - Adjust rates based on your service capacity
2. **Client Handling** - Implement exponential backoff for RESOURCE_EXHAUSTED errors
3. **Monitor Rates** - Track rejected requests in your observability system
4. **Per-Method Limits** - Implement custom rate limiting per RPC method

### Learning Path

- **Beginner:** Combine with [Health Checks](health-check/) for production readiness
- **Intermediate:** Learn [Advanced Rate Limiting](../../guide/server/rate-limiting/) patterns
