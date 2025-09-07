# Rate Limiting Example

A server with token bucket rate limiting for request throttling.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.factories import plugin_protocol, plugin_server
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter

class RateLimitedHandler:
    """Handler with built-in rate limiting."""
    
    def __init__(self):
        # 10 requests per second, burst of 20
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=20.0,
            refill_rate=10.0
        )
        print("🔌 Rate-limited handler initialized")
    
    async def process_request(self, data: str) -> str:
        """Rate-limited request processing."""
        if await self.rate_limiter.is_allowed():
            return f"Processed: {data}"
        else:
            raise Exception("Rate limit exceeded")

async def main():
    # Create handler and server
    handler = RateLimitedHandler()
    protocol = plugin_protocol(service_name="RateLimitedPlugin")
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        print("🚀 Starting rate-limited plugin server...")
        await server.serve()
    except KeyboardInterrupt:
        print("🛑 Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- `TokenBucketRateLimiter` implements token bucket algorithm
- `capacity` sets burst limit, `refill_rate` sets sustained rate
- `is_allowed()` returns `True` if request can proceed
- Rate limiting happens at the application level

## Related Examples

- [Basic Server](basic-server.md) - Simple server without rate limiting
- [Full Rate Limiting Guide](../guide/server/rate-limiting.md)