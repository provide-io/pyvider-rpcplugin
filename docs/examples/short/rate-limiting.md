# Rate Limiting Example

A server with token bucket rate limiting for request throttling.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.factories import plugin_protocol, plugin_server
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from provide.foundation import logger

class RateLimitedHandler:
    """Handler with built-in rate limiting."""
    
    def __init__(self):
        # 10 requests per second, burst of 20
        self.rate_limiter = TokenBucketRateLimiter(
            tokens_per_second=10.0,
            bucket_size=20
        )
        logger.info("Rate-limited handler initialized", extra={
            "rps_limit": 10.0,
            "burst_capacity": 20
        })
    
    async def process_request(self, data: str) -> str:
        """Rate-limited request processing with Foundation patterns."""
        if await self.rate_limiter.acquire():
            logger.debug("Request approved by rate limiter", extra={"data_preview": data[:50]})
            return f"Processed: {data}"
        else:
            logger.warning("Rate limit exceeded", extra={
                "available_tokens": self.rate_limiter.available_tokens()
            })
            raise Exception("Rate limit exceeded")

async def main():
    # Create handler and server
    handler = RateLimitedHandler()
    protocol = plugin_protocol(service_name="RateLimitedPlugin")
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        logger.info("Starting rate-limited plugin server...")
        await server.serve()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- Foundation's `TokenBucketRateLimiter` implements async token bucket algorithm
- `bucket_size` sets burst limit, `tokens_per_second` sets sustained rate  
- `acquire()` returns `True` if request can proceed (Foundation method)
- Structured logging provides visibility into rate limiting decisions
- Rate limiting integrates with Foundation's observability system

## Related Examples

- [Basic Server](basic-server.md) - Simple server without rate limiting
- [Full Rate Limiting Guide](../../guide/config/rate-limiting.md)