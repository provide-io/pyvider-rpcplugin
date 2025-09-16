# Rate Limiting API

Foundation's `TokenBucketRateLimiter` provides thread-safe, async rate limiting for plugin servers.

## Overview

The rate limiter uses a token bucket algorithm where:
- **Capacity**: Maximum burst size (tokens in bucket)
- **Refill Rate**: Tokens added per second
- **Thread-Safe**: Uses `asyncio.Lock` for concurrent access

```python
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from provide.foundation import logger

# Create rate limiter: 10 requests per second, burst up to 20
rate_limiter = TokenBucketRateLimiter(
    capacity=20.0,      # Maximum burst size
    refill_rate=10.0    # Tokens per second
)

# Check if request is allowed
if await rate_limiter.is_allowed():
    await process_request()
else:
    logger.warning("Rate limit exceeded")
```

## Class Reference

### `TokenBucketRateLimiter`

```python
from typing import final

@final
class TokenBucketRateLimiter:
    def __init__(self, capacity: float, refill_rate: float):
        """Initialize token bucket rate limiter.
        
        Args:
            capacity: Maximum tokens in bucket (burst size)
            refill_rate: Tokens added per second
            
        Raises:
            ValueError: If capacity or refill_rate <= 0
        """
```

### Configuration Examples

```python
# API endpoint rate limiting
standard_api = TokenBucketRateLimiter(capacity=100.0, refill_rate=50.0)

# Background job rate limiting  
batch_jobs = TokenBucketRateLimiter(capacity=10.0, refill_rate=1.0)

# High throughput with burst
high_throughput = TokenBucketRateLimiter(capacity=500.0, refill_rate=100.0)
```

### Methods

#### `is_allowed`

```python
async def is_allowed(self) -> bool:
```

Check if request is allowed and consume one token if available.

**Returns:** `bool` - True if allowed (token consumed), False if rate limited

**Example:**
```python
if await rate_limiter.is_allowed():
    logger.debug("Request approved")
    await handle_request()
else:
    logger.warning("Rate limit exceeded")
    raise RateLimitExceeded("Too many requests")
```

#### `get_current_tokens`

```python
async def get_current_tokens(self) -> float:
```

Get current number of tokens in bucket (primarily for testing/monitoring).

**Returns:** `float` - Current tokens available

## Integration Examples

### gRPC Service Integration

```python
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from provide.foundation import logger
import grpc

class RateLimitedServicer:
    """gRPC servicer with Foundation rate limiting."""
    
    def __init__(self):
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=100.0,
            refill_rate=50.0
        )
    
    async def Process(self, request, context):
        if not await self.rate_limiter.is_allowed():
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details("Rate limit exceeded")
            
            tokens = await self.rate_limiter.get_current_tokens()
            logger.warning("Rate limit exceeded", extra={
                "available_tokens": tokens,
                "client": context.peer()
            })
            return None
        
        return await self._process_request(request)
```

### Plugin Server Integration

```python
from pyvider.rpcplugin import plugin_server
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

class RateLimitedHandler:
    """Plugin handler with rate limiting."""
    
    def __init__(self, rps: float = 10.0, burst: float = 20.0):
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=burst,
            refill_rate=rps
        )
        logger.info(f"Rate limiting enabled: {rps} RPS, {burst} burst")
    
    async def handle_request(self, request):
        if not await self.rate_limiter.is_allowed():
            raise Exception("Rate limit exceeded")
        
        return await self.process(request)

# Create server with rate-limited handler
server = plugin_server(
    protocol=plugin_protocol(),
    handler=RateLimitedHandler(rps=100.0, burst=200.0)
)
```

### Per-Client Rate Limiting

```python
from collections import defaultdict
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

class PerClientRateLimiter:
    """Manage per-client rate limits."""
    
    def __init__(self, default_rps: float = 10.0, default_burst: float = 20.0):
        self.default_rps = default_rps
        self.default_burst = default_burst
        self.limiters: dict[str, TokenBucketRateLimiter] = {}
    
    def get_limiter(self, client_id: str) -> TokenBucketRateLimiter:
        if client_id not in self.limiters:
            self.limiters[client_id] = TokenBucketRateLimiter(
                capacity=self.default_burst,
                refill_rate=self.default_rps
            )
        return self.limiters[client_id]
    
    async def check_rate_limit(self, client_id: str) -> bool:
        limiter = self.get_limiter(client_id)
        return await limiter.is_allowed()

# Usage in handler
class MultiClientHandler:
    def __init__(self):
        self.rate_limiter = PerClientRateLimiter(
            default_rps=50.0,
            default_burst=100.0
        )
    
    async def handle_request(self, request, context):
        client_id = context.peer() or "unknown"
        
        if not await self.rate_limiter.check_rate_limit(client_id):
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            raise Exception("Rate limit exceeded")
        
        return await self.process_request(request)
```

### Middleware Pattern

```python
from grpc.aio import ServerInterceptor

class RateLimitingInterceptor(ServerInterceptor):
    """gRPC interceptor for automatic rate limiting."""
    
    def __init__(self, requests_per_second: float, burst_capacity: float):
        self.limiter = TokenBucketRateLimiter(
            capacity=burst_capacity,
            refill_rate=requests_per_second
        )
    
    async def intercept_service(self, continuation, handler_call_details):
        if not await self.limiter.is_allowed():
            context = handler_call_details.invocation_metadata
            context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                "Rate limit exceeded"
            )
        
        return await continuation(handler_call_details)

# Apply to server
from grpc.aio import server

grpc_server = server(interceptors=[
    RateLimitingInterceptor(
        requests_per_second=100.0,
        burst_capacity=200.0
    )
])
```

## Best Practices

### 1. Choose Appropriate Limits

```python
# API endpoints (user-facing)
user_api = TokenBucketRateLimiter(capacity=50.0, refill_rate=10.0)

# Internal services (service-to-service)
internal = TokenBucketRateLimiter(capacity=1000.0, refill_rate=500.0)

# Admin operations (privileged)
admin = TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0)

# Batch operations (analytics/reports)
batch = TokenBucketRateLimiter(capacity=10.0, refill_rate=0.1)
```

### 2. Error Handling

```python
async def robust_rate_limiting(request, limiter):
    """Robust rate limiting with proper error handling."""
    try:
        if not await limiter.is_allowed():
            logger.warning("Rate limit exceeded")
            return {"error": "Rate limit exceeded", "retry_after": 1}
        
        return await process_request(request)
        
    except Exception as e:
        logger.error(f"Rate limiter error: {e}")
        # Fail open: allow request if limiter fails
        return await process_request(request)
```

### 3. Monitoring

```python
class MonitoredRateLimiter:
    """Rate limiter with metrics collection."""
    
    def __init__(self, capacity: float, refill_rate: float):
        self.limiter = TokenBucketRateLimiter(capacity, refill_rate)
        self.allowed_count = 0
        self.denied_count = 0
    
    async def check_and_track(self) -> bool:
        allowed = await self.limiter.is_allowed()
        
        if allowed:
            self.allowed_count += 1
        else:
            self.denied_count += 1
        
        # Log metrics periodically
        if (self.allowed_count + self.denied_count) % 100 == 0:
            denial_rate = self.denied_count / (self.allowed_count + self.denied_count)
            logger.info("Rate limiter stats", extra={
                "allowed": self.allowed_count,
                "denied": self.denied_count,
                "denial_rate": denial_rate
            })
        
        return allowed
```

## Testing

```python
import pytest
import asyncio

class TestTokenBucketRateLimiter:
    @pytest.mark.asyncio
    async def test_basic_functionality(self):
        limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=1.0)
        
        # Should allow initial requests
        assert await limiter.is_allowed() == True
        assert await limiter.is_allowed() == True
        
        # Should deny when empty
        assert await limiter.is_allowed() == False
    
    @pytest.mark.asyncio
    async def test_refill_behavior(self):
        limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=1.0)
        
        assert await limiter.is_allowed() == True
        assert await limiter.is_allowed() == False
        
        # Wait for refill
        await asyncio.sleep(1.1)
        assert await limiter.is_allowed() == True
    
    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=5.0)
        
        async def worker():
            results = []
            for _ in range(20):
                results.append(await limiter.is_allowed())
            return results
        
        # Run concurrent workers
        tasks = [worker() for _ in range(5)]
        all_results = await asyncio.gather(*tasks)
        
        # Verify rate limiting
        total_allowed = sum(sum(results) for results in all_results)
        assert total_allowed <= 10  # Should not exceed capacity
```

## Configuration Reference

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `capacity` | Maximum burst size (tokens) | Required | `100.0` |
| `refill_rate` | Tokens added per second | Required | `50.0` |

### Common Rate Limit Patterns

| Use Case | Capacity | Refill Rate | Description |
|----------|----------|-------------|-------------|
| Standard API | 100 | 50 | 50 RPS, 2-second burst |
| High Traffic | 500 | 100 | 100 RPS, 5-second burst |
| Batch Jobs | 10 | 1 | 1 RPS, 10-request burst |
| Admin API | 5 | 1 | 1 RPS, 5-request burst |
| Analytics | 10 | 0.1 | 1 per 10s, 10-request burst |

## See Also

- [Foundation Rate Limiting Documentation](https://github.com/provide-io/provide-foundation)
- [Server Configuration Guide](../../guide/server/index.md)
- [Middleware Patterns](../../guide/advanced/middleware.md)
- [Performance Tuning](../../guide/advanced/performance.md)