# Rate Limiting API

The Rate Limiting API provides basic token bucket rate limiting for traffic control.

## Overview

The rate limiting system provides:

- **Token Bucket Algorithm** - Allows burst traffic up to capacity with steady refill rate
- **Async/Await Support** - Thread-safe implementation using asyncio.Lock
- **Simple Interface** - Easy to integrate into RPC service handlers

## Class Reference

### `TokenBucketRateLimiter`

Token bucket algorithm implementation for rate limiting with burst capability.

```python
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter
```

#### Constructor

```python
def __init__(self, capacity: float, refill_rate: float) -> None:
```

**Parameters:**
- `capacity` (float): Maximum number of tokens the bucket can hold (burst capacity)
- `refill_rate` (float): Rate at which tokens are refilled per second

**Example:**
```python
# Rate limiter: 10 requests per second, burst of 20
rate_limiter = TokenBucketRateLimiter(
    capacity=20.0,
    refill_rate=10.0
)
```

#### Methods

##### `is_allowed`

```python
async def is_allowed(self) -> bool:
```

Check if a request is allowed based on available tokens.

**Returns:**
- `bool`: True if request is allowed, False if rate limited

**Example:**
```python
# Check if request is allowed
if await rate_limiter.is_allowed():
    # Process request
    await handle_request()
else:
    # Rate limited
    raise RateLimitExceeded("Too many requests")
```

##### `get_current_tokens`

```python
async def get_current_tokens(self) -> float:
```

Get the current number of tokens in the bucket.

**Returns:**
- `float`: Current number of tokens available

**Example:**
```python
tokens = await rate_limiter.get_current_tokens()
print(f"Available tokens: {tokens}")
```

## Usage Example

```python
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter
import asyncio

async def example_usage():
    # Create rate limiter: 5 requests per second, burst of 10
    limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=5.0)
    
    # Check if requests are allowed
    for i in range(15):
        if await limiter.is_allowed():
            print(f"Request {i+1}: ALLOWED")
        else:
            print(f"Request {i+1}: RATE LIMITED")
        
        # Small delay between requests
        await asyncio.sleep(0.1)
    
    # Check remaining tokens
    tokens = await limiter.get_current_tokens()
    print(f"Remaining tokens: {tokens:.2f}")

# Run example
asyncio.run(example_usage())
```

The `TokenBucketRateLimiter` provides basic but effective rate limiting suitable for controlling request rates in RPC services.