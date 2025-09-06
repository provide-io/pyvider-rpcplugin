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
print(f"Reset in: {info['reset_time']} seconds")
```

### `SlidingWindowRateLimiter`

Sliding window algorithm for precise rate limiting over time windows.

```python
from pyvider.ratelimit import SlidingWindowRateLimiter

class SlidingWindowRateLimiter(RateLimiter):
    """Sliding window rate limiter implementation."""
```

#### Constructor

```python
def __init__(
    self,
    limit: int,
    window_size: int,
    redis_client: Any | None = None
):
```

**Parameters:**
- `limit` (int): Maximum requests per window
- `window_size` (int): Time window size in seconds
- `redis_client` (Any | None): Redis client for distributed rate limiting

**Example:**
```python
# 1000 requests per 60-second sliding window
sliding_limiter = SlidingWindowRateLimiter(
    limit=1000,
    window_size=60
)
```

### `FixedWindowRateLimiter`

Fixed window algorithm for simple time-based rate limiting.

```python
from pyvider.ratelimit import FixedWindowRateLimiter

class FixedWindowRateLimiter(RateLimiter):
    """Fixed window rate limiter implementation."""
```

#### Constructor

```python
def __init__(
    self,
    limit: int,
    window_size: int,
    redis_client: Any | None = None
):
```

**Parameters:**
- `limit` (int): Maximum requests per window
- `window_size` (int): Fixed window size in seconds
- `redis_client` (Any | None): Redis client for distributed rate limiting

## Middleware Integration

### `RateLimitingInterceptor`

gRPC interceptor for automatic rate limiting.

```python
from pyvider.ratelimit import RateLimitingInterceptor
import grpc
from grpc.aio import ServicerContext, ServicerInterceptor

class RateLimitingInterceptor(ServicerInterceptor):
    """gRPC interceptor for rate limiting."""
```

#### Constructor

```python
def __init__(
    self,
    rate_limiter: RateLimiter,
    key_extractor: Callable[[Any], str] | None = None,
    per_method: bool = False,
    method_limits: dict[str, RateLimiter] | None = None
):
```

**Parameters:**
- `rate_limiter` (RateLimiter): Default rate limiter instance
- `key_extractor` (Callable | None): Function to extract rate limiting key from context
- `per_method` (bool): Enable per-method rate limiting
- `method_limits` (dict | None): Method-specific rate limiters

**Example:**
```python
# Default key extractor using client IP
def extract_client_ip(handler_call_details) -> str:
    context = handler_call_details.invocation_metadata
    peer = context.peer()  # Get client address
    return peer.split(':')[0] if peer else 'unknown'

# Create rate limiting interceptor
rate_limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)
interceptor = RateLimitingInterceptor(
    rate_limiter=rate_limiter,
    key_extractor=extract_client_ip,
    per_method=True
)

# Add to server
server.add_interceptor(interceptor)
```

#### Per-Method Rate Limiting

```python
# Different limits for different methods
method_limits = {
    '/user.UserService/GetUser': TokenBucketRateLimiter(capacity=1000, refill_rate=100),
    '/user.UserService/CreateUser': TokenBucketRateLimiter(capacity=10, refill_rate=1),
    '/user.UserService/DeleteUser': TokenBucketRateLimiter(capacity=5, refill_rate=0.1),
}

interceptor = RateLimitingInterceptor(
    rate_limiter=default_limiter,
    method_limits=method_limits,
    key_extractor=lambda details: extract_user_id(details)
)
```

### Custom Key Extractors

```python
def extract_user_id(handler_call_details) -> str:
    """Extract user ID from JWT token."""
    context = handler_call_details.invocation_metadata
    
    # Get authorization header
    auth_header = None
    for key, value in context.invocation_metadata():
        if key.lower() == 'authorization':
            auth_header = value
            break
    
    if auth_header and auth_header.startswith('Bearer '):
        try:
            import jwt
            token = auth_header[7:]
            payload = jwt.decode(token, verify=False)  # In production, verify the token
            return payload.get('user_id', 'anonymous')
        except Exception:
            pass
    
    return 'anonymous'

def extract_api_key(handler_call_details) -> str:
    """Extract API key from headers."""
    context = handler_call_details.invocation_metadata
    
    for key, value in context.invocation_metadata():
        if key.lower() == 'x-api-key':
            return f"api_key:{value}"
    
    return 'no_api_key'
```

## Distributed Rate Limiting

### Redis Backend

```python
import aioredis
from pyvider.ratelimit import RedisRateLimiter

class RedisRateLimiter(TokenBucketRateLimiter):
    """Redis-backed distributed rate limiter."""
    
    def __init__(self, redis_client: aioredis.Redis, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.redis = redis_client
    
    async def is_allowed(self, key: str, tokens: int = 1) -> bool:
        """Check rate limit using Redis Lua script for atomicity."""
        
        # Lua script for atomic token bucket operation
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local tokens_requested = tonumber(ARGV[2])
        local refill_rate = tonumber(ARGV[3])
        local refill_period = tonumber(ARGV[4])
        local current_time = tonumber(ARGV[5])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or current_time
        
        -- Calculate tokens to add
        local time_passed = math.max(0, current_time - last_refill)
        local tokens_to_add = math.floor(time_passed / refill_period * refill_rate)
        tokens = math.min(capacity, tokens + tokens_to_add)
        
        local allowed = 0
        if tokens >= tokens_requested then
            tokens = tokens - tokens_requested
            allowed = 1
        end
        
        -- Update bucket state
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
        redis.call('EXPIRE', key, 3600)  -- Expire after 1 hour of inactivity
        
        return {allowed, tokens}
        """
        
        result = await self.redis.eval(
            lua_script,
            1,  # Number of keys
            key,  # The rate limit key
            self.capacity,
            tokens,
            self.refill_rate,
            self.refill_period,
            time.time()
        )
        
        return bool(result[0])

# Usage
redis_client = aioredis.from_url("redis://localhost:6379")
distributed_limiter = RedisRateLimiter(
    redis_client=redis_client,
    capacity=1000,
    refill_rate=100
)
```

## Advanced Usage Examples

### Hierarchical Rate Limiting

```python
from pyvider.ratelimit import HierarchicalRateLimiter

class HierarchicalRateLimiter:
    """Multiple rate limiters in hierarchy (global -> user -> method)."""
    
    def __init__(self):
        self.global_limiter = TokenBucketRateLimiter(capacity=10000, refill_rate=1000)
        self.user_limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10)
        self.method_limiters = {
            'expensive_method': TokenBucketRateLimiter(capacity=5, refill_rate=0.5)
        }
    
    async def is_allowed(self, user_id: str, method: str) -> bool:
        """Check all rate limit levels."""
        
        # Global rate limit
        if not await self.global_limiter.is_allowed("global"):
            return False
        
        # Per-user rate limit
        if not await self.user_limiter.is_allowed(f"user:{user_id}"):
            return False
        
        # Per-method rate limit (if applicable)
        method_limiter = self.method_limiters.get(method)
        if method_limiter:
            if not await method_limiter.is_allowed(f"user:{user_id}:method:{method}"):
                return False
        
        return True
```

### Rate Limit Headers

```python
class RateLimitHeadersInterceptor(ServicerInterceptor):
    """Add rate limit information to response headers."""
    
    def __init__(self, rate_limiter: RateLimiter, key_extractor: Callable):
        self.rate_limiter = rate_limiter
        self.key_extractor = key_extractor
    
    async def intercept_service(self, continuation, handler_call_details):
        context = handler_call_details.invocation_metadata
        key = self.key_extractor(handler_call_details)
        
        # Check rate limit
        allowed = await self.rate_limiter.is_allowed(key)
        
        if not allowed:
            # Add rate limit headers before aborting
            limit_info = await self.rate_limiter.get_limit_info(key)
            
            context.set_trailing_metadata([
                ('x-ratelimit-limit', str(limit_info.get('capacity', 0))),
                ('x-ratelimit-remaining', str(limit_info.get('remaining', 0))),
                ('x-ratelimit-reset', str(int(time.time() + limit_info.get('reset_time', 0)))),
            ])
            
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
            return
        
        # Execute request
        response = await continuation(handler_call_details)
        
        # Add rate limit headers to successful responses
        limit_info = await self.rate_limiter.get_limit_info(key)
        context.set_trailing_metadata([
            ('x-ratelimit-limit', str(limit_info.get('capacity', 0))),
            ('x-ratelimit-remaining', str(limit_info.get('remaining', 0))),
            ('x-ratelimit-reset', str(int(time.time() + limit_info.get('reset_time', 0)))),
        ])
        
        return response
```

### Adaptive Rate Limiting

```python
class AdaptiveRateLimiter:
    """Rate limiter that adapts based on system load."""
    
    def __init__(self, base_limiter: RateLimiter):
        self.base_limiter = base_limiter
        self.load_threshold = 0.8  # Reduce limits when load > 80%
        self.current_load = 0.0
    
    async def is_allowed(self, key: str, tokens: int = 1) -> bool:
        """Check rate limit with load-based adjustment."""
        
        # Adjust tokens based on system load
        if self.current_load > self.load_threshold:
            # Increase token cost when system is under load
            load_multiplier = 1 + (self.current_load - self.load_threshold) * 5
            adjusted_tokens = int(tokens * load_multiplier)
        else:
            adjusted_tokens = tokens
        
        return await self.base_limiter.is_allowed(key, adjusted_tokens)
    
    async def update_system_load(self) -> None:
        """Update current system load metrics."""
        import psutil
        
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # Calculate combined load score (0.0 to 1.0)
        cpu_load = cpu_percent / 100.0
        memory_load = memory.percent / 100.0
        
        self.current_load = max(cpu_load, memory_load)
```

### Rate Limit Monitoring

```python
from prometheus_client import Counter, Histogram, Gauge

# Prometheus metrics
rate_limit_requests = Counter(
    'rate_limit_requests_total',
    'Total rate limit checks',
    ['key_type', 'method', 'result']
)

rate_limit_tokens = Gauge(
    'rate_limit_tokens_remaining',
    'Remaining tokens in rate limit bucket',
    ['key', 'limiter']
)

class MonitoredRateLimiter:
    """Rate limiter with Prometheus monitoring."""
    
    def __init__(self, base_limiter: RateLimiter, limiter_name: str):
        self.base_limiter = base_limiter
        self.limiter_name = limiter_name
    
    async def is_allowed(self, key: str, tokens: int = 1) -> bool:
        """Rate limit check with monitoring."""
        
        # Perform rate limit check
        allowed = await self.base_limiter.is_allowed(key, tokens)
        
        # Record metrics
        result = 'allowed' if allowed else 'denied'
        rate_limit_requests.labels(
            key_type=self._get_key_type(key),
            method='unknown',  # Could extract from context
            result=result
        ).inc()
        
        # Update remaining tokens gauge
        if allowed:
            limit_info = await self.base_limiter.get_limit_info(key)
            rate_limit_tokens.labels(
                key=key,
                limiter=self.limiter_name
            ).set(limit_info.get('remaining', 0))
        
        return allowed
    
    def _get_key_type(self, key: str) -> str:
        """Determine key type for metrics."""
        if key.startswith('user:'):
            return 'user'
        elif key.startswith('api_key:'):
            return 'api_key'
        elif '.' in key:  # IP address
            return 'ip'
        else:
            return 'other'
```

## Configuration Examples

### YAML Configuration

```yaml
rate_limiting:
  enabled: true
  
  # Default rate limiter
  default:
    type: token_bucket
    capacity: 1000
    refill_rate: 100
    refill_period: 1.0
  
  # Per-method limits
  methods:
    "/user.UserService/CreateUser":
      type: token_bucket
      capacity: 10
      refill_rate: 1
    
    "/user.UserService/ListUsers":
      type: sliding_window
      limit: 100
      window_size: 60
  
  # Key extraction
  key_extractor: user_id  # user_id, ip_address, api_key
  
  # Redis configuration for distributed limiting
  redis:
    url: "redis://localhost:6379"
    db: 0
    key_prefix: "ratelimit:"
```

### Loading Configuration

```python
from pyvider.config import load_rate_limit_config
from pyvider.ratelimit import create_rate_limiter

def setup_rate_limiting(config_path: str):
    """Setup rate limiting from configuration."""
    
    config = load_rate_limit_config(config_path)
    
    if not config.get('enabled', False):
        return None
    
    # Create default rate limiter
    default_config = config['default']
    default_limiter = create_rate_limiter(default_config)
    
    # Create method-specific limiters
    method_limits = {}
    for method, method_config in config.get('methods', {}).items():
        method_limits[method] = create_rate_limiter(method_config)
    
    # Create key extractor
    key_extractor = create_key_extractor(config.get('key_extractor', 'ip_address'))
    
    return RateLimitingInterceptor(
        rate_limiter=default_limiter,
        method_limits=method_limits,
        key_extractor=key_extractor
    )
```

## Best Practices

1. **Choose the Right Algorithm**
   - Token bucket: For burst tolerance
   - Sliding window: For precise rate limiting
   - Fixed window: For simple time-based limits

2. **Key Design**
   - Use hierarchical keys: `user:123:method:create`
   - Include relevant context: IP, user ID, API key
   - Consider key cardinality for memory usage

3. **Error Handling**
   - Graceful degradation when rate limiter fails
   - Appropriate HTTP status codes (429 for rate limiting)
   - Meaningful error messages with retry information

4. **Monitoring**
   - Track rate limit hit rates
   - Monitor token bucket fill levels
   - Alert on unusual patterns

5. **Testing**
   - Load test rate limiting under various scenarios
   - Test distributed consistency
   - Verify burst handling behavior

The Rate Limiting API provides comprehensive traffic control capabilities that scale from single-instance deployments to distributed microservices architectures.