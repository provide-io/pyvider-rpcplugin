# Rate Limiting

Pyvider RPC Plugin integrates with Foundation's rate limiting system, providing server-side protection using a token bucket algorithm to protect against abuse, ensure fair resource usage, and maintain service quality under high load conditions.

## Overview

Rate limiting operates at the server level using Foundation's `TokenBucketRateLimiter` and applies to all incoming requests regardless of the client or request type. It uses a token bucket algorithm that provides:

- **Sustained rate control**: Limits average requests per second over time
- **Burst handling**: Allows temporary spikes in traffic up to a configured limit
- **Fair resource allocation**: Prevents any single client from overwhelming the server
- **Graceful degradation**: Returns standard gRPC errors when limits are exceeded

### Foundation Integration

The rate limiting is implemented using Foundation's rate limiting utilities:

```python
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from pyvider.rpcplugin.config import rpcplugin_config

# Rate limiter is automatically configured from environment
if rpcplugin_config.plugin_rate_limit_enabled:
    rate_limiter = TokenBucketRateLimiter(
        requests_per_second=rpcplugin_config.plugin_rate_limit_requests_per_second,
        burst_capacity=rpcplugin_config.plugin_rate_limit_burst_capacity
    )
```

## Configuration

### Basic Rate Limiting

Enable rate limiting with default settings:

```bash
# Enable rate limiting with defaults
export PLUGIN_RATE_LIMIT_ENABLED=true
# Default: 100 requests/second, 200 burst capacity
```

### Custom Rate Configuration

Configure specific rate and burst limits:

```bash
# Custom rate limiting configuration
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=50.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=100.0
```

### Configuration Parameters

| Parameter | Environment Variable | Type | Default | Description |
|-----------|---------------------|------|---------|-------------|
| **Enabled** | `PLUGIN_RATE_LIMIT_ENABLED` | `bool` | `false` | Enable/disable rate limiting |
| **Rate** | `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` | `float` | `100.0` | Average requests per second allowed |
| **Burst** | `PLUGIN_RATE_LIMIT_BURST_CAPACITY` | `float` | `200.0` | Maximum requests in burst (token bucket size) |

## Token Bucket Algorithm

The rate limiter uses a token bucket algorithm with the following behavior:

### How It Works

1. **Token Generation**: Tokens are added to the bucket at the configured rate (requests per second)
2. **Request Processing**: Each request consumes one token from the bucket
3. **Burst Handling**: Bucket can hold up to the burst capacity in tokens
4. **Rate Limiting**: When bucket is empty, requests are rejected with `RESOURCE_EXHAUSTED` error

### Example Scenarios

#### Scenario 1: Steady Traffic
```bash
# Configuration: 10 RPS, 20 burst capacity
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=10.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=20.0
```

- **Sustained load**: 10 requests/second are consistently allowed
- **Idle periods**: Bucket fills to 20 tokens during quiet periods  
- **Steady state**: Bucket maintains ~10 tokens during consistent load

#### Scenario 2: Bursty Traffic
```bash
# Configuration: 50 RPS, 200 burst capacity  
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=50.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=200.0
```

- **Initial burst**: 200 requests can be processed immediately
- **Recovery**: Takes 4 seconds (200/50) to refill bucket after burst
- **Ongoing**: 50 requests/second sustained after initial burst

#### Scenario 3: High Throughput
```bash
# Configuration: 1000 RPS, 2000 burst capacity
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000.0
```

- **High capacity**: Handles 1000 requests/second consistently
- **Large bursts**: Can accommodate 2000 request spikes
- **Quick recovery**: 2 second recovery time after burst

## Configuration Patterns

### Development Environment

For development, use lenient rate limiting to avoid interrupting testing:

```bash
# Development rate limiting - very permissive
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=5000.0
```

### Production Environment

#### Web API Backend
```bash
# Typical web API rate limiting
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=300.0
```

#### High-Throughput Service
```bash
# High-throughput microservice
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000.0
```

#### Administrative Interface
```bash
# Conservative rate limiting for admin operations
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=10.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=50.0
```

#### Public API
```bash
# Public-facing API with abuse protection
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=20.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=100.0
```

## Error Handling

When rate limits are exceeded, the server returns a standard gRPC `RESOURCE_EXHAUSTED` error. Clients should handle this gracefully with appropriate retry logic.

### Server-Side Error Response

```python
# When rate limit is exceeded, server automatically returns:
# grpc.StatusCode.RESOURCE_EXHAUSTED: "Rate limit exceeded"
```

### Client-Side Error Handling

```python
import grpc
import asyncio
from pyvider.rpcplugin import plugin_client

async def handle_rate_limited_request():
    async with plugin_client() as client:
        for attempt in range(3):
            try:
                response = await client.my_service.process_request(data="example")
                return response
            except grpc.aio.AioRpcError as e:
                if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
                    # Rate limit exceeded, implement backoff
                    backoff_time = min(2 ** attempt, 10)  # Exponential backoff, max 10s
                    logger.warning(f"Rate limited, retrying in {backoff_time}s")
                    await asyncio.sleep(backoff_time)
                    continue
                else:
                    # Other error, don't retry
                    raise
        
        # All retries exhausted
        raise Exception("Request failed after rate limit retries")
```

### Graceful Degradation

Implement circuit breaker pattern for persistent rate limiting:

```python
import time
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Rate limited, rejecting requests
    HALF_OPEN = "half_open" # Testing if rate limiting is resolved

class RateLimitCircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = CircuitState.CLOSED
    
    async def call_with_circuit_breaker(self, client, request_func, *args, **kwargs):
        if self.state == CircuitState.OPEN:
            # Check if we should transition to half-open
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker transitioning to half-open")
            else:
                raise Exception("Circuit breaker is open due to rate limiting")
        
        try:
            result = await request_func(*args, **kwargs)
            
            # Success - reset circuit breaker
            if self.state == CircuitState.HALF_OPEN:
                logger.info("Circuit breaker closing - rate limiting resolved")
                self.state = CircuitState.CLOSED
                self.failure_count = 0
            
            return result
            
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.failure_count >= self.failure_threshold:
                    logger.warning(f"Circuit breaker opening due to {self.failure_count} rate limit failures")
                    self.state = CircuitState.OPEN
                
                raise
            else:
                # Non-rate-limiting error, don't affect circuit breaker
                raise
```

## Monitoring and Observability

### Rate Limiting Metrics

Monitor these key metrics to understand rate limiting behavior:

```python
from prometheus_client import Counter, Histogram, Gauge

# Define rate limiting metrics
RATE_LIMIT_REQUESTS = Counter('plugin_rate_limit_requests_total', 'Total requests processed by rate limiter', ['result'])
RATE_LIMIT_TOKENS = Gauge('plugin_rate_limit_tokens_available', 'Available tokens in rate limit bucket')
RATE_LIMIT_LATENCY = Histogram('plugin_rate_limit_check_duration_seconds', 'Time spent checking rate limits')

# Example implementation (conceptual - actual implementation is internal)
async def rate_limited_handler(request, context):
    with RATE_LIMIT_LATENCY.time():
        if rate_limiter.allow_request():
            RATE_LIMIT_REQUESTS.labels(result='allowed').inc()
            RATE_LIMIT_TOKENS.set(rate_limiter.available_tokens())
            return await process_request(request, context)
        else:
            RATE_LIMIT_REQUESTS.labels(result='rejected').inc()
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details("Rate limit exceeded")
            return empty_response()
```

### Logging Rate Limiting Events

```python
from provide.foundation import logger

# Rate limiting is automatically logged by the framework
# Example log messages you'll see:

# When rate limiting is enabled:
logger.info("🚦 Rate limiting enabled", extra={
    "requests_per_second": 100.0,
    "burst_capacity": 200.0
})

# When requests are rate limited:
logger.warning("🚦 Request rate limited", extra={
    "client_ip": "192.168.1.100",
    "available_tokens": 0,
    "refill_rate": 100.0
})

# When burst capacity is reached:
logger.info("🚦 Burst capacity reached", extra={
    "burst_size": 200.0,
    "recovery_time_seconds": 2.0
})
```

### Health Check Integration

Rate limiting status can be included in health checks:

```python
from pyvider.rpcplugin import RPCPluginServer

class CustomHealthServicer:
    async def check_health(self) -> dict:
        health_status = {
            "status": "SERVING",
            "rate_limiting": {
                "enabled": True,
                "current_tokens": rate_limiter.available_tokens(),
                "requests_per_second": 100.0,
                "burst_capacity": 200.0
            }
        }
        return health_status
```

## Performance Considerations

### Rate Limiter Overhead

The token bucket implementation is highly optimized:

- **O(1) complexity**: Constant time for rate limit checks
- **Minimal memory**: Small fixed memory footprint per server
- **Lock-free**: Uses atomic operations for thread safety
- **Low latency**: Sub-microsecond overhead per request

### Benchmarks

Typical performance characteristics:

| Configuration | Overhead per Request | Memory Usage |
|---------------|---------------------|--------------|
| 100 RPS, 200 burst | < 0.1μs | < 1KB |
| 1000 RPS, 2000 burst | < 0.1μs | < 1KB |
| 10000 RPS, 20000 burst | < 0.2μs | < 1KB |

### Tuning for Performance

For high-throughput services:

```bash
# High-performance configuration
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=5000.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=10000.0

# Consider disabling rate limiting for internal services
export PLUGIN_RATE_LIMIT_ENABLED=false
```

## Advanced Patterns

### Per-Client Rate Limiting

While the built-in rate limiter is global, you can implement per-client rate limiting in your service handlers:

```python
import asyncio
from collections import defaultdict
from time import time

class PerClientRateLimiter:
    def __init__(self, requests_per_second: float, burst_capacity: float):
        self.rate = requests_per_second
        self.capacity = burst_capacity
        self.buckets = defaultdict(lambda: {
            'tokens': burst_capacity,
            'last_update': time()
        })
    
    def allow_request(self, client_id: str) -> bool:
        now = time()
        bucket = self.buckets[client_id]
        
        # Add tokens based on elapsed time
        elapsed = now - bucket['last_update']
        tokens_to_add = elapsed * self.rate
        bucket['tokens'] = min(self.capacity, bucket['tokens'] + tokens_to_add)
        bucket['last_update'] = now
        
        # Check if request is allowed
        if bucket['tokens'] >= 1.0:
            bucket['tokens'] -= 1.0
            return True
        return False

# Usage in your service
per_client_limiter = PerClientRateLimiter(10.0, 50.0)

async def my_service_method(self, request, context):
    client_id = context.peer()  # or extract from metadata
    
    if not per_client_limiter.allow_request(client_id):
        context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
        context.set_details(f"Rate limit exceeded for client {client_id}")
        return ErrorResponse()
    
    return await process_request(request)
```

### Dynamic Rate Limiting

Adjust rate limits based on system load:

```python
import psutil
from pyvider.rpcplugin import configure

class AdaptiveRateLimiter:
    def __init__(self):
        self.base_rate = 100.0
        self.max_rate = 500.0
        self.min_rate = 10.0
    
    async def update_rate_limits(self):
        while True:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            
            # Calculate rate based on system load
            if cpu_percent > 80 or memory_percent > 80:
                # High load - reduce rate
                new_rate = max(self.min_rate, self.base_rate * 0.5)
            elif cpu_percent < 30 and memory_percent < 50:
                # Low load - increase rate
                new_rate = min(self.max_rate, self.base_rate * 1.5)
            else:
                # Normal load - use base rate
                new_rate = self.base_rate
            
            # Update configuration
            configure(
                rate_limit_requests_per_second=new_rate,
                rate_limit_burst_capacity=new_rate * 2
            )
            
            logger.info(f"📊 Adjusted rate limit to {new_rate} RPS based on system load")
            await asyncio.sleep(30)  # Update every 30 seconds

# Start adaptive rate limiting
adaptive_limiter = AdaptiveRateLimiter()
asyncio.create_task(adaptive_limiter.update_rate_limits())
```

## Troubleshooting

### Common Issues

#### 1. Too Aggressive Rate Limiting
**Symptoms**: Legitimate requests being rejected, high error rates
**Solution**: Increase burst capacity or requests per second

```bash
# Before (too restrictive)
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=5.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=10.0

# After (more permissive)
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=20.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=100.0
```

#### 2. Rate Limiting Not Working
**Symptoms**: No rate limiting observed, server overwhelmed
**Solution**: Verify rate limiting is enabled and configured correctly

```bash
# Check configuration
export PLUGIN_RATE_LIMIT_ENABLED=true  # Must be explicit
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
```

#### 3. Client Retry Storms
**Symptoms**: Rate limiting triggers cascade of retries, making problem worse
**Solution**: Implement exponential backoff in client retry logic

```python
# Good: Exponential backoff
async def retry_with_backoff(func, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            return await func()
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and attempt < max_attempts - 1:
                backoff = min(2 ** attempt, 10)  # Cap at 10 seconds
                await asyncio.sleep(backoff)
                continue
            raise
```

### Debugging Rate Limiting

Enable debug logging to see rate limiting decisions:

```bash
export PLUGIN_LOG_LEVEL=DEBUG
```

Debug logs will show:
- Token bucket state changes
- Request allow/reject decisions  
- Rate limiting configuration updates
- Client connection patterns

## Best Practices

1. **Start Conservative**: Begin with lower limits and increase based on monitoring
2. **Monitor Metrics**: Track rate limiting events and adjust based on patterns  
3. **Client-Side Handling**: Always implement proper error handling for rate limits
4. **Burst Capacity**: Set burst capacity 2-5x higher than sustained rate
5. **Environment Specific**: Use different limits for dev/staging/production
6. **Document Limits**: Make rate limits visible to API consumers
7. **Graceful Degradation**: Implement circuit breakers for persistent rate limiting
8. **Load Testing**: Test rate limiting under realistic load conditions

## Next Steps

- **[Production Setup](production.md)** - Complete production configuration guide
- **[Logging Configuration](logging.md)** - Observability and monitoring setup
- **[Environment Variables](environment.md)** - Complete configuration reference
- **[API Reference](../../reference/index.md)** - Auto-generated API documentation