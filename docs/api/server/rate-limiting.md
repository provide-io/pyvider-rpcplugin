# Rate Limiting API

The Rate Limiting API provides token bucket rate limiting for traffic control and abuse prevention in RPC services, enabling smooth request flow management with burst tolerance.

## Overview

The rate limiting system provides essential traffic control capabilities:

- **Token Bucket Algorithm** - Allows burst traffic up to capacity with steady refill rate
- **Async/Await Support** - Thread-safe implementation using asyncio.Lock for concurrent access
- **Simple Integration** - Easy to integrate into RPC service handlers and middleware  
- **Monitoring Support** - Built-in token level monitoring for debugging and metrics
- **Time-based Refill** - Automatic token replenishment based on elapsed time

## Core Components

### `TokenBucketRateLimiter`

Token bucket algorithm implementation for rate limiting with burst capability.

```python
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter
import asyncio
import time
from typing import final

@final
class TokenBucketRateLimiter:
    """Token Bucket rate limiter for asyncio applications."""
```

#### Constructor

```python
def __init__(self, capacity: float, refill_rate: float) -> None:
```

**Parameters:**
- `capacity` (float): Maximum number of tokens the bucket can hold (burst capacity)
- `refill_rate` (float): Rate at which tokens are refilled per second

**Raises:**
- `ValueError`: If capacity or refill_rate is not positive

**Example:**
```python
# Rate limiter: 10 requests per second, burst of 20
rate_limiter = TokenBucketRateLimiter(
    capacity=20.0,
    refill_rate=10.0
)

# Strict rate limiting: 1 request per second, no burst
strict_limiter = TokenBucketRateLimiter(
    capacity=1.0, 
    refill_rate=1.0
)

# High throughput with burst: 100 RPS, burst up to 500
high_throughput = TokenBucketRateLimiter(
    capacity=500.0,
    refill_rate=100.0
)
```

### Methods

#### `is_allowed`

```python
async def is_allowed(self) -> bool:
```

Check if a request is allowed and consume one token if available.

**Returns:**
- `bool`: True if request is allowed (token consumed), False if rate limited

**Behavior:**
- Thread-safe: Uses asyncio.Lock for concurrent access
- Automatic refill: Updates token count based on elapsed time
- Token consumption: Consumes exactly one token per call if available
- Logging: Provides debug/warning logs for monitoring

**Example:**
```python
# Basic usage
if await rate_limiter.is_allowed():
    # Process request - token was consumed
    await handle_request()
else:
    # Rate limited - no token available
    raise RateLimitExceeded("Too many requests")

# With error handling
try:
    allowed = await rate_limiter.is_allowed()
    if not allowed:
        return {"error": "Rate limit exceeded", "retry_after": 1}
    
    return await process_request()
    
except Exception as e:
    logger.error(f"Rate limiter error: {e}")
    # Fail open - allow request on limiter error
    return await process_request()
```

#### `get_current_tokens`

```python
async def get_current_tokens(self) -> float:
```

Get the current number of tokens in the bucket.

**Returns:**
- `float`: Current number of tokens available (may be fractional)

**Note:** 
- This method does NOT perform token refill before returning the count
- For most up-to-date count including refill, call `is_allowed()` first
- Primarily useful for testing and monitoring

**Example:**
```python
# Check token levels
tokens = await rate_limiter.get_current_tokens()
print(f"Available tokens: {tokens:.2f}")

# Monitor token levels over time
for i in range(10):
    tokens = await rate_limiter.get_current_tokens()
    print(f"Time {i}s: {tokens:.2f} tokens")
    await asyncio.sleep(1)
```

## Integration Examples

### gRPC Service Integration

```python
import grpc
from grpc import aio
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter

class RateLimitedServicer:
    """Example gRPC servicer with rate limiting."""
    
    def __init__(self):
        # Create rate limiter: 50 RPS with burst of 100
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=100.0,
            refill_rate=50.0
        )
    
    async def SomeMethod(self, request, context):
        """Rate-limited RPC method."""
        
        # Check rate limit
        if not await self.rate_limiter.is_allowed():
            # Set error details
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details("Rate limit exceeded. Try again later.")
            return None
        
        # Process the request
        return await self._process_request(request)
    
    async def _process_request(self, request):
        """Process the actual request."""
        # Your business logic here
        pass

# Usage in server
async def serve():
    server = aio.server()
    servicer = RateLimitedServicer()
    
    # Add servicer to server
    # add_SomeServiceServicer_to_server(servicer, server)
    
    listen_addr = "[::]:50051"
    server.add_insecure_port(listen_addr)
    
    await server.start()
    await server.wait_for_termination()
```

### Per-Client Rate Limiting

```python
import hashlib
from collections import defaultdict
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter

class PerClientRateLimiter:
    """Rate limiter that tracks separate limits per client."""
    
    def __init__(self, capacity: float, refill_rate: float, cleanup_interval: int = 3600):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.cleanup_interval = cleanup_interval
        self.limiters: dict[str, TokenBucketRateLimiter] = {}
        self.last_access: dict[str, float] = {}
    
    def _get_client_key(self, request, context) -> str:
        """Extract client identifier from request context."""
        # Option 1: Use peer address
        peer = context.peer()
        if peer:
            return peer
        
        # Option 2: Use client certificate (if available)
        auth_context = context.auth_context()
        if auth_context:
            peer_identity = auth_context.get('x509_subject_alternative_name')
            if peer_identity:
                return str(peer_identity)
        
        # Option 3: Use request metadata
        metadata = dict(context.invocation_metadata())
        client_id = metadata.get('client-id')
        if client_id:
            return client_id
        
        # Fallback: hash of peer info
        peer_info = f"{peer}_{context.time_remaining()}"
        return hashlib.md5(peer_info.encode()).hexdigest()
    
    def _get_limiter(self, client_key: str) -> TokenBucketRateLimiter:
        """Get or create rate limiter for client."""
        import time
        
        if client_key not in self.limiters:
            self.limiters[client_key] = TokenBucketRateLimiter(
                capacity=self.capacity,
                refill_rate=self.refill_rate
            )
        
        self.last_access[client_key] = time.time()
        return self.limiters[client_key]
    
    async def is_allowed(self, request, context) -> bool:
        """Check if request from client is allowed."""
        client_key = self._get_client_key(request, context)
        limiter = self._get_limiter(client_key)
        return await limiter.is_allowed()
    
    def cleanup_stale_limiters(self):
        """Remove rate limiters for inactive clients."""
        import time
        current_time = time.time()
        stale_clients = []
        
        for client_key, last_access in self.last_access.items():
            if current_time - last_access > self.cleanup_interval:
                stale_clients.append(client_key)
        
        for client_key in stale_clients:
            del self.limiters[client_key]
            del self.last_access[client_key]
        
        if stale_clients:
            print(f"Cleaned up {len(stale_clients)} stale rate limiters")

# Usage
class ServicerWithPerClientLimits:
    def __init__(self):
        # 10 RPS per client, burst of 20
        self.rate_limiter = PerClientRateLimiter(
            capacity=20.0,
            refill_rate=10.0
        )
    
    async def SomeMethod(self, request, context):
        if not await self.rate_limiter.is_allowed(request, context):
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details("Rate limit exceeded for client")
            return None
        
        return await self._process_request(request)
```

### Method-Specific Rate Limiting

```python
class MultiMethodRateLimiter:
    """Different rate limits for different RPC methods."""
    
    def __init__(self):
        self.method_limiters = {
            # Read operations: higher limits
            'GetUser': TokenBucketRateLimiter(capacity=100.0, refill_rate=50.0),
            'ListUsers': TokenBucketRateLimiter(capacity=50.0, refill_rate=25.0),
            'SearchUsers': TokenBucketRateLimiter(capacity=20.0, refill_rate=10.0),
            
            # Write operations: lower limits  
            'CreateUser': TokenBucketRateLimiter(capacity=10.0, refill_rate=2.0),
            'UpdateUser': TokenBucketRateLimiter(capacity=20.0, refill_rate=5.0),
            'DeleteUser': TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0),
            
            # Admin operations: very low limits
            'AdminOperation': TokenBucketRateLimiter(capacity=2.0, refill_rate=0.1),
        }
        
        # Default limiter for unlisted methods
        self.default_limiter = TokenBucketRateLimiter(capacity=30.0, refill_rate=15.0)
    
    async def is_allowed(self, method_name: str) -> bool:
        """Check if method call is allowed."""
        limiter = self.method_limiters.get(method_name, self.default_limiter)
        return await limiter.is_allowed()

class ServicerWithMethodLimits:
    def __init__(self):
        self.rate_limiter = MultiMethodRateLimiter()
    
    async def GetUser(self, request, context):
        if not await self.rate_limiter.is_allowed('GetUser'):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
        return await self._get_user(request)
    
    async def CreateUser(self, request, context):
        if not await self.rate_limiter.is_allowed('CreateUser'):
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
        return await self._create_user(request)
```

### Rate Limiting Middleware

```python
import functools
import grpc
from collections.abc import Callable, Awaitable

def rate_limited(
    capacity: float, 
    refill_rate: float,
    per_client: bool = False
):
    """Decorator for rate limiting RPC methods."""
    
    def decorator(method: Callable) -> Callable:
        if per_client:
            limiter = PerClientRateLimiter(capacity, refill_rate)
        else:
            limiter = TokenBucketRateLimiter(capacity, refill_rate)
        
        @functools.wraps(method)
        async def wrapper(self, request, context):
            # Check rate limit
            if per_client:
                allowed = await limiter.is_allowed(request, context)
            else:
                allowed = await limiter.is_allowed()
            
            if not allowed:
                context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
                context.set_details("Rate limit exceeded")
                return None
            
            return await method(self, request, context)
        
        return wrapper
    return decorator

# Usage with decorator
class DecoratedServicer:
    
    @rate_limited(capacity=50.0, refill_rate=25.0)
    async def GetData(self, request, context):
        """Rate limited to 25 RPS with burst of 50."""
        return await self._get_data(request)
    
    @rate_limited(capacity=5.0, refill_rate=1.0, per_client=True)  
    async def CreateResource(self, request, context):
        """Rate limited to 1 RPS per client, burst of 5."""
        return await self._create_resource(request)
```

## Performance Examples

### Load Testing Rate Limiter

```python
import asyncio
import time
from statistics import mean, median
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter

async def load_test_rate_limiter():
    """Load test the rate limiter performance."""
    
    # Create rate limiter: 100 RPS, burst of 200
    limiter = TokenBucketRateLimiter(capacity=200.0, refill_rate=100.0)
    
    # Test parameters
    duration = 10  # seconds
    concurrent_clients = 50
    
    results = []
    start_time = time.time()
    
    async def client_worker(client_id: int):
        """Simulate a client making requests."""
        client_results = {"allowed": 0, "denied": 0, "latencies": []}
        
        while time.time() - start_time < duration:
            request_start = time.time()
            
            # Make request
            allowed = await limiter.is_allowed()
            
            request_end = time.time()
            latency = request_end - request_start
            
            client_results["latencies"].append(latency)
            if allowed:
                client_results["allowed"] += 1
            else:
                client_results["denied"] += 1
            
            # Small delay to avoid tight loop
            await asyncio.sleep(0.01)
        
        return client_results
    
    # Run concurrent clients
    print(f"Starting load test: {concurrent_clients} clients for {duration}s")
    tasks = [client_worker(i) for i in range(concurrent_clients)]
    client_results = await asyncio.gather(*tasks)
    
    # Analyze results
    total_allowed = sum(r["allowed"] for r in client_results)
    total_denied = sum(r["denied"] for r in client_results)
    total_requests = total_allowed + total_denied
    
    all_latencies = []
    for r in client_results:
        all_latencies.extend(r["latencies"])
    
    actual_duration = time.time() - start_time
    
    print("\n=== Load Test Results ===")
    print(f"Duration: {actual_duration:.2f}s")
    print(f"Total requests: {total_requests:,}")
    print(f"Allowed: {total_allowed:,} ({total_allowed/total_requests*100:.1f}%)")
    print(f"Denied: {total_denied:,} ({total_denied/total_requests*100:.1f}%)")
    print(f"Actual RPS: {total_requests/actual_duration:.1f}")
    print(f"Allowed RPS: {total_allowed/actual_duration:.1f}")
    
    if all_latencies:
        print(f"Latency - Mean: {mean(all_latencies)*1000:.2f}ms")
        print(f"Latency - Median: {median(all_latencies)*1000:.2f}ms") 
        print(f"Latency - P99: {sorted(all_latencies)[int(len(all_latencies)*0.99)]*1000:.2f}ms")

# Run load test
asyncio.run(load_test_rate_limiter())
```

### Burst Behavior Analysis

```python
async def analyze_burst_behavior():
    """Analyze token bucket burst behavior."""
    
    # Rate limiter: 5 RPS steady, burst up to 20
    limiter = TokenBucketRateLimiter(capacity=20.0, refill_rate=5.0)
    
    print("=== Burst Behavior Analysis ===")
    
    # Phase 1: Initial burst
    print("\nPhase 1: Initial burst (bucket starts full)")
    for i in range(25):
        allowed = await limiter.is_allowed()
        tokens = await limiter.get_current_tokens()
        status = "ALLOWED" if allowed else "DENIED"
        print(f"Request {i+1:2d}: {status:7s} (tokens: {tokens:5.2f})")
    
    # Phase 2: Wait for refill
    print("\nPhase 2: Waiting for token refill...")
    await asyncio.sleep(2)  # Wait 2 seconds for 10 tokens to refill
    
    # Phase 3: Steady state
    print("\nPhase 3: Steady state requests")
    for i in range(10):
        allowed = await limiter.is_allowed()
        tokens = await limiter.get_current_tokens()
        status = "ALLOWED" if allowed else "DENIED"
        print(f"Request {i+1:2d}: {status:7s} (tokens: {tokens:5.2f})")
        await asyncio.sleep(0.15)  # 6.67 RPS (slightly above limit)

# Run analysis
asyncio.run(analyze_burst_behavior())
```

### Rate Limiter Monitoring

```python
import asyncio
import logging
from datetime import datetime, timedelta

class RateLimiterMonitor:
    """Monitor rate limiter usage and performance."""
    
    def __init__(self, limiter: TokenBucketRateLimiter, name: str = "limiter"):
        self.limiter = limiter
        self.name = name
        self.stats = {
            "total_requests": 0,
            "allowed_requests": 0,
            "denied_requests": 0,
            "start_time": datetime.now()
        }
        self.monitoring = False
    
    async def check_and_record(self) -> bool:
        """Check rate limit and record statistics."""
        self.stats["total_requests"] += 1
        
        allowed = await self.limiter.is_allowed()
        
        if allowed:
            self.stats["allowed_requests"] += 1
        else:
            self.stats["denied_requests"] += 1
        
        return allowed
    
    async def start_monitoring(self, interval: float = 30.0):
        """Start background monitoring task."""
        self.monitoring = True
        
        while self.monitoring:
            await asyncio.sleep(interval)
            await self._log_statistics()
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring = False
    
    async def _log_statistics(self):
        """Log current statistics."""
        duration = datetime.now() - self.stats["start_time"]
        duration_seconds = duration.total_seconds()
        
        if duration_seconds == 0:
            return
        
        tokens = await self.limiter.get_current_tokens()
        
        total_rps = self.stats["total_requests"] / duration_seconds
        allowed_rps = self.stats["allowed_requests"] / duration_seconds
        denial_rate = (self.stats["denied_requests"] / 
                      max(self.stats["total_requests"], 1) * 100)
        
        logging.info(
            f"Rate Limiter '{self.name}' Stats: "
            f"Total RPS: {total_rps:.2f}, "
            f"Allowed RPS: {allowed_rps:.2f}, "
            f"Denial Rate: {denial_rate:.1f}%, "
            f"Current Tokens: {tokens:.2f}"
        )
    
    def get_summary(self) -> dict:
        """Get summary statistics."""
        duration = datetime.now() - self.stats["start_time"]
        duration_seconds = duration.total_seconds()
        
        return {
            "name": self.name,
            "duration_seconds": duration_seconds,
            "total_requests": self.stats["total_requests"],
            "allowed_requests": self.stats["allowed_requests"], 
            "denied_requests": self.stats["denied_requests"],
            "total_rps": self.stats["total_requests"] / max(duration_seconds, 1),
            "allowed_rps": self.stats["allowed_requests"] / max(duration_seconds, 1),
            "denial_rate_percent": (self.stats["denied_requests"] / 
                                   max(self.stats["total_requests"], 1) * 100)
        }

# Usage
async def monitored_service():
    """Example service with rate limit monitoring."""
    limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=5.0)
    monitor = RateLimiterMonitor(limiter, "api_service")
    
    # Start monitoring in background
    monitor_task = asyncio.create_task(monitor.start_monitoring(interval=10.0))
    
    try:
        # Simulate service requests
        for i in range(100):
            if await monitor.check_and_record():
                # Process request
                await asyncio.sleep(0.05)  # Simulate work
                print(f"Request {i+1}: processed")
            else:
                print(f"Request {i+1}: rate limited")
            
            await asyncio.sleep(0.1)  # Request interval
    
    finally:
        monitor.stop_monitoring()
        monitor_task.cancel()
        
        # Print final summary
        summary = monitor.get_summary()
        print(f"\nFinal Statistics:")
        print(f"Total Requests: {summary['total_requests']}")
        print(f"Allowed: {summary['allowed_requests']} ({100-summary['denial_rate_percent']:.1f}%)")
        print(f"Denied: {summary['denied_requests']} ({summary['denial_rate_percent']:.1f}%)")
        print(f"Average RPS: {summary['total_rps']:.2f}")

# Run monitored service
asyncio.run(monitored_service())
```

## Configuration Patterns

### Rate Limiter Factory

```python
from enum import Enum
from dataclasses import dataclass

class RateLimitType(Enum):
    PERMISSIVE = "permissive"      # High limits for normal operation
    STANDARD = "standard"          # Balanced limits 
    RESTRICTIVE = "restrictive"    # Low limits for high security
    BURST_TOLERANT = "burst_tolerant"  # High burst, moderate steady rate

@dataclass
class RateLimitConfig:
    capacity: float
    refill_rate: float
    description: str

class RateLimiterFactory:
    """Factory for creating preconfigured rate limiters."""
    
    PRESETS = {
        RateLimitType.PERMISSIVE: RateLimitConfig(
            capacity=1000.0,
            refill_rate=500.0, 
            description="High throughput for normal operations"
        ),
        RateLimitType.STANDARD: RateLimitConfig(
            capacity=100.0,
            refill_rate=50.0,
            description="Balanced rate limiting"
        ),
        RateLimitType.RESTRICTIVE: RateLimitConfig(
            capacity=10.0,
            refill_rate=2.0,
            description="Strict limits for security"
        ),
        RateLimitType.BURST_TOLERANT: RateLimitConfig(
            capacity=500.0,
            refill_rate=50.0,
            description="Handle traffic spikes well"
        )
    }
    
    @classmethod
    def create(cls, preset: RateLimitType) -> TokenBucketRateLimiter:
        """Create rate limiter from preset configuration."""
        config = cls.PRESETS[preset]
        return TokenBucketRateLimiter(
            capacity=config.capacity,
            refill_rate=config.refill_rate
        )
    
    @classmethod
    def create_custom(cls, capacity: float, refill_rate: float) -> TokenBucketRateLimiter:
        """Create rate limiter with custom parameters."""
        return TokenBucketRateLimiter(capacity=capacity, refill_rate=refill_rate)

# Usage
# Standard rate limiter
limiter = RateLimiterFactory.create(RateLimitType.STANDARD)

# Burst tolerant for user-facing API
api_limiter = RateLimiterFactory.create(RateLimitType.BURST_TOLERANT) 

# Custom configuration
custom_limiter = RateLimiterFactory.create_custom(capacity=75.0, refill_rate=25.0)
```

### Environment-Based Configuration

```python
import os
from typing import Optional

class RateLimitSettings:
    """Rate limiting settings from environment variables."""
    
    @staticmethod
    def get_float_env(key: str, default: float) -> float:
        """Get float from environment with default."""
        value = os.getenv(key)
        if value is None:
            return default
        try:
            return float(value)
        except ValueError:
            print(f"Warning: Invalid float value for {key}={value}, using default {default}")
            return default
    
    @classmethod
    def from_env(cls, service_name: str) -> TokenBucketRateLimiter:
        """Create rate limiter from environment variables."""
        
        # Environment variable names
        capacity_key = f"{service_name.upper()}_RATE_LIMIT_CAPACITY"
        rate_key = f"{service_name.upper()}_RATE_LIMIT_REFILL_RATE"
        
        # Get values with defaults
        capacity = cls.get_float_env(capacity_key, 100.0)
        refill_rate = cls.get_float_env(rate_key, 50.0)
        
        print(f"Rate limiter for {service_name}: {refill_rate} RPS, burst {capacity}")
        
        return TokenBucketRateLimiter(
            capacity=capacity,
            refill_rate=refill_rate
        )

# Usage
# Set environment variables:
# export USER_SERVICE_RATE_LIMIT_CAPACITY=200
# export USER_SERVICE_RATE_LIMIT_REFILL_RATE=100

user_limiter = RateLimitSettings.from_env("user_service")
auth_limiter = RateLimitSettings.from_env("auth_service") 
```

## Best Practices

### 1. Rate Limit Selection

Choose appropriate rate limits based on your use case:

```python
# API Categories and Suggested Limits

# Public APIs (external users)
public_api_limiter = TokenBucketRateLimiter(capacity=60.0, refill_rate=10.0)  # 10 RPS, 1-minute burst

# Authenticated APIs (registered users) 
auth_api_limiter = TokenBucketRateLimiter(capacity=300.0, refill_rate=50.0)   # 50 RPS, 6-second burst

# Internal APIs (service-to-service)
internal_limiter = TokenBucketRateLimiter(capacity=1000.0, refill_rate=500.0) # 500 RPS, 2-second burst

# Admin APIs (privileged operations)
admin_limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0)         # 1 RPS, 5-request burst

# Batch/Analytics APIs (bulk operations)
batch_limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=0.1)        # 1 request per 10s, 10-request burst
```

### 2. Error Handling

Implement robust error handling:

```python
async def robust_rate_limited_handler(request, context, limiter):
    """Robust rate limiting with proper error handling."""
    
    try:
        # Check rate limit
        allowed = await limiter.is_allowed()
        
        if not allowed:
            # Set appropriate gRPC error
            context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
            context.set_details("Rate limit exceeded. Please retry after some time.")
            
            # Add rate limit headers (if supported)
            context.set_trailing_metadata([
                ('retry-after', '1'),
                ('x-rate-limit-remaining', '0'),
            ])
            
            return None
        
        # Process request
        return await process_request(request)
        
    except Exception as e:
        logger.error(f"Rate limiter error: {e}")
        
        # Fail open: allow request if rate limiter fails
        # Alternative: fail closed by returning rate limit error
        logger.warning("Rate limiter failed, allowing request (fail-open)")
        return await process_request(request)
```

### 3. Testing Rate Limiters

Comprehensive testing approach:

```python
import pytest

class TestTokenBucketRateLimiter:
    """Comprehensive rate limiter tests."""
    
    @pytest.mark.asyncio
    async def test_basic_functionality(self):
        """Test basic allow/deny functionality."""
        limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=1.0)
        
        # Should allow initial requests (bucket starts full)
        assert await limiter.is_allowed() == True
        assert await limiter.is_allowed() == True
        
        # Should deny when bucket is empty
        assert await limiter.is_allowed() == False
        
    @pytest.mark.asyncio
    async def test_refill_behavior(self):
        """Test token refill over time."""
        limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=1.0)
        
        # Consume token
        assert await limiter.is_allowed() == True
        assert await limiter.is_allowed() == False
        
        # Wait for refill
        await asyncio.sleep(1.1)  # Wait slightly more than 1 second
        
        # Should allow again
        assert await limiter.is_allowed() == True
        
    @pytest.mark.asyncio  
    async def test_concurrent_access(self):
        """Test thread safety with concurrent access."""
        limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=5.0)
        
        async def worker():
            results = []
            for _ in range(20):
                results.append(await limiter.is_allowed())
            return results
        
        # Run 5 concurrent workers
        tasks = [worker() for _ in range(5)]
        all_results = await asyncio.gather(*tasks)
        
        # Count total allowed requests
        total_allowed = sum(sum(results) for results in all_results)
        total_requests = sum(len(results) for results in all_results)
        
        # Should have some denied requests due to rate limiting
        assert total_allowed < total_requests
        assert total_allowed <= 10  # Should not exceed capacity
```

## Future Improvements

The following advanced rate limiting features are planned for future releases:

### Multiple Algorithm Support

Support for additional rate limiting algorithms:

- **Sliding Window**: More precise rate limiting over time windows
- **Fixed Window**: Simple time-window based limiting  
- **Leaky Bucket**: Smooth output rate regardless of input bursts
- **Adaptive**: Dynamic rate adjustment based on system load

```python
# Future API concept
sliding_limiter = SlidingWindowRateLimiter(
    limit=100,
    window_seconds=60,
    precision_buckets=12  # 5-second sub-windows
)

leaky_limiter = LeakyBucketRateLimiter(
    capacity=50.0,
    leak_rate=10.0  # Process 10 requests per second
)
```

### Distributed Rate Limiting  

Redis-backed rate limiting for multi-instance deployments:

- **Shared State**: Rate limits shared across multiple server instances
- **Redis Backend**: Atomic operations using Lua scripts
- **Conflict Resolution**: Handle Redis connectivity issues gracefully
- **Performance**: Optimized for low latency and high throughput

```python
# Future API concept
distributed_limiter = RedisTokenBucketRateLimiter(
    redis_client=redis_client,
    key_prefix="ratelimit:api:",
    capacity=100.0,
    refill_rate=50.0
)
```

### gRPC Interceptor Integration

Built-in gRPC interceptors for automatic rate limiting:

- **Method-Level Limits**: Different limits per RPC method
- **Client-Based Limits**: Automatic client identification and limiting  
- **Header Integration**: Rate limit status in response headers
- **Metrics Export**: Automatic metrics collection

```python
# Future API concept
interceptor = RateLimitingInterceptor(
    default_limiter=TokenBucketRateLimiter(100.0, 50.0),
    method_limits={
        'CreateUser': TokenBucketRateLimiter(10.0, 2.0),
        'DeleteUser': TokenBucketRateLimiter(5.0, 1.0),
    },
    per_client=True,
    export_metrics=True
)

server.add_interceptor(interceptor)
```

### Advanced Features

Enterprise-grade rate limiting capabilities:

- **Hierarchical Limits**: Global → Service → Client → Method rate limiting
- **Quota Management**: Time-based quota allocation and tracking
- **Dynamic Configuration**: Runtime rate limit updates without restart
- **Circuit Breaker Integration**: Automatic rate limit adjustment during failures

```python
# Future API concept
hierarchy = HierarchicalRateLimiter()
hierarchy.add_level("global", TokenBucketRateLimiter(10000.0, 5000.0))
hierarchy.add_level("service", TokenBucketRateLimiter(1000.0, 500.0))
hierarchy.add_level("client", TokenBucketRateLimiter(100.0, 50.0))

quota_manager = QuotaManager()
quota_manager.set_quota("premium_client", requests_per_month=1000000)
quota_manager.set_quota("basic_client", requests_per_month=100000)
```

## Quick Examples

For executable code samples:

- **[Rate Limiting](../../examples/short/rate-limiting.md)** - Basic token bucket implementation  
- **[Basic Server](../../examples/short/basic-server.md)** - Server without rate limiting for comparison

These enhancements would provide comprehensive rate limiting suitable for large-scale production deployments with complex traffic management requirements.