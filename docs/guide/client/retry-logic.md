# Retry Logic

Build resilient plugin clients with sophisticated retry strategies, exponential backoff, circuit breakers, and graceful degradation for handling transient failures.

## Overview

Retry logic ensures plugin clients handle transient failures gracefully - network hiccups, server restarts, temporary overload, and other recoverable errors common in distributed systems.

### Key Benefits

- **Resilient Communication**: Automatic recovery from transient failures
- **Exponential Backoff**: Intelligent retry spacing to avoid thundering herds  
- **Circuit Breaker**: Fail fast when services are consistently unavailable
- **Error Classification**: Retry only appropriate error types
- **Graceful Degradation**: Fallback strategies when retries exhausted

### Quick Start

```python
import asyncio
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import RPCPluginError, TransportError
from provide.foundation import logger

async def retry_example():
    """Basic retry with exponential backoff."""
    
    max_retries = 3
    base_delay = 1.0
    
    for attempt in range(max_retries + 1):
        try:
            async with plugin_client(command=["python", "plugin.py"]) as client:
                result = await client.service.unreliable_method()
                logger.info(f"Success on attempt {attempt + 1}")
                return result
                
        except (TransportError, RPCPluginError) as e:
            if attempt == max_retries:
                logger.error(f"All {max_retries + 1} attempts failed")
                raise
            
            # Exponential backoff: 1s, 2s, 4s
            delay = base_delay * (2 ** attempt)
            logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay}s")
            await asyncio.sleep(delay)
```

## Retry Strategies

### 1. **Exponential Backoff with Jitter**
Prevents thundering herd problems by adding randomization to retry delays.

```python
import random
from pyvider.rpcplugin.retry import ExponentialBackoff

# Configure backoff strategy
backoff = ExponentialBackoff(
    base_delay=1.0,
    max_delay=30.0,
    multiplier=2.0,
    jitter=True  # Add randomization
)

async def retry_with_backoff(func, max_attempts=5):
    for attempt in range(max_attempts):
        try:
            return await func()
        except RetryableError as e:
            if attempt == max_attempts - 1:
                raise
            
            delay = backoff.calculate_delay(attempt)
            await asyncio.sleep(delay)
```

### 2. **Circuit Breaker Pattern**
Fail fast when service is consistently unavailable to prevent cascade failures.

```python
from pyvider.rpcplugin.retry import CircuitBreaker

# Configure circuit breaker
breaker = CircuitBreaker(
    failure_threshold=5,      # Open after 5 failures
    recovery_timeout=30.0,    # Try again after 30 seconds
    expected_exception=RPCPluginError
)

async def call_with_circuit_breaker():
    async with breaker:
        result = await client.service.fragile_method()
        return result
```

### 3. **Adaptive Retry**
Adjusts retry behavior based on observed failure patterns and response times.

```python
from pyvider.rpcplugin.retry import AdaptiveRetry

adaptive = AdaptiveRetry(
    initial_max_attempts=3,
    success_rate_threshold=0.8,  # Reduce retries if 80%+ success
    failure_rate_threshold=0.5   # Increase retries if 50%+ failures
)

async def adaptive_retry_call():
    return await adaptive.execute(
        lambda: client.service.adaptive_method()
    )
```

## Error Classification

### Retryable Errors
```python
from pyvider.rpcplugin.exception import (
    TransportError,        # Network connectivity issues
    ServerUnavailableError, # Temporary server problems  
    TimeoutError,          # Request timeouts
    ResourceExhaustedError # Rate limiting, temporary overload
)

# Errors that should trigger retries
RETRYABLE_ERRORS = (
    TransportError,
    ServerUnavailableError, 
    TimeoutError,
    ResourceExhaustedError
)

async def smart_retry(func, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            return await func()
        except RETRYABLE_ERRORS as e:
            if attempt == max_attempts - 1:
                raise
            logger.warning(f"Retryable error: {e}")
        except Exception as e:
            # Non-retryable error - fail immediately
            logger.error(f"Non-retryable error: {e}")
            raise
```

### Non-Retryable Errors
```python
# Errors that should NOT be retried
NON_RETRYABLE_ERRORS = (
    AuthenticationError,    # Invalid credentials
    AuthorizationError,     # Insufficient permissions
    ValidationError,        # Invalid request data
    NotFoundError          # Resource doesn't exist
)
```

## Client Integration

### Retry-Enabled Client
```python
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.retry import RetryConfig

# Configure retry behavior
retry_config = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=True,
    retryable_errors=RETRYABLE_ERRORS
)

# Client with built-in retry
async with plugin_client(
    command=["python", "plugin.py"],
    retry_config=retry_config
) as client:
    # All method calls automatically retry on failure
    result = await client.service.method_with_retries()
```

### Custom Retry Decorator
```python
from functools import wraps
from pyvider.rpcplugin.retry import retry_with_backoff

def retry_on_failure(max_attempts=3, base_delay=1.0):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_with_backoff(
                lambda: func(*args, **kwargs),
                max_attempts=max_attempts,
                base_delay=base_delay
            )
        return wrapper
    return decorator

# Usage
@retry_on_failure(max_attempts=5, base_delay=2.0)
async def resilient_plugin_call():
    async with plugin_client() as client:
        return await client.service.important_method()
```

## Configuration Patterns

### Development Environment
```python
# Lenient retry for development
dev_retry = RetryConfig(
    max_attempts=2,          # Quick failures
    base_delay=0.5,          # Short delays
    max_delay=5.0,           # Low maximum
    enable_circuit_breaker=False  # No circuit breaking
)
```

### Production Environment
```python
# Aggressive retry for production
prod_retry = RetryConfig(
    max_attempts=5,          # More attempts
    base_delay=1.0,          # Standard delay
    max_delay=60.0,          # Higher maximum
    jitter=True,             # Prevent thundering herd
    enable_circuit_breaker=True,
    circuit_failure_threshold=10,
    circuit_recovery_timeout=30.0
)
```

### High-Availability Environment
```python
# Maximum resilience configuration
ha_retry = RetryConfig(
    max_attempts=10,         # Many attempts
    base_delay=0.5,          # Quick start
    max_delay=300.0,         # 5 minute maximum
    adaptive_retry=True,     # Learn from patterns
    circuit_breaker_enabled=True,
    fallback_strategy="graceful_degradation"
)
```

## Advanced Patterns

### Retry with Timeout
```python
import asyncio
from contextlib import asynccontextmanager

@asynccontextmanager
async def retry_with_timeout(total_timeout=60.0):
    """Retry operations within overall timeout."""
    start_time = asyncio.get_event_loop().time()
    
    async def time_remaining():
        elapsed = asyncio.get_event_loop().time() - start_time
        return max(0, total_timeout - elapsed)
    
    yield time_remaining

# Usage
async def timed_retry_call():
    async with retry_with_timeout(total_timeout=30.0) as time_left:
        max_attempts = 5
        for attempt in range(max_attempts):
            if await time_left() < 1.0:
                raise TimeoutError("Overall timeout exceeded")
                
            try:
                return await client.service.method()
            except RetryableError:
                if attempt < max_attempts - 1:
                    await asyncio.sleep(min(2 ** attempt, await time_left()))
```

### Fallback Strategies
```python
from pyvider.rpcplugin.fallback import FallbackStrategy

async def resilient_call_with_fallbacks():
    """Primary call with multiple fallback options."""
    
    # Try primary service
    try:
        return await retry_call(primary_client.service.method)
    except Exception as e:
        logger.warning(f"Primary service failed: {e}")
    
    # Fallback to secondary service
    try:
        return await retry_call(secondary_client.service.method)
    except Exception as e:
        logger.warning(f"Secondary service failed: {e}")
    
    # Final fallback - cached response or default
    cached_result = await get_cached_response()
    if cached_result:
        logger.info("Using cached fallback response")
        return cached_result
    
    # Return safe default
    logger.warning("All services failed, using default response")
    return get_default_response()
```

### Bulk Retry Operations
```python
async def retry_batch_operations(operations, max_concurrent=5):
    """Retry multiple operations concurrently."""
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def retry_single_operation(operation):
        async with semaphore:
            return await retry_with_backoff(operation)
    
    # Execute all operations with retry logic
    tasks = [retry_single_operation(op) for op in operations]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Separate successful results from failures
    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]
    
    return successes, failures
```

## Monitoring and Observability

### Retry Metrics
```python
from provide.foundation import logger

class RetryMetrics:
    def __init__(self):
        self.total_calls = 0
        self.successful_calls = 0
        self.retried_calls = 0
        self.failed_calls = 0
    
    def record_success(self, attempt_count):
        self.total_calls += 1
        self.successful_calls += 1
        if attempt_count > 1:
            self.retried_calls += 1
        
        logger.info("Call succeeded", extra={
            "attempt_count": attempt_count,
            "success_rate": self.successful_calls / self.total_calls
        })
    
    def record_failure(self, attempt_count, error):
        self.total_calls += 1
        self.failed_calls += 1
        
        logger.error("Call failed after retries", extra={
            "attempt_count": attempt_count,
            "error": str(error),
            "failure_rate": self.failed_calls / self.total_calls
        })
```

### Health Monitoring
```python
async def monitor_retry_health():
    """Monitor retry patterns for service health."""
    
    retry_tracker = RetryHealthTracker()
    
    while True:
        stats = retry_tracker.get_stats()
        
        # Alert on high retry rates
        if stats.retry_rate > 0.5:  # 50% of calls need retries
            logger.warning("High retry rate detected", extra=stats.to_dict())
            
        # Alert on circuit breaker trips
        if stats.circuit_breaker_trips > 0:
            logger.error("Circuit breaker trips detected", extra=stats.to_dict())
        
        await asyncio.sleep(60)  # Check every minute
```

## Best Practices

1. **Classify Errors**: Only retry transient/recoverable errors
2. **Use Exponential Backoff**: Prevent overwhelming failing services
3. **Add Jitter**: Avoid thundering herd synchronization
4. **Set Reasonable Limits**: Balance resilience with responsiveness
5. **Implement Circuit Breakers**: Fail fast for consistent failures
6. **Monitor Retry Patterns**: High retry rates indicate service issues
7. **Test Failure Scenarios**: Verify retry logic works correctly
8. **Use Fallback Strategies**: Provide alternatives when retries fail

## Troubleshooting

### High Retry Rates
```python
# Check retry statistics
if retry_metrics.retry_rate > 0.3:
    logger.warning("High retry rate indicates service issues")
    
    # Investigate causes
    error_breakdown = retry_metrics.get_error_breakdown()
    for error_type, count in error_breakdown.items():
        logger.info(f"{error_type}: {count} occurrences")
```

### Circuit Breaker Issues
```python
# Monitor circuit breaker state
if circuit_breaker.state == "OPEN":
    logger.error("Circuit breaker is open - service unavailable")
    time_until_retry = circuit_breaker.time_until_retry()
    logger.info(f"Will retry in {time_until_retry} seconds")
```

### Timeout Problems  
```python
# Analyze timeout patterns
timeout_stats = retry_tracker.get_timeout_stats()
if timeout_stats.average_timeout > acceptable_threshold:
    logger.warning("High timeout rates detected")
    # Consider increasing timeouts or reducing retry attempts
```

## Next Steps

- **[Connection Management](connections/)** - Advanced connection handling
- **[Error Handling](error-handling/)** - Comprehensive error strategies
- **[Direct Connections](direct-connections/)** - Low-level client patterns
- **[Client Configuration](basic-setup/)** - Client setup and configuration