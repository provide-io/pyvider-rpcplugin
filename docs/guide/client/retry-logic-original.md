# Retry Logic

Build resilient plugin clients with sophisticated retry strategies, exponential backoff, circuit breakers, and graceful degradation patterns.

## Overview

Retry logic ensures your plugin clients can handle transient failures gracefully. This includes network hiccups, server restarts, temporary overload, and other recoverable errors that are common in distributed systems.

```python
import asyncio
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import RPCPluginError, TransportError

async def basic_retry_example():
    """Simple retry with exponential backoff."""
    
    max_retries = 3
    base_delay = 1.0  # Start with 1 second
    
    for attempt in range(max_retries + 1):
        try:
            async with plugin_client(command=["python", "unreliable_plugin.py"]) as client:
                result = await client.calculator.Add(a=5, b=3)
                print(f"Success on attempt {attempt + 1}: {result.result}")
                return result
                
        except (TransportError, RPCPluginError) as e:
            if attempt == max_retries:
                print(f"All {max_retries + 1} attempts failed")
                raise e
            
            # Exponential backoff: 1s, 2s, 4s, 8s...
            delay = base_delay * (2 ** attempt)
            print(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
            await asyncio.sleep(delay)

# Usage
await basic_retry_example()
```

## Retry Strategies

### Exponential Backoff with Jitter

```python
import asyncio
import random
import time
from typing import Optional, Callable, TypeVar, Any
from dataclasses import dataclass

T = TypeVar('T')

@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_ratio: float = 0.1  # ±10% random jitter

class ExponentialBackoff:
    """Exponential backoff retry handler with jitter."""
    
    def __init__(self, config: RetryConfig):
        self.config = config
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt number."""
        
        # Exponential calculation
        delay = self.config.base_delay * (self.config.exponential_base ** attempt)
        
        # Apply max delay cap
        delay = min(delay, self.config.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.config.jitter:
            jitter_range = delay * self.config.jitter_ratio
            jitter = random.uniform(-jitter_range, jitter_range)
            delay = max(0.1, delay + jitter)  # Ensure minimum 100ms delay
        
        return delay
    
    async def retry(self, operation: Callable[[], T], 
                   retryable_exceptions: tuple = None) -> T:
        """Execute operation with exponential backoff retry."""
        
        if retryable_exceptions is None:
            retryable_exceptions = (Exception,)
        
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                result = await operation()
                if attempt > 0:
                    print(f" Operation succeeded on attempt {attempt + 1}")
                return result
                
            except retryable_exceptions as e:
                last_exception = e
                
                if attempt == self.config.max_retries:
                    print(f"=¥ All {self.config.max_retries + 1} attempts failed")
                    raise e
                
                delay = self.calculate_delay(attempt)
                print(f"ó Attempt {attempt + 1} failed: {e}. Retrying in {delay:.1f}s...")
                await asyncio.sleep(delay)
        
        # Should never reach here, but just in case
        raise last_exception

# Usage example
async def exponential_backoff_example():
    """Demonstrate exponential backoff with jitter."""
    
    config = RetryConfig(
        max_retries=5,
        base_delay=0.5,
        max_delay=30.0,
        exponential_base=2.0,
        jitter=True,
        jitter_ratio=0.2  # ±20% jitter
    )
    
    backoff = ExponentialBackoff(config)
    
    async def unreliable_operation():
        async with plugin_client(command=["python", "flaky_plugin.py"]) as client:
            # This might fail randomly
            return await client.calculator.Divide(a=10, b=2)
    
    try:
        result = await backoff.retry(
            unreliable_operation,
            retryable_exceptions=(TransportError, RPCPluginError)
        )
        print(f"Final result: {result.result}")
        
    except Exception as e:
        print(f"Operation failed after all retries: {e}")

# Usage
await exponential_backoff_example()
```

### Advanced Retry Policies

```python
import grpc
from enum import Enum
from typing import List, Dict, Callable, Optional
from dataclasses import dataclass, field

class RetryCondition(Enum):
    """Conditions that determine if a retry should be attempted."""
    ALWAYS = "always"
    NEVER = "never"
    ON_TRANSIENT_ERROR = "transient"
    ON_CUSTOM_CONDITION = "custom"

@dataclass
class RetryPolicy:
    """Advanced retry policy configuration."""
    
    # Basic retry settings
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    
    # Retry conditions
    condition: RetryCondition = RetryCondition.ON_TRANSIENT_ERROR
    custom_condition: Optional[Callable[[Exception], bool]] = None
    
    # Transient error types (retryable)
    transient_exceptions: tuple = field(default_factory=lambda: (
        TransportError,
        grpc.aio.AioRpcError
    ))
    
    # Specific gRPC status codes to retry
    retryable_grpc_codes: List[grpc.StatusCode] = field(default_factory=lambda: [
        grpc.StatusCode.UNAVAILABLE,
        grpc.StatusCode.DEADLINE_EXCEEDED,
        grpc.StatusCode.RESOURCE_EXHAUSTED,
        grpc.StatusCode.INTERNAL,
        grpc.StatusCode.ABORTED
    ])
    
    # Non-retryable codes (permanent failures)
    non_retryable_grpc_codes: List[grpc.StatusCode] = field(default_factory=lambda: [
        grpc.StatusCode.INVALID_ARGUMENT,
        grpc.StatusCode.NOT_FOUND,
        grpc.StatusCode.ALREADY_EXISTS,
        grpc.StatusCode.PERMISSION_DENIED,
        grpc.StatusCode.UNAUTHENTICATED
    ])
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if we should retry based on exception and policy."""
        
        if attempt >= self.max_retries:
            return False
        
        if self.condition == RetryCondition.NEVER:
            return False
        
        if self.condition == RetryCondition.ALWAYS:
            return True
        
        if self.condition == RetryCondition.ON_CUSTOM_CONDITION:
            return self.custom_condition(exception) if self.custom_condition else False
        
        # ON_TRANSIENT_ERROR (default)
        return self._is_transient_error(exception)
    
    def _is_transient_error(self, exception: Exception) -> bool:
        """Check if exception is a transient/retryable error."""
        
        # Check if it's a known transient exception type
        if isinstance(exception, self.transient_exceptions):
            # Special handling for gRPC errors
            if isinstance(exception, grpc.aio.AioRpcError):
                status_code = exception.code()
                
                # Explicit non-retryable codes
                if status_code in self.non_retryable_grpc_codes:
                    return False
                
                # Explicit retryable codes
                if status_code in self.retryable_grpc_codes:
                    return True
                
                # Default to non-retryable for unknown codes
                return False
            
            return True
        
        return False

class RetryableClient:
    """Plugin client with configurable retry policies."""
    
    def __init__(self, command: list[str], retry_policy: RetryPolicy):
        self.command = command
        self.policy = retry_policy
        self.backoff = ExponentialBackoff(RetryConfig(
            max_retries=retry_policy.max_retries,
            base_delay=retry_policy.base_delay,
            max_delay=retry_policy.max_delay
        ))
    
    async def call_with_retry(self, service_method: str, **kwargs) -> Any:
        """Make RPC call with retry policy."""
        
        async def rpc_operation():
            async with plugin_client(command=self.command) as client:
                service_name, method_name = service_method.split('.')
                service = getattr(client, service_name.lower())
                method = getattr(service, method_name)
                
                return await method(**kwargs)
        
        # Custom retry logic with policy
        last_exception = None
        
        for attempt in range(self.policy.max_retries + 1):
            try:
                return await rpc_operation()
                
            except Exception as e:
                last_exception = e
                
                if not self.policy.should_retry(e, attempt):
                    print(f"=« Not retrying {type(e).__name__}: {e}")
                    raise e
                
                if attempt == self.policy.max_retries:
                    print(f"=¥ Max retries ({self.policy.max_retries}) exceeded")
                    raise e
                
                delay = self.backoff.calculate_delay(attempt)
                print(f"= Retrying after {delay:.1f}s due to: {type(e).__name__}")
                await asyncio.sleep(delay)
        
        raise last_exception

# Usage examples
async def advanced_retry_examples():
    """Demonstrate advanced retry policies."""
    
    # Policy 1: Conservative - only retry specific transient errors
    conservative_policy = RetryPolicy(
        max_retries=2,
        base_delay=2.0,
        retryable_grpc_codes=[grpc.StatusCode.UNAVAILABLE]
    )
    
    conservative_client = RetryableClient(
        ["python", "reliable_plugin.py"], 
        conservative_policy
    )
    
    # Policy 2: Aggressive - retry most errors except obvious client errors
    aggressive_policy = RetryPolicy(
        max_retries=5,
        base_delay=0.5,
        max_delay=20.0,
        non_retryable_grpc_codes=[
            grpc.StatusCode.INVALID_ARGUMENT,
            grpc.StatusCode.NOT_FOUND
        ]
    )
    
    aggressive_client = RetryableClient(
        ["python", "flaky_plugin.py"], 
        aggressive_policy
    )
    
    # Policy 3: Custom condition - retry based on error message
    def custom_retry_condition(exception: Exception) -> bool:
        error_msg = str(exception).lower()
        # Retry if error suggests temporary issue
        transient_keywords = ["timeout", "connection", "temporary", "retry"]
        return any(keyword in error_msg for keyword in transient_keywords)
    
    custom_policy = RetryPolicy(
        condition=RetryCondition.ON_CUSTOM_CONDITION,
        custom_condition=custom_retry_condition,
        max_retries=3
    )
    
    custom_client = RetryableClient(
        ["python", "custom_plugin.py"], 
        custom_policy
    )
    
    # Test different policies
    clients = [
        ("Conservative", conservative_client),
        ("Aggressive", aggressive_client), 
        ("Custom", custom_client)
    ]
    
    for policy_name, client in clients:
        try:
            print(f"\n=, Testing {policy_name} policy:")
            result = await client.call_with_retry("calculator.Add", a=10, b=5)
            print(f" {policy_name} succeeded: {result.result}")
        except Exception as e:
            print(f"L {policy_name} failed: {e}")

# Usage
await advanced_retry_examples()
```

## Circuit Breaker Pattern

### Basic Circuit Breaker

```python
import time
import asyncio
from enum import Enum
from typing import Callable, TypeVar, Any, Optional
from dataclasses import dataclass

T = TypeVar('T')

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests  
    HALF_OPEN = "half_open"  # Testing if service recovered

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    
    failure_threshold: int = 5        # Failures to open circuit
    recovery_timeout: float = 60.0    # Seconds before trying recovery
    success_threshold: int = 3        # Successes to close circuit in half-open
    request_timeout: float = 30.0     # Timeout for individual requests

class CircuitBreaker:
    """Circuit breaker for plugin client calls."""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0
        self.total_requests = 0
        self.total_successes = 0
        self.total_failures = 0
    
    async def call(self, operation: Callable[[], T]) -> T:
        """Execute operation through circuit breaker."""
        
        self.total_requests += 1
        
        # Check circuit state
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._attempt_reset()
            else:
                raise Exception(f"Circuit breaker OPEN - requests blocked for {self.config.recovery_timeout}s")
        
        try:
            # Execute operation with timeout
            result = await asyncio.wait_for(
                operation(), 
                timeout=self.config.request_timeout
            )
            
            # Record success
            self._on_success()
            return result
            
        except Exception as e:
            # Record failure
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        return time.time() - self.last_failure_time >= self.config.recovery_timeout
    
    def _attempt_reset(self):
        """Attempt to reset circuit from OPEN to HALF_OPEN."""
        print("= Circuit breaker attempting reset: OPEN -> HALF_OPEN")
        self.state = CircuitState.HALF_OPEN
        self.success_count = 0
    
    def _on_success(self):
        """Handle successful operation."""
        self.total_successes += 1
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self._close_circuit()
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success in closed state
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed operation."""
        self.total_failures += 1
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self._open_circuit()
        elif self.state == CircuitState.HALF_OPEN:
            # Failure in half-open immediately reopens circuit
            self._open_circuit()
    
    def _open_circuit(self):
        """Open the circuit breaker."""
        print(f"=« Circuit breaker OPENED after {self.failure_count} failures")
        self.state = CircuitState.OPEN
        self.success_count = 0
    
    def _close_circuit(self):
        """Close the circuit breaker."""
        print(f" Circuit breaker CLOSED after {self.success_count} successes")
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
    
    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "state": self.state.value,
            "total_requests": self.total_requests,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "success_rate": self.total_successes / max(1, self.total_requests),
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure_time": self.last_failure_time
        }

class CircuitBreakerClient:
    """Plugin client with circuit breaker protection."""
    
    def __init__(self, command: list[str], circuit_config: CircuitBreakerConfig):
        self.command = command
        self.circuit_breaker = CircuitBreaker(circuit_config)
    
    async def protected_call(self, service_method: str, **kwargs) -> Any:
        """Make RPC call protected by circuit breaker."""
        
        async def rpc_operation():
            async with plugin_client(command=self.command) as client:
                service_name, method_name = service_method.split('.')
                service = getattr(client, service_name.lower())
                method = getattr(service, method_name)
                
                return await method(**kwargs)
        
        return await self.circuit_breaker.call(rpc_operation)
    
    def get_circuit_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return self.circuit_breaker.get_stats()

# Usage example
async def circuit_breaker_example():
    """Demonstrate circuit breaker pattern."""
    
    config = CircuitBreakerConfig(
        failure_threshold=3,      # Open after 3 failures
        recovery_timeout=10.0,    # Try recovery after 10 seconds
        success_threshold=2,      # Close after 2 successes
        request_timeout=5.0       # 5 second request timeout
    )
    
    circuit_client = CircuitBreakerClient(
        ["python", "unreliable_plugin.py"], 
        config
    )
    
    # Simulate many requests to trigger circuit breaker
    for i in range(20):
        try:
            result = await circuit_client.protected_call("calculator.Add", a=i, b=1)
            print(f" Request {i}: {i} + 1 = {result.result}")
        except Exception as e:
            print(f"L Request {i} failed: {e}")
        
        # Show circuit stats periodically  
        if i % 5 == 4:
            stats = circuit_client.get_circuit_stats()
            print(f"=Ê Circuit stats: {stats}")
        
        await asyncio.sleep(1)

# Usage
await circuit_breaker_example()
```

### Adaptive Circuit Breaker

```python
from typing import Deque
from collections import deque
import statistics

class AdaptiveCircuitBreaker(CircuitBreaker):
    """Circuit breaker that adapts thresholds based on recent performance."""
    
    def __init__(self, config: CircuitBreakerConfig, 
                 window_size: int = 20, 
                 adaptation_interval: float = 300.0):
        super().__init__(config)
        
        # Adaptive parameters
        self.window_size = window_size
        self.adaptation_interval = adaptation_interval
        self.last_adaptation = time.time()
        
        # Track recent requests for adaptation
        self.recent_requests: Deque[tuple[float, bool]] = deque(maxlen=window_size)
        
        # Original config for reset
        self.original_failure_threshold = config.failure_threshold
        self.original_recovery_timeout = config.recovery_timeout
    
    def _on_success(self):
        """Record success and adapt if needed."""
        super()._on_success()
        self._record_request(True)
        self._adapt_if_needed()
    
    def _on_failure(self):
        """Record failure and adapt if needed."""
        super()._on_failure()
        self._record_request(False)
        self._adapt_if_needed()
    
    def _record_request(self, success: bool):
        """Record request outcome with timestamp."""
        self.recent_requests.append((time.time(), success))
    
    def _adapt_if_needed(self):
        """Adapt circuit breaker parameters based on recent performance."""
        
        current_time = time.time()
        if current_time - self.last_adaptation < self.adaptation_interval:
            return
        
        if len(self.recent_requests) < self.window_size // 2:
            return  # Not enough data
        
        # Calculate recent success rate
        successes = sum(1 for _, success in self.recent_requests if success)
        success_rate = successes / len(self.recent_requests)
        
        # Adapt failure threshold based on recent performance
        if success_rate > 0.9:  # High success rate
            # Be more lenient - increase failure threshold
            self.config.failure_threshold = min(
                self.original_failure_threshold * 2,
                self.original_failure_threshold + 3
            )
            # Reduce recovery timeout
            self.config.recovery_timeout = max(
                self.original_recovery_timeout * 0.5,
                10.0
            )
            print(f"<¯ Adapted: More lenient (threshold={self.config.failure_threshold}, recovery={self.config.recovery_timeout:.1f}s)")
        
        elif success_rate < 0.5:  # Low success rate
            # Be more strict - decrease failure threshold
            self.config.failure_threshold = max(
                self.original_failure_threshold - 2,
                1
            )
            # Increase recovery timeout
            self.config.recovery_timeout = min(
                self.original_recovery_timeout * 1.5,
                300.0
            )
            print(f"<¯ Adapted: More strict (threshold={self.config.failure_threshold}, recovery={self.config.recovery_timeout:.1f}s)")
        
        self.last_adaptation = current_time
    
    def get_adaptive_stats(self) -> dict[str, Any]:
        """Get adaptive circuit breaker statistics."""
        
        base_stats = self.get_stats()
        
        if self.recent_requests:
            recent_successes = sum(1 for _, success in self.recent_requests if success)
            recent_success_rate = recent_successes / len(self.recent_requests)
        else:
            recent_success_rate = 0.0
        
        base_stats.update({
            "recent_success_rate": recent_success_rate,
            "recent_requests_count": len(self.recent_requests),
            "current_failure_threshold": self.config.failure_threshold,
            "current_recovery_timeout": self.config.recovery_timeout,
            "original_failure_threshold": self.original_failure_threshold,
            "original_recovery_timeout": self.original_recovery_timeout,
            "last_adaptation": self.last_adaptation
        })
        
        return base_stats

# Usage example
async def adaptive_circuit_breaker_example():
    """Demonstrate adaptive circuit breaker."""
    
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30.0,
        success_threshold=2
    )
    
    # Create adaptive circuit breaker
    adaptive_breaker = AdaptiveCircuitBreaker(
        config,
        window_size=15,      # Look at last 15 requests
        adaptation_interval=60.0  # Adapt every 60 seconds
    )
    
    class AdaptiveClient:
        def __init__(self, command: list[str]):
            self.command = command
            self.circuit_breaker = adaptive_breaker
        
        async def call(self, service_method: str, **kwargs):
            async def operation():
                async with plugin_client(command=self.command) as client:
                    service_name, method_name = service_method.split('.')
                    service = getattr(client, service_name.lower())
                    method = getattr(service, method_name)
                    return await method(**kwargs)
            
            return await self.circuit_breaker.call(operation)
    
    client = AdaptiveClient(["python", "adaptive_test_plugin.py"])
    
    # Simulate varying success rates to see adaptation
    for phase in range(3):
        print(f"\n=, Phase {phase + 1}: Simulating requests...")
        
        for i in range(10):
            try:
                result = await client.call("calculator.Add", a=i, b=phase)
                print(f" Request {i}: Success")
            except Exception as e:
                print(f"L Request {i}: {e}")
            
            await asyncio.sleep(0.5)
        
        # Show adaptive stats
        stats = adaptive_breaker.get_adaptive_stats()
        print(f"=Ê Adaptive stats: success_rate={stats['recent_success_rate']:.2f}, "
              f"threshold={stats['current_failure_threshold']}, "
              f"recovery_timeout={stats['current_recovery_timeout']:.1f}s")

# Usage
await adaptive_circuit_breaker_example()
```

## Timeout Management

### Hierarchical Timeouts

```python
import asyncio
from typing import Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class TimeoutConfig:
    """Hierarchical timeout configuration."""
    
    # Connection timeouts
    connection_timeout: float = 10.0
    handshake_timeout: float = 5.0
    
    # Request timeouts  
    request_timeout: float = 30.0
    streaming_timeout: float = 300.0  # 5 minutes for streaming
    
    # Circuit breaker timeout
    circuit_timeout: float = 5.0
    
    # Overall operation timeout
    total_timeout: float = 60.0

class TimeoutManager:
    """Manages hierarchical timeouts for plugin operations."""
    
    def __init__(self, config: TimeoutConfig):
        self.config = config
        self._active_timeouts: Dict[str, asyncio.Task] = {}
    
    async def with_connection_timeout(self, operation: Callable[[], T]) -> T:
        """Execute operation with connection timeout."""
        return await asyncio.wait_for(operation(), timeout=self.config.connection_timeout)
    
    async def with_request_timeout(self, operation: Callable[[], T], 
                                 streaming: bool = False) -> T:
        """Execute operation with request timeout."""
        timeout = self.config.streaming_timeout if streaming else self.config.request_timeout
        return await asyncio.wait_for(operation(), timeout=timeout)
    
    async def with_total_timeout(self, operation: Callable[[], T]) -> T:
        """Execute operation with total timeout."""
        return await asyncio.wait_for(operation(), timeout=self.config.total_timeout)
    
    async def with_nested_timeouts(self, operation: Callable[[], T], 
                                  timeout_name: str = "operation") -> T:
        """Execute with nested timeout tracking."""
        
        timeout_task = asyncio.create_task(
            asyncio.wait_for(operation(), timeout=self.config.total_timeout)
        )
        
        self._active_timeouts[timeout_name] = timeout_task
        
        try:
            result = await timeout_task
            return result
        except asyncio.TimeoutError as e:
            print(f"ð Timeout in '{timeout_name}' after {self.config.total_timeout}s")
            raise e
        finally:
            self._active_timeouts.pop(timeout_name, None)
    
    def cancel_all_timeouts(self):
        """Cancel all active timeout tasks."""
        for timeout_name, task in self._active_timeouts.items():
            if not task.done():
                task.cancel()
                print(f"=« Cancelled timeout: {timeout_name}")
        
        self._active_timeouts.clear()

class TimeoutAwareClient:
    """Plugin client with sophisticated timeout management."""
    
    def __init__(self, command: list[str], timeout_config: TimeoutConfig):
        self.command = command
        self.timeout_manager = TimeoutManager(timeout_config)
        self.config = timeout_config
    
    async def connect_with_timeout(self) -> plugin_client:
        """Connect with connection timeout."""
        
        async def connection_operation():
            client = plugin_client(command=self.command)
            await client.start()
            return client
        
        return await self.timeout_manager.with_connection_timeout(connection_operation)
    
    async def call_with_timeouts(self, service_method: str, 
                               streaming: bool = False, **kwargs) -> Any:
        """Make RPC call with hierarchical timeouts."""
        
        async def full_operation():
            # Connection with its own timeout
            client = await self.connect_with_timeout()
            
            try:
                # RPC call with request timeout
                async def rpc_operation():
                    service_name, method_name = service_method.split('.')
                    service = getattr(client, service_name.lower())
                    method = getattr(service, method_name)
                    
                    return await method(**kwargs)
                
                return await self.timeout_manager.with_request_timeout(
                    rpc_operation, 
                    streaming=streaming
                )
            
            finally:
                await client.close()
        
        # Wrap everything in total timeout
        return await self.timeout_manager.with_total_timeout(full_operation)
    
    async def batch_call_with_timeouts(self, calls: list[tuple[str, dict]], 
                                     max_concurrent: int = 5) -> list[Any]:
        """Execute multiple calls with timeout management."""
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def single_call_with_semaphore(service_method: str, kwargs: dict, index: int):
            async with semaphore:
                try:
                    result = await self.timeout_manager.with_nested_timeouts(
                        lambda: self.call_with_timeouts(service_method, **kwargs),
                        timeout_name=f"call_{index}"
                    )
                    return result
                except Exception as e:
                    print(f"Batch call {index} failed: {e}")
                    return e
        
        # Create tasks for all calls
        tasks = [
            single_call_with_semaphore(service_method, kwargs, i)
            for i, (service_method, kwargs) in enumerate(calls)
        ]
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results
        except Exception as e:
            print(f"Batch operation failed: {e}")
            self.timeout_manager.cancel_all_timeouts()
            raise

# Usage example
async def timeout_management_example():
    """Demonstrate hierarchical timeout management."""
    
    timeout_config = TimeoutConfig(
        connection_timeout=5.0,
        handshake_timeout=3.0,
        request_timeout=10.0,
        streaming_timeout=60.0,
        total_timeout=30.0
    )
    
    client = TimeoutAwareClient(
        ["python", "slow_plugin.py"], 
        timeout_config
    )
    
    try:
        # Single call with timeouts
        result = await client.call_with_timeouts("calculator.Add", a=5, b=3)
        print(f" Single call result: {result.result}")
        
        # Streaming call with longer timeout
        stream_result = await client.call_with_timeouts(
            "data.StreamProcessor", 
            streaming=True,
            data="large_dataset"
        )
        print(f" Streaming call completed")
        
        # Batch calls with timeout management
        batch_calls = [
            ("calculator.Add", {"a": i, "b": i*2})
            for i in range(10)
        ]
        
        batch_results = await client.batch_call_with_timeouts(
            batch_calls, 
            max_concurrent=3
        )
        
        successful_results = [r for r in batch_results if not isinstance(r, Exception)]
        print(f" Batch: {len(successful_results)}/10 calls succeeded")
        
    except asyncio.TimeoutError as e:
        print(f"ð Operation timed out: {e}")
    except Exception as e:
        print(f"L Operation failed: {e}")

# Usage
await timeout_management_example()
```

## Graceful Degradation

### Fallback Strategies

```python
from typing import List, Callable, TypeVar, Any, Optional, Union
from dataclasses import dataclass

T = TypeVar('T')

@dataclass
class FallbackStrategy:
    """Configuration for fallback behavior."""
    
    # Primary service configuration
    primary_command: list[str]
    primary_service: str
    
    # Fallback options
    fallback_commands: List[list[str]]
    fallback_services: List[str]
    
    # Degradation settings
    enable_caching: bool = True
    cache_duration: float = 300.0  # 5 minutes
    enable_default_responses: bool = True
    
    # Quality settings
    max_fallback_attempts: int = 2
    fallback_timeout: float = 5.0

class GracefulDegradationClient:
    """Client with graceful degradation capabilities."""
    
    def __init__(self, fallback_strategy: FallbackStrategy):
        self.strategy = fallback_strategy
        self.cache: Dict[str, tuple[Any, float]] = {}  # value, timestamp
        self.fallback_statistics = {
            "primary_calls": 0,
            "primary_successes": 0,
            "fallback_calls": 0,
            "fallback_successes": 0,
            "cache_hits": 0,
            "default_responses": 0
        }
    
    async def resilient_call(self, method: str, **kwargs) -> Any:
        """Make call with graceful degradation."""
        
        cache_key = self._generate_cache_key(method, kwargs)
        
        # Try primary service first
        try:
            result = await self._try_primary_service(method, **kwargs)
            self._update_cache(cache_key, result)
            self.fallback_statistics["primary_calls"] += 1
            self.fallback_statistics["primary_successes"] += 1
            return result
            
        except Exception as primary_error:
            print(f"=4 Primary service failed: {primary_error}")
            self.fallback_statistics["primary_calls"] += 1
            
            # Try fallback services
            fallback_result = await self._try_fallback_services(method, **kwargs)
            if fallback_result is not None:
                self._update_cache(cache_key, fallback_result)
                return fallback_result
            
            # Try cached response
            cached_result = self._get_cached_response(cache_key)
            if cached_result is not None:
                print("=æ Using cached response")
                self.fallback_statistics["cache_hits"] += 1
                return cached_result
            
            # Try default response
            default_result = self._get_default_response(method, **kwargs)
            if default_result is not None:
                print("<¯ Using default response")
                self.fallback_statistics["default_responses"] += 1
                return default_result
            
            # All fallbacks failed
            raise Exception(f"All fallback strategies exhausted. Original error: {primary_error}")
    
    async def _try_primary_service(self, method: str, **kwargs) -> Any:
        """Attempt primary service call."""
        
        async with plugin_client(command=self.strategy.primary_command) as client:
            service_name, method_name = method.split('.')
            service = getattr(client, service_name.lower())
            rpc_method = getattr(service, method_name)
            
            return await rpc_method(**kwargs)
    
    async def _try_fallback_services(self, method: str, **kwargs) -> Optional[Any]:
        """Try fallback services in order."""
        
        for i, (fallback_command, fallback_service) in enumerate(
            zip(self.strategy.fallback_commands, self.strategy.fallback_services)
        ):
            if i >= self.strategy.max_fallback_attempts:
                break
            
            try:
                print(f"=á Trying fallback service {i+1}")
                self.fallback_statistics["fallback_calls"] += 1
                
                async with plugin_client(command=fallback_command) as client:
                    # Adapt method call for fallback service
                    adapted_method = self._adapt_method_for_fallback(
                        method, fallback_service
                    )
                    
                    service_name, method_name = adapted_method.split('.')
                    service = getattr(client, service_name.lower())
                    rpc_method = getattr(service, method_name)
                    
                    result = await asyncio.wait_for(
                        rpc_method(**kwargs), 
                        timeout=self.strategy.fallback_timeout
                    )
                    
                    print(f" Fallback service {i+1} succeeded")
                    self.fallback_statistics["fallback_successes"] += 1
                    return result
                    
            except Exception as e:
                print(f"=á Fallback service {i+1} failed: {e}")
                continue
        
        return None
    
    def _adapt_method_for_fallback(self, original_method: str, fallback_service: str) -> str:
        """Adapt method call for different fallback service."""
        
        # Simple mapping - in real implementation this could be more sophisticated
        method_mappings = {
            "calculator.Add": {
                "simple_math.SimpleMath": "simple_math.Add",
                "basic_calc.BasicCalculator": "basic_calc.Add"
            },
            "calculator.Multiply": {
                "simple_math.SimpleMath": "simple_math.Multiply", 
                "basic_calc.BasicCalculator": "basic_calc.Multiply"
            }
        }
        
        if original_method in method_mappings:
            if fallback_service in method_mappings[original_method]:
                return method_mappings[original_method][fallback_service]
        
        # Default: try same method on fallback service
        _, method_name = original_method.split('.')
        fallback_service_name = fallback_service.split('.')[-1].lower()
        return f"{fallback_service_name}.{method_name}"
    
    def _generate_cache_key(self, method: str, kwargs: dict) -> str:
        """Generate cache key for method and parameters."""
        
        # Simple cache key generation
        import hashlib
        
        key_data = f"{method}:{sorted(kwargs.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _update_cache(self, cache_key: str, value: Any):
        """Update cache with new value."""
        
        if not self.strategy.enable_caching:
            return
        
        self.cache[cache_key] = (value, time.time())
    
    def _get_cached_response(self, cache_key: str) -> Optional[Any]:
        """Get response from cache if available and fresh."""
        
        if not self.strategy.enable_caching:
            return None
        
        if cache_key not in self.cache:
            return None
        
        value, timestamp = self.cache[cache_key]
        
        # Check if cache is still valid
        if time.time() - timestamp > self.strategy.cache_duration:
            del self.cache[cache_key]
            return None
        
        return value
    
    def _get_default_response(self, method: str, **kwargs) -> Optional[Any]:
        """Generate default response for method."""
        
        if not self.strategy.enable_default_responses:
            return None
        
        # Method-specific default responses
        if method == "calculator.Add":
            # For calculator.Add, return sum of inputs or 0
            return type('AddResponse', (), {
                'result': kwargs.get('a', 0) + kwargs.get('b', 0)
            })()
        
        elif method == "calculator.Multiply":
            # For calculator.Multiply, return product or 1
            return type('MultiplyResponse', (), {
                'result': kwargs.get('a', 1) * kwargs.get('b', 1)
            })()
        
        elif method.startswith("status."):
            # For status methods, return healthy
            return type('StatusResponse', (), {
                'status': 'degraded',
                'message': 'Running in degraded mode'
            })()
        
        # No default available
        return None
    
    def get_degradation_stats(self) -> dict[str, Any]:
        """Get graceful degradation statistics."""
        
        total_calls = self.fallback_statistics["primary_calls"] + self.fallback_statistics["fallback_calls"]
        total_successes = self.fallback_statistics["primary_successes"] + self.fallback_statistics["fallback_successes"]
        
        return {
            **self.fallback_statistics,
            "total_calls": total_calls,
            "total_successes": total_successes,
            "overall_success_rate": total_successes / max(1, total_calls),
            "primary_success_rate": (
                self.fallback_statistics["primary_successes"] / 
                max(1, self.fallback_statistics["primary_calls"])
            ),
            "cache_entries": len(self.cache)
        }

# Usage example
async def graceful_degradation_example():
    """Demonstrate graceful degradation."""
    
    strategy = FallbackStrategy(
        primary_command=["python", "advanced_calculator.py"],
        primary_service="calculator.Calculator",
        fallback_commands=[
            ["python", "simple_calculator.py"],
            ["python", "basic_math.py"]
        ],
        fallback_services=[
            "simple_calc.SimpleCalculator", 
            "basic_math.BasicMath"
        ],
        enable_caching=True,
        cache_duration=60.0,
        enable_default_responses=True,
        max_fallback_attempts=2,
        fallback_timeout=3.0
    )
    
    client = GracefulDegradationClient(strategy)
    
    # Test various scenarios
    test_calls = [
        ("calculator.Add", {"a": 10, "b": 5}),
        ("calculator.Multiply", {"a": 4, "b": 3}),
        ("calculator.Add", {"a": 10, "b": 5}),  # Should hit cache
        ("calculator.Divide", {"a": 20, "b": 4}),
        ("status.Health", {}),
    ]
    
    for i, (method, kwargs) in enumerate(test_calls):
        try:
            result = await client.resilient_call(method, **kwargs)
            print(f" Call {i+1}: {method} = {getattr(result, 'result', getattr(result, 'status', result))}")
        except Exception as e:
            print(f"L Call {i+1}: {method} failed completely: {e}")
        
        await asyncio.sleep(1)
    
    # Show degradation statistics
    stats = client.get_degradation_stats()
    print(f"\n=Ê Degradation Statistics:")
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2f}")
        else:
            print(f"  {key}: {value}")

# Usage
await graceful_degradation_example()
```

## Testing Retry Logic

### Retry Logic Testing

```python
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from pyvider.rpcplugin.exception import TransportError, RPCPluginError

class TestRetryLogic:
    """Test suite for retry logic."""
    
    @pytest.mark.asyncio
    async def test_exponential_backoff_calculation(self):
        """Test exponential backoff delay calculation."""
        
        config = RetryConfig(
            base_delay=1.0,
            exponential_base=2.0,
            max_delay=10.0,
            jitter=False
        )
        
        backoff = ExponentialBackoff(config)
        
        # Test delay progression
        assert backoff.calculate_delay(0) == 1.0  # 1 * 2^0
        assert backoff.calculate_delay(1) == 2.0  # 1 * 2^1
        assert backoff.calculate_delay(2) == 4.0  # 1 * 2^2
        assert backoff.calculate_delay(3) == 8.0  # 1 * 2^3
        assert backoff.calculate_delay(4) == 10.0  # Capped at max_delay
    
    @pytest.mark.asyncio
    async def test_successful_retry_after_failures(self):
        """Test that retry succeeds after initial failures."""
        
        config = RetryConfig(max_retries=3, base_delay=0.1)
        backoff = ExponentialBackoff(config)
        
        call_count = 0
        
        async def flaky_operation():
            nonlocal call_count
            call_count += 1
            
            if call_count <= 2:  # Fail first 2 attempts
                raise TransportError("Connection failed")
            
            return "success"
        
        # Should succeed on 3rd attempt
        result = await backoff.retry(
            flaky_operation,
            retryable_exceptions=(TransportError,)
        )
        
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_exhaustion(self):
        """Test that retry gives up after max attempts."""
        
        config = RetryConfig(max_retries=2, base_delay=0.1)
        backoff = ExponentialBackoff(config)
        
        call_count = 0
        
        async def always_failing_operation():
            nonlocal call_count
            call_count += 1
            raise TransportError("Always fails")
        
        # Should fail after 3 attempts (initial + 2 retries)
        with pytest.raises(TransportError, match="Always fails"):
            await backoff.retry(
                always_failing_operation,
                retryable_exceptions=(TransportError,)
            )
        
        assert call_count == 3  # Initial + 2 retries
    
    @pytest.mark.asyncio
    async def test_non_retryable_exception(self):
        """Test that non-retryable exceptions are not retried."""
        
        config = RetryConfig(max_retries=3, base_delay=0.1)
        backoff = ExponentialBackoff(config)
        
        call_count = 0
        
        async def operation_with_non_retryable_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("Invalid input")  # Not in retryable_exceptions
        
        # Should fail immediately without retries
        with pytest.raises(ValueError, match="Invalid input"):
            await backoff.retry(
                operation_with_non_retryable_error,
                retryable_exceptions=(TransportError,)
            )
        
        assert call_count == 1  # No retries
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_after_failures(self):
        """Test circuit breaker opens after threshold failures."""
        
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=1.0,
            request_timeout=0.5
        )
        
        circuit_breaker = CircuitBreaker(config)
        
        async def failing_operation():
            raise Exception("Service unavailable")
        
        # First 2 failures should work (circuit closed)
        for i in range(2):
            with pytest.raises(Exception, match="Service unavailable"):
                await circuit_breaker.call(failing_operation)
        
        # Circuit should now be open
        assert circuit_breaker.state == CircuitState.OPEN
        
        # Next call should fail immediately (circuit open)
        with pytest.raises(Exception, match="Circuit breaker OPEN"):
            await circuit_breaker.call(failing_operation)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery after timeout."""
        
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1,  # Very short for testing
            success_threshold=1,
            request_timeout=1.0
        )
        
        circuit_breaker = CircuitBreaker(config)
        
        # Open the circuit
        async def failing_operation():
            raise Exception("Failure")
        
        for _ in range(2):
            with pytest.raises(Exception):
                await circuit_breaker.call(failing_operation)
        
        assert circuit_breaker.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(0.15)
        
        # Circuit should attempt reset to half-open
        async def succeeding_operation():
            return "success"
        
        result = await circuit_breaker.call(succeeding_operation)
        
        assert result == "success"
        assert circuit_breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio 
    async def test_retry_policy_grpc_codes(self):
        """Test retry policy with specific gRPC status codes."""
        
        policy = RetryPolicy(
            max_retries=2,
            base_delay=0.1,
            retryable_grpc_codes=[grpc.StatusCode.UNAVAILABLE],
            non_retryable_grpc_codes=[grpc.StatusCode.INVALID_ARGUMENT]
        )
        
        # Mock gRPC error that should be retried
        retryable_error = Mock(spec=grpc.aio.AioRpcError)
        retryable_error.code.return_value = grpc.StatusCode.UNAVAILABLE
        
        # Should retry this error
        assert policy.should_retry(retryable_error, attempt=0) == True
        
        # Mock gRPC error that should NOT be retried
        non_retryable_error = Mock(spec=grpc.aio.AioRpcError)
        non_retryable_error.code.return_value = grpc.StatusCode.INVALID_ARGUMENT
        
        # Should not retry this error
        assert policy.should_retry(non_retryable_error, attempt=0) == False
    
    @pytest.mark.asyncio
    async def test_timeout_management(self):
        """Test hierarchical timeout management."""
        
        config = TimeoutConfig(
            connection_timeout=0.5,
            request_timeout=0.3,
            total_timeout=1.0
        )
        
        timeout_manager = TimeoutManager(config)
        
        # Test connection timeout
        async def slow_connection():
            await asyncio.sleep(1.0)  # Slower than connection_timeout
            return "connected"
        
        with pytest.raises(asyncio.TimeoutError):
            await timeout_manager.with_connection_timeout(slow_connection)
        
        # Test request timeout
        async def slow_request():
            await asyncio.sleep(0.5)  # Slower than request_timeout
            return "response"
        
        with pytest.raises(asyncio.TimeoutError):
            await timeout_manager.with_request_timeout(slow_request)
        
        # Test total timeout
        async def slow_total():
            await asyncio.sleep(1.5)  # Slower than total_timeout
            return "done"
        
        with pytest.raises(asyncio.TimeoutError):
            await timeout_manager.with_total_timeout(slow_total)
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_fallback(self):
        """Test graceful degradation with fallback services."""
        
        strategy = FallbackStrategy(
            primary_command=["python", "primary.py"],
            primary_service="primary.Service",
            fallback_commands=[["python", "fallback.py"]],
            fallback_services=["fallback.Service"],
            enable_caching=False,
            enable_default_responses=True,
            max_fallback_attempts=1
        )
        
        client = GracefulDegradationClient(strategy)
        
        # Mock the client connections
        with patch('pyvider.rpcplugin.plugin_client') as mock_client:
            # Primary service fails
            mock_primary = AsyncMock()
            mock_primary.__aenter__.side_effect = Exception("Primary failed")
            
            # Fallback service succeeds
            mock_fallback = AsyncMock()
            mock_fallback_result = Mock()
            mock_fallback_result.result = 42
            
            mock_fallback_service = Mock()
            mock_fallback_service.Add = AsyncMock(return_value=mock_fallback_result)
            
            mock_fallback.__aenter__.return_value = Mock()
            mock_fallback.__aenter__.return_value.simple_calc = mock_fallback_service
            
            # Configure mock to return primary then fallback
            mock_client.side_effect = [mock_primary, mock_fallback]
            
            # Should use fallback service
            result = await client.resilient_call("calculator.Add", a=20, b=22)
            assert result.result == 42
            
            # Check statistics
            stats = client.get_degradation_stats()
            assert stats["primary_calls"] == 1
            assert stats["primary_successes"] == 0
            assert stats["fallback_successes"] == 1

# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

## Best Practices

### Production-Ready Retry Configuration

```python
import os
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class ProductionRetryConfig:
    """Production-ready retry configuration."""
    
    # Environment-based configuration
    @classmethod
    def from_environment(cls, service_name: str) -> 'ProductionRetryConfig':
        """Create config from environment variables."""
        
        prefix = f"RETRY_{service_name.upper()}_"
        
        return cls(
            # Basic retry settings
            max_retries=int(os.environ.get(f"{prefix}MAX_RETRIES", "3")),
            base_delay=float(os.environ.get(f"{prefix}BASE_DELAY", "1.0")),
            max_delay=float(os.environ.get(f"{prefix}MAX_DELAY", "60.0")),
            
            # Circuit breaker
            enable_circuit_breaker=os.environ.get(f"{prefix}CIRCUIT_BREAKER", "true").lower() == "true",
            failure_threshold=int(os.environ.get(f"{prefix}FAILURE_THRESHOLD", "5")),
            recovery_timeout=float(os.environ.get(f"{prefix}RECOVERY_TIMEOUT", "60.0")),
            
            # Timeouts
            connection_timeout=float(os.environ.get(f"{prefix}CONNECTION_TIMEOUT", "10.0")),
            request_timeout=float(os.environ.get(f"{prefix}REQUEST_TIMEOUT", "30.0")),
            total_timeout=float(os.environ.get(f"{prefix}TOTAL_TIMEOUT", "120.0")),
            
            # Degradation
            enable_graceful_degradation=os.environ.get(f"{prefix}GRACEFUL_DEGRADATION", "true").lower() == "true",
            enable_caching=os.environ.get(f"{prefix}CACHING", "true").lower() == "true",
            cache_duration=float(os.environ.get(f"{prefix}CACHE_DURATION", "300.0"))
        )

class ProductionRetryClient:
    """Production-ready retry client with comprehensive configuration."""
    
    def __init__(self, service_name: str, command: list[str]):
        self.service_name = service_name
        self.command = command
        
        # Load configuration from environment
        self.config = ProductionRetryConfig.from_environment(service_name)
        
        # Initialize components based on config
        self._setup_retry_components()
        
        # Monitoring
        self.metrics = {
            "total_calls": 0,
            "successful_calls": 0,
            "retried_calls": 0,
            "circuit_breaker_trips": 0,
            "cache_hits": 0,
            "fallback_uses": 0
        }
    
    def _setup_retry_components(self):
        """Setup retry components based on configuration."""
        
        # Retry policy
        self.retry_policy = RetryPolicy(
            max_retries=self.config.max_retries,
            base_delay=self.config.base_delay,
            max_delay=self.config.max_delay
        )
        
        # Circuit breaker (if enabled)
        if self.config.enable_circuit_breaker:
            circuit_config = CircuitBreakerConfig(
                failure_threshold=self.config.failure_threshold,
                recovery_timeout=self.config.recovery_timeout
            )
            self.circuit_breaker = CircuitBreaker(circuit_config)
        else:
            self.circuit_breaker = None
        
        # Timeout manager
        timeout_config = TimeoutConfig(
            connection_timeout=self.config.connection_timeout,
            request_timeout=self.config.request_timeout,
            total_timeout=self.config.total_timeout
        )
        self.timeout_manager = TimeoutManager(timeout_config)
        
        # Cache (if enabled)
        if self.config.enable_caching:
            self.cache = {}
        else:
            self.cache = None
    
    async def call(self, service_method: str, **kwargs) -> Any:
        """Make production call with full retry logic."""
        
        self.metrics["total_calls"] += 1
        
        # Check cache first
        if self.cache:
            cache_key = self._generate_cache_key(service_method, kwargs)
            cached_result = self._get_cached_result(cache_key)
            if cached_result is not None:
                self.metrics["cache_hits"] += 1
                return cached_result
        
        # Create the operation
        async def full_operation():
            async with plugin_client(command=self.command) as client:
                service_name, method_name = service_method.split('.')
                service = getattr(client, service_name.lower())
                method = getattr(service, method_name)
                
                return await method(**kwargs)
        
        # Apply timeouts
        async def timed_operation():
            return await self.timeout_manager.with_total_timeout(full_operation)
        
        # Apply circuit breaker if enabled
        if self.circuit_breaker:
            async def protected_operation():
                return await self.circuit_breaker.call(timed_operation)
            operation = protected_operation
        else:
            operation = timed_operation
        
        # Apply retry logic
        try:
            backoff = ExponentialBackoff(RetryConfig(
                max_retries=self.config.max_retries,
                base_delay=self.config.base_delay,
                max_delay=self.config.max_delay
            ))
            
            result = await backoff.retry(operation)
            
            # Cache successful result
            if self.cache:
                self._cache_result(cache_key, result)
            
            self.metrics["successful_calls"] += 1
            return result
            
        except Exception as e:
            # All retry attempts failed
            print(f"=¨ Production call failed after all retries: {e}")
            
            # Try graceful degradation if enabled
            if self.config.enable_graceful_degradation:
                fallback_result = self._get_fallback_result(service_method, **kwargs)
                if fallback_result is not None:
                    self.metrics["fallback_uses"] += 1
                    return fallback_result
            
            raise e
    
    def _generate_cache_key(self, service_method: str, kwargs: dict) -> str:
        """Generate cache key."""
        import hashlib
        key_data = f"{service_method}:{sorted(kwargs.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> Optional[Any]:
        """Get cached result if valid."""
        if not self.cache or cache_key not in self.cache:
            return None
        
        result, timestamp = self.cache[cache_key]
        if time.time() - timestamp > self.config.cache_duration:
            del self.cache[cache_key]
            return None
        
        return result
    
    def _cache_result(self, cache_key: str, result: Any):
        """Cache successful result."""
        if self.cache:
            self.cache[cache_key] = (result, time.time())
    
    def _get_fallback_result(self, service_method: str, **kwargs) -> Optional[Any]:
        """Get fallback result for graceful degradation."""
        
        # Simple fallback responses - customize per service
        fallback_responses = {
            "calculator.Add": lambda a, b: type('AddResponse', (), {'result': a + b})(),
            "status.Health": lambda **_: type('HealthResponse', (), {
                'status': 'degraded', 
                'message': 'Service in degraded mode'
            })(),
        }
        
        if service_method in fallback_responses:
            return fallback_responses[service_method](**kwargs)
        
        return None
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics."""
        
        base_metrics = self.metrics.copy()
        
        if self.circuit_breaker:
            base_metrics.update(self.circuit_breaker.get_stats())
        
        # Calculate success rate
        total_calls = base_metrics["total_calls"]
        if total_calls > 0:
            base_metrics["success_rate"] = base_metrics["successful_calls"] / total_calls
        else:
            base_metrics["success_rate"] = 0.0
        
        return base_metrics

# Usage example
async def production_retry_example():
    """Example of production retry client usage."""
    
    # Set environment variables for configuration
    os.environ.update({
        "RETRY_CALCULATOR_MAX_RETRIES": "5",
        "RETRY_CALCULATOR_BASE_DELAY": "0.5", 
        "RETRY_CALCULATOR_FAILURE_THRESHOLD": "3",
        "RETRY_CALCULATOR_CIRCUIT_BREAKER": "true",
        "RETRY_CALCULATOR_GRACEFUL_DEGRADATION": "true",
        "RETRY_CALCULATOR_CACHING": "true"
    })
    
    # Create production client
    client = ProductionRetryClient(
        service_name="calculator",
        command=["python", "production_calculator.py"]
    )
    
    try:
        # Make production calls
        for i in range(10):
            try:
                result = await client.call("calculator.Add", a=i, b=i*2)
                print(f" Call {i}: {i} + {i*2} = {result.result}")
            except Exception as e:
                print(f"L Call {i} failed: {e}")
            
            await asyncio.sleep(0.5)
        
        # Show production metrics
        metrics = client.get_metrics()
        print(f"\n=Ê Production Metrics:")
        for key, value in metrics.items():
            if isinstance(value, float):
                print(f"  {key}: {value:.2f}")
            else:
                print(f"  {key}: {value}")
    
    finally:
        # Cleanup would go here in real production
        pass

# Usage
await production_retry_example()
```

## Next Steps

- **[Connection Management](connections.md)** - Master connection lifecycle and pooling patterns
- **[Direct Connections](direct-connections.md)** - Connect to existing servers with service discovery
- **[Basic Client Setup](basic-setup.md)** - Review client fundamentals and configuration