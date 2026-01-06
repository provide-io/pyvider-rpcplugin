# Middleware

Intercept and process RPC requests and responses with middleware for logging, authentication, rate limiting, and request transformation.

## Overview

Middleware in Pyvider RPC operates at the gRPC service level, providing a powerful way to implement cross-cutting concerns:

- **Logging** - Request/response logging for debugging
- **Authentication** - JWT validation and role-based access control
- **Rate Limiting** - Token bucket rate limiting per client
- **Transformation** - Request/response data modification
- **Error Handling** - Consistent error responses
- **Metrics** - Performance monitoring

## Basic Middleware

### Request Logging

```python
import asyncio
import logging
import time
from grpc.aio import ServicerInterceptor

logger = logging.getLogger(__name__)

class RequestLoggingInterceptor(ServicerInterceptor):
    """Logs all incoming RPC requests with timing."""

    async def intercept_service(self, continuation, handler_call_details):
        start_time = time.time()
        method = handler_call_details.method

        logger.info(f"RPC started: {method}")

        try:
            response = await continuation(handler_call_details)
            duration = time.time() - start_time
            logger.info(f"RPC completed: {method} ({duration:.3f}s)")
            return response
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"RPC failed: {method} ({duration:.3f}s) - {e}")
            raise
```

### Metrics Collection

```python
class MetricsInterceptor(ServicerInterceptor):
    """Collects performance metrics for RPC calls."""

    def __init__(self):
        self.request_count = 0
        self.error_count = 0
        self.total_duration = 0.0

    async def intercept_service(self, continuation, handler_call_details):
        self.request_count += 1
        start_time = time.time()

        try:
            response = await continuation(handler_call_details)
            duration = time.time() - start_time
            self.total_duration += duration
            return response
        except Exception:
            self.error_count += 1
            raise

    def get_metrics(self):
        return {
            "request_count": self.request_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(self.request_count, 1),
            "avg_duration": self.total_duration / max(self.request_count, 1),
        }
```

## Authentication Middleware

### JWT Authentication

```python
import jwt
from grpc import StatusCode
from grpc.aio import ServicerContext, ServicerInterceptor

class JWTAuthInterceptor(ServicerInterceptor):
    """Validates JWT tokens in RPC requests."""

    def __init__(self, secret_key: str, exempt_methods: set[str] | None = None):
        self.secret_key = secret_key
        self.exempt_methods = exempt_methods or set()

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method

        # Skip authentication for exempt methods
        if method in self.exempt_methods:
            return await continuation(handler_call_details)

        # Extract token from metadata
        context = handler_call_details.invocation_metadata
        auth_header = None

        for key, value in context.invocation_metadata():
            if key.lower() == 'authorization':
                auth_header = value
                break

        if not auth_header or not auth_header.startswith('Bearer '):
            await context.abort(StatusCode.UNAUTHENTICATED, 'Missing or invalid token')
            return

        token = auth_header[7:]  # Remove 'Bearer ' prefix

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            context.user_id = payload.get('user_id')
            context.permissions = payload.get('permissions', [])
        except jwt.InvalidTokenError as e:
            await context.abort(StatusCode.UNAUTHENTICATED, f'Invalid token: {e}')
            return

        return await continuation(handler_call_details)
```

### Role-Based Access Control

```python
class RoleBasedAuthInterceptor(ServicerInterceptor):
    """Enforces role-based access control."""

    def __init__(self, method_permissions: dict[str, set[str]]):
        self.method_permissions = method_permissions

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        context = handler_call_details.invocation_metadata

        # Check if method requires permissions
        required_perms = self.method_permissions.get(method, set())
        if not required_perms:
            return await continuation(handler_call_details)

        # Get user permissions from context (set by JWT middleware)
        user_perms = set(getattr(context, 'permissions', []))

        if not required_perms.intersection(user_perms):
            await context.abort(
                StatusCode.PERMISSION_DENIED,
                f'Insufficient permissions for {method}'
            )
            return

        return await continuation(handler_call_details)
```

## Rate Limiting

### Token Bucket Implementation

```python
import asyncio
import time
from collections import defaultdict

class TokenBucketRateLimiter:
    """Token bucket rate limiting implementation."""

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume tokens. Returns True if successful."""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill

            # Refill tokens based on elapsed time
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate
            )
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

class RateLimitingInterceptor(ServicerInterceptor):
    """Rate limits RPC calls per client."""

    def __init__(
        self,
        requests_per_second: int = 100,
        burst_capacity: int = 200,
        per_method: bool = False
    ):
        self.requests_per_second = requests_per_second
        self.burst_capacity = burst_capacity
        self.per_method = per_method
        self.limiters = defaultdict(
            lambda: TokenBucketRateLimiter(burst_capacity, requests_per_second)
        )

    def _get_client_key(self, context, method: str) -> str:
        """Generate client key for rate limiting."""
        peer = context.peer()

        if self.per_method:
            return f"{peer}:{method}"
        return peer

    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        context = handler_call_details.invocation_metadata

        client_key = self._get_client_key(context, method)
        limiter = self.limiters[client_key]

        if not await limiter.consume():
            await context.abort(
                StatusCode.RESOURCE_EXHAUSTED,
                'Rate limit exceeded'
            )
            return

        return await continuation(handler_call_details)
```

## Advanced Patterns

=== "Error Handling"

    ```python
    from grpc import StatusCode
    from pyvider.exceptions import (
        ValidationError,
        AuthenticationError,
        NotFoundError
    )

    class ErrorHandlingInterceptor(ServicerInterceptor):
        """Standardizes error handling across all RPC methods."""

        async def intercept_service(self, continuation, handler_call_details):
            context = handler_call_details.invocation_metadata

            try:
                return await continuation(handler_call_details)

            except ValidationError as e:
                await context.abort(StatusCode.INVALID_ARGUMENT, str(e))

            except AuthenticationError as e:
                await context.abort(StatusCode.UNAUTHENTICATED, str(e))

            except NotFoundError as e:
                await context.abort(StatusCode.NOT_FOUND, str(e))

            except Exception as e:
                logger.exception(f"Unexpected error in {handler_call_details.method}")
                await context.abort(StatusCode.INTERNAL, "Internal server error")
    ```

=== "Circuit Breaker"

    ```python
    class CircuitBreakerInterceptor(ServicerInterceptor):
        """Implements circuit breaker pattern."""

        def __init__(
            self,
            failure_threshold: int = 5,
            recovery_timeout: int = 60,
            expected_exception: type = Exception
        ):
            self.failure_threshold = failure_threshold
            self.recovery_timeout = recovery_timeout
            self.expected_exception = expected_exception

            self.failure_count = 0
            self.last_failure_time = None
            self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN

        async def intercept_service(self, continuation, handler_call_details):
            context = handler_call_details.invocation_metadata

            # Check circuit breaker state
            if self.state == 'OPEN':
                if (self.last_failure_time and
                    time.time() - self.last_failure_time > self.recovery_timeout):
                    self.state = 'HALF_OPEN'
                else:
                    await context.abort(
                        StatusCode.UNAVAILABLE,
                        'Service temporarily unavailable'
                    )
                    return

            try:
                response = await continuation(handler_call_details)

                # Reset on success
                if self.state == 'HALF_OPEN':
                    self.state = 'CLOSED'
                    self.failure_count = 0

                return response

            except self.expected_exception:
                self.failure_count += 1
                self.last_failure_time = time.time()

                if self.failure_count >= self.failure_threshold:
                    self.state = 'OPEN'

                raise
    ```

=== "Response Caching"

    ```python
    from google.protobuf.json_format import MessageToJson

    class ResponseCacheInterceptor(ServicerInterceptor):
        """Caches responses for idempotent operations."""

        def __init__(self, cache_ttl: int = 300):
            self.cache = {}
            self.cache_ttl = cache_ttl

        def _get_cache_key(self, method: str, request) -> str:
            request_json = MessageToJson(request)
            return f"{method}:{hash(request_json)}"

        async def intercept_service(self, continuation, handler_call_details):
            method = handler_call_details.method
            request = handler_call_details.request

            # Only cache GET-like operations
            if not method.endswith(('Get', 'List', 'Search')):
                return await continuation(handler_call_details)

            cache_key = self._get_cache_key(method, request)
            now = time.time()

            # Check cache
            if cache_key in self.cache:
                cached_response, timestamp = self.cache[cache_key]
                if now - timestamp < self.cache_ttl:
                    return cached_response
                else:
                    del self.cache[cache_key]

            # Execute request and cache result
            response = await continuation(handler_call_details)
            self.cache[cache_key] = (response, now)

            return response
    ```

## Server Integration

### Middleware Stack Configuration

```python
from pyvider.server import RPCPluginServer
from pyvider.config import ServerConfig

async def create_server_with_middleware():
    """Create server with comprehensive middleware stack."""

    # Create interceptors
    logging_interceptor = RequestLoggingInterceptor()
    metrics_interceptor = MetricsInterceptor()
    auth_interceptor = JWTAuthInterceptor(
        secret_key="<YOUR_SECRET_KEY>",
        exempt_methods={'/grpc.health.v1.Health/Check'}
    )
    rate_limit_interceptor = RateLimitingInterceptor(
        requests_per_second=100,
        burst_capacity=200
    )
    error_interceptor = ErrorHandlingInterceptor()
    circuit_breaker = CircuitBreakerInterceptor()

    # Configure server with middleware stack
    config = ServerConfig(
        host="localhost",
        port=50051,
        interceptors=[
            logging_interceptor,
            metrics_interceptor,
            rate_limit_interceptor,
            auth_interceptor,
            circuit_breaker,
            error_interceptor,  # Should be last
        ]
    )

    server = RPCPluginServer(config)
    return server, metrics_interceptor

# Usage
async def main():
    server, metrics = await create_server_with_middleware()

    try:
        await server.start()

        # Monitor metrics
        while True:
            await asyncio.sleep(30)
            print("Metrics:", metrics.get_metrics())

    except KeyboardInterrupt:
        await server.stop()
```

### Conditional Middleware

```python
class ConditionalMiddleware(ServicerInterceptor):
    """Applies middleware conditionally."""

    def __init__(self, condition, middleware):
        self.condition = condition
        self.middleware = middleware

    async def intercept_service(self, continuation, handler_call_details):
        if self.condition(handler_call_details):
            return await self.middleware.intercept_service(continuation, handler_call_details)
        return await continuation(handler_call_details)

# Example: Only apply auth to specific methods
def requires_auth(handler_call_details) -> bool:
    method = handler_call_details.method
    return not method.endswith(('Health/Check', 'Metrics'))

auth_middleware = ConditionalMiddleware(
    condition=requires_auth,
    middleware=JWTAuthInterceptor("<YOUR_SECRET_KEY>")
)
```

## Best Practices

### Performance

1. **Use connection pooling** for external services
2. **Cache expensive computations** with weak references
3. **Order middleware correctly** - auth before authorization
4. **Monitor performance** - track latency added by each middleware

### Security

1. **Validate middleware order** - authentication before authorization
2. **Sanitize log output** - don't log sensitive data
3. **Use secure defaults** - conservative rate limiting initially
4. **Implement proper cleanup** - release resources in destructors

### Error Handling

```python
class RobustMiddleware(ServicerInterceptor):
    """Template for robust middleware implementation."""

    async def intercept_service(self, continuation, handler_call_details):
        try:
            # Pre-processing logic
            await self._pre_process(handler_call_details)

            # Execute request
            response = await continuation(handler_call_details)

            # Post-processing logic
            await self._post_process(response)

            return response

        except Exception as e:
            logger.error(f"Middleware error: {e}")
            raise

        finally:
            await self._cleanup()

    async def _pre_process(self, handler_call_details):
        """Override in subclasses."""
        pass

    async def _post_process(self, response):
        """Override in subclasses."""
        pass

    async def _cleanup(self):
        """Override in subclasses."""
        pass
```

## Related Topics

- [Lifecycle Management](lifecycle.md) - Plugin lifecycle patterns
- [Observability](observability.md) - Metrics and tracing
- [Security](../security/index.md) - Authentication and authorization
- [Configuration](../config/configuration-guide.md) - Middleware configuration
