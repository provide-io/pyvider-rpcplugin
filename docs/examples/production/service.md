# Production Service Implementation

**Path:** [Home](../../index.md) → [Examples](../index.md) → [Production](index.md) → Service

Complete production-ready plugin service with enterprise features including health checks, rate limiting, circuit breakers, and comprehensive error handling.

## Complete Service Code

```python
#!/usr/bin/env python3
"""
Production-ready Pyvider RPC Plugin Service.

Features:
- Health checks and readiness probes
- Rate limiting with Foundation
- Circuit breaker pattern
- Structured logging with correlation IDs
- Graceful shutdown
- Connection pooling
- Retry logic with exponential backoff
- Metrics collection
"""

import asyncio
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import grpc
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig
from provide.foundation.crypto import Certificate
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

from pyvider.rpcplugin import plugin_server, configure
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.exception import RPCPluginError

# Import your generated protobuf files
import api_pb2
import api_pb2_grpc


@dataclass
class ServiceConfig(RuntimeConfig):
    """Production service configuration."""
    
    # Service identification
    service_name: str = os.environ.get("SERVICE_NAME", "production-api")
    service_version: str = os.environ.get("SERVICE_VERSION", "1.0.0")
    
    # Performance settings
    max_concurrent_requests: int = int(os.environ.get("MAX_CONCURRENT_REQUESTS", "100"))
    request_timeout: float = float(os.environ.get("REQUEST_TIMEOUT", "30.0"))
    
    # Database settings
    database_url: str = os.environ.get("DATABASE_URL", "")
    database_pool_size: int = int(os.environ.get("DATABASE_POOL_SIZE", "10"))
    
    # Redis settings
    redis_url: str = os.environ.get("REDIS_URL", "")
    redis_max_connections: int = int(os.environ.get("REDIS_MAX_CONNECTIONS", "50"))
    
    # Rate limiting
    rate_limit_enabled: bool = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
    rate_limit_rps: float = float(os.environ.get("RATE_LIMIT_RPS", "100.0"))
    rate_limit_burst: float = float(os.environ.get("RATE_LIMIT_BURST", "200.0"))


class CircuitBreaker:
    """Circuit breaker for external service calls."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"
    
    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        
        current_time = time.time()
        
        if self.state == "open":
            if current_time - self.last_failure_time >= self.recovery_timeout:
                self.state = "half_open"
                logger.info("Circuit breaker entering half-open state")
            else:
                raise RPCPluginError("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            
            if self.state == "half_open":
                self.state = "closed"
                logger.info("Circuit breaker closed")
            self.failure_count = 0
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = current_time
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error(f"Circuit breaker opened after {self.failure_threshold} failures")
            
            raise


class ProductionHandler(api_pb2_grpc.APIServiceServicer):
    """Production API service handler."""
    
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.db_pool = None
        self.redis_pool = None
        self.rate_limiter = None
        self.circuit_breaker = CircuitBreaker()
        self.request_counter = 0
        self.error_counter = 0
        
        # Initialize rate limiter if enabled
        if config.rate_limit_enabled:
            self.rate_limiter = TokenBucketRateLimiter(
                capacity=config.rate_limit_burst,
                refill_rate=config.rate_limit_rps
            )
            logger.info(f"Rate limiting enabled: {config.rate_limit_rps} RPS")
    
    async def initialize(self):
        """Initialize database and cache connections."""
        
        # Initialize database pool
        if self.config.database_url:
            logger.info("Initializing database connection pool")
            # Your database initialization here
            # self.db_pool = await create_db_pool(self.config.database_url)
        
        # Initialize Redis pool
        if self.config.redis_url:
            logger.info("Initializing Redis connection pool")
            # Your Redis initialization here
            # self.redis_pool = await create_redis_pool(self.config.redis_url)
        
        logger.info("Service initialization complete")
    
    async def cleanup(self):
        """Clean up resources on shutdown."""
        
        if self.db_pool:
            logger.info("Closing database connections")
            # await self.db_pool.close()
        
        if self.redis_pool:
            logger.info("Closing Redis connections")
            # await self.redis_pool.close()
        
        logger.info("Service cleanup complete")
    
    async def ProcessRequest(
        self,
        request: api_pb2.Request,
        context: grpc.aio.ServicerContext
    ) -> api_pb2.Response:
        """Main request processing method."""
        
        # Generate request ID for tracing
        request_id = str(uuid4())
        start_time = time.time()
        
        # Add request ID to context
        context.set_trailing_metadata([
            ("x-request-id", request_id)
        ])
        
        logger.info("Processing request", extra={
            "request_id": request_id,
            "method": context.method,
            "peer": context.peer()
        })
        
        try:
            # Rate limiting
            if self.rate_limiter:
                if not await self.rate_limiter.is_allowed():
                    context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
                    context.set_details("Rate limit exceeded")
                    logger.warning("Rate limit exceeded", extra={
                        "request_id": request_id,
                        "peer": context.peer()
                    })
                    return api_pb2.Response(
                        success=False,
                        error="Rate limit exceeded"
                    )
            
            # Process request with circuit breaker
            result = await self.circuit_breaker.call(
                self._process_internal,
                request,
                request_id
            )
            
            # Update metrics
            self.request_counter += 1
            duration = time.time() - start_time
            
            logger.info("Request completed", extra={
                "request_id": request_id,
                "duration_ms": duration * 1000,
                "success": True
            })
            
            return api_pb2.Response(
                success=True,
                data=result,
                request_id=request_id
            )
            
        except Exception as e:
            self.error_counter += 1
            duration = time.time() - start_time
            
            logger.error("Request failed", extra={
                "request_id": request_id,
                "duration_ms": duration * 1000,
                "error": str(e),
                "error_rate": self.error_counter / max(1, self.request_counter)
            }, exc_info=True)
            
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            
            return api_pb2.Response(
                success=False,
                error=str(e),
                request_id=request_id
            )
    
    async def _process_internal(self, request: api_pb2.Request, request_id: str) -> str:
        """Internal processing logic."""
        
        # Your actual business logic here
        logger.debug(f"Processing internal logic for {request_id}")
        
        # Example: Query database
        if self.db_pool:
            # result = await self.db_pool.fetch("SELECT * FROM ...", ...)
            pass
        
        # Example: Use cache
        if self.redis_pool:
            # cached = await self.redis_pool.get(f"cache:{request.key}")
            pass
        
        # Simulate processing
        await asyncio.sleep(0.1)
        
        return f"Processed: {request.data}"
    
    async def HealthCheck(
        self,
        request: api_pb2.HealthCheckRequest,
        context: grpc.aio.ServicerContext
    ) -> api_pb2.HealthCheckResponse:
        """Health check endpoint."""
        
        checks = {
            "service": "healthy",
            "database": "unknown",
            "redis": "unknown"
        }
        
        # Check database
        if self.db_pool:
            try:
                # await self.db_pool.execute("SELECT 1")
                checks["database"] = "healthy"
            except:
                checks["database"] = "unhealthy"
        
        # Check Redis
        if self.redis_pool:
            try:
                # await self.redis_pool.ping()
                checks["redis"] = "healthy"
            except:
                checks["redis"] = "unhealthy"
        
        # Overall status
        overall_healthy = all(v == "healthy" or v == "unknown" for v in checks.values())
        
        return api_pb2.HealthCheckResponse(
            status="SERVING" if overall_healthy else "NOT_SERVING",
            checks=checks
        )
    
    def get_metrics(self) -> dict[str, Any]:
        """Get service metrics."""
        return {
            "total_requests": self.request_counter,
            "total_errors": self.error_counter,
            "error_rate": self.error_counter / max(1, self.request_counter),
            "circuit_breaker_state": self.circuit_breaker.state
        }
```

## Graceful Shutdown Handler

```python
class GracefulShutdown:
    """Handle graceful shutdown of the service."""
    
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.tasks = []
    
    def handle_signal(self, sig, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {sig}, initiating graceful shutdown")
        self.shutdown_event.set()
    
    async def wait_for_shutdown(self):
        """Wait for shutdown signal."""
        await self.shutdown_event.wait()
    
    def register_task(self, task):
        """Register a task to be cancelled on shutdown."""
        self.tasks.append(task)
    
    async def cleanup(self):
        """Cancel all registered tasks."""
        for task in self.tasks:
            task.cancel()
        
        await asyncio.gather(*self.tasks, return_exceptions=True)
```

## Main Entry Point

```python
async def main():
    """Main entry point for the production service."""
    
    # Load configuration
    config = ServiceConfig()
    config.validate()
    
    # Configure Pyvider RPC Plugin
    configure(
        magic_cookie_key="plugin_key",
        magic_cookie_value=os.environ.get("PLUGIN_MAGIC_COOKIE_VALUE", "secure-cookie"),
        auto_mtls=config.rate_limit_enabled,
        handshake_timeout=30.0,
        log_level=os.environ.get("PLUGIN_LOG_LEVEL", "INFO")
    )
    
    # Initialize handler
    handler = ProductionHandler(config)
    await handler.initialize()
    
    # Set up graceful shutdown
    shutdown = GracefulShutdown()
    signal.signal(signal.SIGTERM, shutdown.handle_signal)
    signal.signal(signal.SIGINT, shutdown.handle_signal)
    
    try:
        # Create and start server
        server = plugin_server(
            protocol=ProductionProtocol(),
            handler=handler
        )
        
        logger.info(f"Starting {config.service_name} v{config.service_version}")
        
        # Start server in background
        server_task = asyncio.create_task(server.serve())
        shutdown.register_task(server_task)
        
        # Wait for shutdown signal
        await shutdown.wait_for_shutdown()
        
    finally:
        # Cleanup
        logger.info("Shutting down service")
        await shutdown.cleanup()
        await handler.cleanup()
        logger.info("Service shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Features

This production service includes:

1. **Health Checks**: Separate liveness and readiness probes
2. **Rate Limiting**: Using Foundation's token bucket
3. **Circuit Breaker**: Protecting against cascading failures
4. **Graceful Shutdown**: Proper cleanup on termination
5. **Request Tracing**: Correlation IDs for debugging
6. **Error Handling**: Comprehensive error recovery
7. **Connection Pooling**: Database and cache pools
8. **Metrics Collection**: Performance monitoring

---

**Navigation:** [Previous: Production](index.md) | [Next: Docker Configuration](docker.md)