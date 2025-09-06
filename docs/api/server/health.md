# Health Servicer API

The Health Servicer provides basic health check functionality for RPC services, implementing the gRPC Health Checking Protocol.

## Overview

The `HealthServicer` class implements basic health monitoring by:

- **Application Health Checking** - Monitors main application health status
- **Service Status Reporting** - Reports health for specific service names
- **Standard Protocol** - Compatible with gRPC health checking protocol

## Class Reference

### `HealthServicer`

```python
from pyvider.rpcplugin.health_servicer import HealthServicer
from grpc_health.v1 import health_pb2, health_pb2_grpc

class HealthServicer(health_pb2_grpc.HealthServicer):
    """gRPC Health Check servicer implementation."""
```

#### Constructor

```python
def __init__(
    self,
    app_is_healthy_callable: Callable[[], bool],
    service_name: str = ""
)
```

**Parameters:**
- `app_is_healthy_callable` (Callable[[], bool]): Function that returns True if the application is healthy
- `service_name` (str): Name of the primary service this health checker monitors (empty string means overall server)

**Example:**
```python
def is_app_healthy() -> bool:
    """Check if the application is healthy."""
    try:
        # Your application health logic here
        return True  # or False if unhealthy
    except Exception:
        return False

health_servicer = HealthServicer(
    app_is_healthy_callable=is_app_healthy,
    service_name="MyPluginService"
)
```

### Methods

#### `Check`

```python
async def Check(
    self, 
    request: health_pb2.HealthCheckRequest, 
    context: grpc.aio.ServicerContext
) -> health_pb2.HealthCheckResponse
```

Perform health check for the monitored service or overall system health.

**Parameters:**
- `request`: Health check request with optional service name
- `context`: gRPC service context

**Returns:**
- `HealthCheckResponse`: Health status based on the `app_is_healthy_callable` result

**Response Status Values:**
- `SERVING`: Application is healthy (app_is_healthy_callable returns True)
- `NOT_SERVING`: Application is unhealthy (app_is_healthy_callable returns False)
- Returns `NOT_FOUND` error if requested service doesn't match the configured service name

**Example:**
```python
# Check overall health (empty service name)
request = health_pb2.HealthCheckRequest()
response = await health_servicer.Check(request, context)

# Check specific service
request = health_pb2.HealthCheckRequest(service="MyPluginService")
response = await health_servicer.Check(request, context)
```

#### `Watch`

```python
async def Watch(
    self, 
    request: health_pb2.HealthCheckRequest, 
    context: grpc.aio.ServicerContext
) -> AsyncIterator[health_pb2.HealthCheckResponse]
```

**⚠️ NOT IMPLEMENTED**: This method always returns `UNIMPLEMENTED` error.

The Watch method for streaming health status updates is not implemented in the current version.

**Current Behavior:**
- Always raises `grpc.StatusCode.UNIMPLEMENTED`
- Does not provide streaming health updates

For continuous health monitoring, use repeated `Check` calls instead.

**Parameters:**
- `service_name` (str): Name of the service to remove

#### `get_health_summary`

```python
async def get_health_summary(self) -> dict[str, Any]
```

Get comprehensive health summary including all services and dependencies.

**Returns:**
- `dict[str, Any]`: Health summary with detailed status information

**Example:**
```python
summary = await health_servicer.get_health_summary()
print(f"Overall healthy: {summary['healthy']}")
print(f"Services: {summary['services']}")
print(f"Dependencies: {summary['dependencies']}")
```

## Enums and Types

### `HealthStatus`

```python
from enum import Enum

class HealthStatus(Enum):
    """Health status enumeration."""
    UNKNOWN = 0
    SERVING = 1
    NOT_SERVING = 2
```

### `DependencyCheck`

```python
from typing import Protocol

class DependencyCheck(Protocol):
    """Protocol for dependency health checkers."""
    
    async def __call__(self) -> bool:
        """Check dependency health.
        
        Returns:
            bool: True if dependency is healthy, False otherwise
        """
        ...
```

## Integration Examples

### Basic Server Setup

```python
import asyncio
import grpc
from grpc_health.v1 import health_pb2_grpc
from pyvider.server import RPCPluginServer
from pyvider.health import HealthServicer
from pyvider.config import ServerConfig

async def create_server_with_health_checks():
    """Create server with health monitoring."""
    
    # Define dependency checkers
    async def check_database() -> bool:
        try:
            # Database connectivity check
            async with get_db_connection() as conn:
                await conn.fetchval('SELECT 1')
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def check_external_api() -> bool:
        try:
            # External API health check
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.example.com/health', timeout=5) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"External API health check failed: {e}")
            return False
    
    # Create health servicer
    health_servicer = HealthServicer(
        dependencies={
            'database': check_database,
            'external_api': check_external_api
        },
        check_interval=30
    )
    
    # Create server
    config = ServerConfig()
    server = RPCPluginServer(config)
    
    # Add health service
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server._server)
    
    # Add business services
    user_service = UserServicer()
    server.add_service(user_service)
    
    return server

async def main():
    server = await create_server_with_health_checks()
    
    try:
        await server.start()
        print("Server with health checks started")
        
        # Keep server running
        await asyncio.Event().wait()
    
    except KeyboardInterrupt:
        print("Shutting down...")
    
    finally:
        await server.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

### Custom Health Checks

```python
from pyvider.health import HealthServicer, HealthStatus
import asyncio
import time

class CustomHealthServicer(HealthServicer):
    """Custom health servicer with additional checks."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.startup_time = time.time()
        self.min_uptime = 60  # Minimum uptime before considering healthy
    
    async def Check(self, request, context):
        """Enhanced health check with warmup period."""
        
        # Check if service has been running long enough
        uptime = time.time() - self.startup_time
        if uptime < self.min_uptime:
            return health_pb2.HealthCheckResponse(
                status=health_pb2.HealthCheckResponse.NOT_SERVING
            )
        
        # Perform standard health checks
        response = await super().Check(request, context)
        
        # Add custom checks
        if response.status == health_pb2.HealthCheckResponse.SERVING:
            # Additional custom validation
            if not await self._check_custom_metrics():
                response.status = health_pb2.HealthCheckResponse.NOT_SERVING
        
        return response
    
    async def _check_custom_metrics(self) -> bool:
        """Check custom application metrics."""
        try:
            # Example: Check memory usage
            import psutil
            process = psutil.Process()
            memory_percent = process.memory_percent()
            
            if memory_percent > 90:  # Over 90% memory usage
                logger.warning(f"High memory usage: {memory_percent}%")
                return False
            
            # Example: Check request queue size
            if hasattr(self, 'request_queue') and len(self.request_queue) > 1000:
                logger.warning("Request queue is full")
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Custom health check failed: {e}")
            return False
```

### Health Check Client

```python
import asyncio
import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

class HealthClient:
    """Client for health check monitoring."""
    
    def __init__(self, target: str):
        self.channel = grpc.aio.insecure_channel(target)
        self.stub = health_pb2_grpc.HealthStub(self.channel)
    
    async def check_service(self, service_name: str = "") -> bool:
        """Check if service is healthy."""
        try:
            request = health_pb2.HealthCheckRequest(service=service_name)
            response = await self.stub.Check(request)
            
            return response.status == health_pb2.HealthCheckResponse.SERVING
        
        except grpc.RpcError as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def monitor_service(self, service_name: str = ""):
        """Monitor service health continuously."""
        try:
            request = health_pb2.HealthCheckRequest(service=service_name)
            
            async for response in self.stub.Watch(request):
                status_name = health_pb2.HealthCheckResponse.ServingStatus.Name(response.status)
                print(f"Service '{service_name}' status: {status_name}")
                
                if response.status == health_pb2.HealthCheckResponse.NOT_SERVING:
                    # Handle unhealthy service
                    await self._handle_unhealthy_service(service_name)
        
        except grpc.RpcError as e:
            logger.error(f"Health monitoring failed: {e}")
    
    async def _handle_unhealthy_service(self, service_name: str):
        """Handle unhealthy service detection."""
        # Implement recovery logic
        logger.warning(f"Service {service_name} is unhealthy - initiating recovery")
    
    async def close(self):
        """Close the health client."""
        await self.channel.close()

# Usage example
async def monitor_services():
    health_client = HealthClient("localhost:50051")
    
    try:
        # Check overall health
        is_healthy = await health_client.check_service()
        print(f"Overall service health: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        # Monitor specific service
        await health_client.monitor_service("user-service")
    
    finally:
        await health_client.close()
```

### Kubernetes Integration

```yaml
# Kubernetes deployment with health checks
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pyvider-service
spec:
  template:
    spec:
      containers:
      - name: service
        image: pyvider-service:latest
        ports:
        - containerPort: 50051
        livenessProbe:
          exec:
            command: ["/bin/grpc_health_probe", "-addr=:50051"]
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command: ["/bin/grpc_health_probe", "-addr=:50051", "-service=user-service"]
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Best Practices

### 1. Comprehensive Health Checks

```python
# Include all critical dependencies
dependencies = {
    'database': check_database_connection,
    'cache': check_redis_connection, 
    'external_api': check_external_services,
    'storage': check_file_system_access,
    'queue': check_message_queue
}

health_servicer = HealthServicer(
    services=[service1, service2],
    dependencies=dependencies,
    check_interval=30
)
```

### 2. Graceful Degradation

```python
async def check_database_with_fallback() -> bool:
    """Database check with graceful degradation."""
    try:
        # Primary database
        await check_primary_database()
        return True
    except Exception:
        try:
            # Fallback to read replica
            await check_read_replica()
            return True
        except Exception:
            # Complete database failure
            return False
```

### 3. Health Check Timeouts

```python
async def check_with_timeout(check_func: Callable, timeout: int = 5) -> bool:
    """Wrapper to add timeouts to health checks."""
    try:
        return await asyncio.wait_for(check_func(), timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(f"Health check timed out after {timeout}s")
        return False
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False
```

### 4. Circuit Breaker Integration

```python
class CircuitBreakerHealthCheck:
    """Health check with circuit breaker pattern."""
    
    def __init__(self, check_func: Callable, failure_threshold: int = 3):
        self.check_func = check_func
        self.failure_threshold = failure_threshold
        self.failure_count = 0
        self.last_check_time = 0
        self.circuit_open = False
    
    async def __call__(self) -> bool:
        current_time = time.time()
        
        # Reset circuit after timeout
        if self.circuit_open and current_time - self.last_check_time > 60:
            self.circuit_open = False
            self.failure_count = 0
        
        if self.circuit_open:
            return False
        
        try:
            result = await self.check_func()
            if result:
                self.failure_count = 0
            else:
                self.failure_count += 1
                if self.failure_count >= self.failure_threshold:
                    self.circuit_open = True
            
            self.last_check_time = current_time
            return result
        
        except Exception:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.circuit_open = True
            
            self.last_check_time = current_time
            return False
```

The Health Servicer API provides robust health monitoring capabilities that integrate seamlessly with container orchestration platforms and monitoring systems, ensuring your RPC services maintain high availability and reliability.