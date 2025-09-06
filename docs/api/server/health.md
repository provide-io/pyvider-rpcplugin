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

## Usage Example

```python
from pyvider.rpcplugin.health_servicer import HealthServicer
from grpc_health.v1 import health_pb2_grpc
import grpc

# Define your application health check
def is_my_app_healthy() -> bool:
    """Check if your application is healthy."""
    # Add your application-specific health checks here
    # For example: database connections, file system access, etc.
    return True

# Create health servicer
health_servicer = HealthServicer(
    app_is_healthy_callable=is_my_app_healthy,
    service_name="MyPluginService"
)

# Add to gRPC server (example)
server = grpc.aio.server()
health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
```

## Client Usage

```python
import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

async def check_server_health(target: str):
    """Check if the server is healthy."""
    channel = grpc.aio.insecure_channel(target)
    stub = health_pb2_grpc.HealthStub(channel)
    
    try:
        request = health_pb2.HealthCheckRequest()
        response = await stub.Check(request)
        return response.status == health_pb2.HealthCheckResponse.SERVING
    except grpc.RpcError:
        return False
    finally:
        await channel.close()
```

The `HealthServicer` provides basic but essential health checking functionality compatible with standard gRPC health checking tools and platforms.