# Health Servicer API

The Health Servicer API provides standardized health check functionality for RPC services, implementing the gRPC Health Checking Protocol for service monitoring and readiness checks.

## Overview

The `HealthServicer` class implements basic health monitoring capabilities:

- **Application Health Checking** - Monitors main application health status via callback function
- **Service Status Reporting** - Reports health for specific service names  
- **Standard Protocol** - Compatible with gRPC Health Checking Protocol (grpc-health-v1)
- **Container Integration** - Works with Kubernetes health probes and Docker health checks
- **Monitoring Compatibility** - Integrates with standard monitoring tools

## Core Components

### `HealthServicer`

Main health check servicer implementing the gRPC health checking protocol.

```python
from pyvider.rpcplugin.health_servicer import HealthServicer
from grpc_health.v1 import health_pb2, health_pb2_grpc
from collections.abc import Callable

class HealthServicer(health_pb2_grpc.HealthServicer):
    """gRPC Health Check servicer implementation."""

    def __init__(
        self,
        app_is_healthy_callable: Callable[[], bool],
        service_name: str = ""
    ) -> None:
        """Initialize health servicer.
        
        Args:
            app_is_healthy_callable: Function returning True if application is healthy
            service_name: Primary service name (empty string means overall server)
        """
```

**Basic Usage:**
```python
def is_app_healthy() -> bool:
    try:
        # Your application-specific health checks here
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
) -> health_pb2.HealthCheckResponse:
```

Perform health check for the monitored service or overall system health.

**Response Status Values:**
- `SERVING`: Application is healthy
- `NOT_SERVING`: Application is unhealthy
- `NOT_FOUND`: Requested service doesn't match configured service name

#### `Watch`

**⚠️ NOT IMPLEMENTED**: Always returns `UNIMPLEMENTED` error. Use repeated `Check` calls for continuous monitoring.

## Integration Examples

### Server Integration

```python
import asyncio
import grpc
from pyvider.rpcplugin.health_servicer import HealthServicer
from grpc_health.v1 import health_pb2_grpc

class MyPluginService:
    def __init__(self):
        self.is_ready = False
        self.has_errors = False
    
    async def initialize(self):
        await asyncio.sleep(1)  # Simulate initialization
        self.is_ready = True
    
    def health_check(self) -> bool:
        return self.is_ready and not self.has_errors

async def main():
    service = MyPluginService()
    health_servicer = HealthServicer(
        app_is_healthy_callable=service.health_check,
        service_name="MyPluginService"
    )
    
    server = grpc.aio.server()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    
    listen_addr = "[::]:50051"
    server.add_insecure_port(listen_addr)
    await server.start()
    
    await service.initialize()
    
    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        await server.stop(5)

if __name__ == "__main__":
    asyncio.run(main())
```

### Database Health Check

```python
import time
import logging
from pyvider.rpcplugin.health_servicer import HealthServicer

logger = logging.getLogger(__name__)

class DatabaseHealthChecker:
    def __init__(self, db_connection_string: str):
        self.db_connection_string = db_connection_string
        self.last_check_time = 0
        self.last_check_result = False
        self.check_interval = 30  # Cache result for 30 seconds
    
    def is_healthy(self) -> bool:
        current_time = time.time()
        
        # Use cached result if recent
        if current_time - self.last_check_time < self.check_interval:
            return self.last_check_result
        
        try:
            self.last_check_result = self._check_database()
            self.last_check_time = current_time
            return self.last_check_result
        except Exception as e:
            logger.error(f"Database health check error: {e}")
            self.last_check_result = False
            self.last_check_time = current_time
            return False
    
    def _check_database(self) -> bool:
        try:
            import asyncpg
            conn = asyncpg.connect(self.db_connection_string)
            result = conn.fetchval("SELECT 1")
            conn.close()
            return result == 1
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False

# Usage
db_checker = DatabaseHealthChecker("postgresql://user:pass@localhost/db")
health_servicer = HealthServicer(
    app_is_healthy_callable=db_checker.is_healthy,
    service_name="DatabaseService"
)
```

### Composite Health Check

```python
from collections.abc import Callable

class CompositeHealthChecker:
    def __init__(self):
        self.checkers: dict[str, Callable[[], bool]] = {}
        self.require_all = True
    
    def add_checker(self, name: str, checker: Callable[[], bool]):
        self.checkers[name] = checker
    
    def is_healthy(self) -> bool:
        if not self.checkers:
            return True
        
        results = {}
        for name, checker in self.checkers.items():
            try:
                results[name] = checker()
            except Exception as e:
                logger.error(f"Health check '{name}' failed: {e}")
                results[name] = False
        
        return all(results.values()) if self.require_all else any(results.values())

# Usage
composite_checker = CompositeHealthChecker()
composite_checker.add_checker("database", db_checker.is_healthy)
composite_checker.add_checker("memory", lambda: psutil.virtual_memory().percent < 90)

health_servicer = HealthServicer(
    app_is_healthy_callable=composite_checker.is_healthy,
    service_name="CompositeService"
)
```

## Client Usage Examples

### Basic Health Check Client

```python
import asyncio
import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

class HealthClient:
    def __init__(self, target: str):
        self.target = target
        self.channel = None
        self.stub = None
    
    async def connect(self):
        self.channel = grpc.aio.insecure_channel(self.target)
        self.stub = health_pb2_grpc.HealthStub(self.channel)
    
    async def check_health(self, service: str = "") -> bool:
        if not self.stub:
            await self.connect()
        
        try:
            request = health_pb2.HealthCheckRequest(service=service)
            response = await self.stub.Check(request)
            return response.status == health_pb2.HealthCheckResponse.SERVING
        except grpc.RpcError:
            return False
    
    async def close(self):
        if self.channel:
            await self.channel.close()

# Usage
async def monitor_service():
    client = HealthClient("localhost:50051")
    try:
        is_healthy = await client.check_health("MyPluginService")
        print(f"Service healthy: {is_healthy}")
    finally:
        await client.close()

asyncio.run(monitor_service())
```

## Container Integration

### Kubernetes Health Probes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-plugin-service
spec:
  template:
    spec:
      containers:
      - name: plugin-service
        image: my-plugin:latest
        ports:
        - containerPort: 50051
          name: grpc
        livenessProbe:
          exec:
            command: ["/usr/local/bin/grpc_health_probe", "-addr=:50051"]
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command: ["/usr/local/bin/grpc_health_probe", "-addr=:50051", "-service=MyPluginService"]
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Docker Health Check

```dockerfile
FROM python:3.11-slim

# Install grpc_health_probe
RUN GRPC_HEALTH_PROBE_VERSION=v0.4.15 && \
    wget -qO/usr/local/bin/grpc_health_probe \
    https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /usr/local/bin/grpc_health_probe

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /usr/local/bin/grpc_health_probe -addr=localhost:50051 || exit 1

EXPOSE 50051
CMD ["python", "-m", "my_plugin.server"]
```

## Best Practices

### 1. Health Check Logic

Design comprehensive health checks:

```python
def comprehensive_health_check() -> bool:
    try:
        # Check critical dependencies first
        if not check_database():
            return False
        
        # Check resource availability  
        if not check_memory_usage():
            return False
        
        # Check application state
        return check_application_state()
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False

def check_memory_usage() -> bool:
    import psutil
    return psutil.virtual_memory().percent < 90
```

### 2. Graceful Startup/Shutdown

```python
class GracefulService:
    def __init__(self):
        self.startup_complete = False
        self.shutdown_started = False
    
    async def startup(self):
        await self._init_dependencies()
        self.startup_complete = True
    
    async def shutdown(self):
        self.shutdown_started = True
        await self._cleanup_connections()
    
    def is_healthy(self) -> bool:
        return self.startup_complete and not self.shutdown_started
```

### 3. Error Recovery

```python
class RecoveringHealthChecker:
    def __init__(self):
        self.consecutive_failures = 0
        self.recovery_attempted = False
    
    def is_healthy(self) -> bool:
        try:
            if self._perform_check():
                self.consecutive_failures = 0
                self.recovery_attempted = False
                return True
            else:
                self.consecutive_failures += 1
                return self._handle_failure()
        except Exception:
            self.consecutive_failures += 1
            return False
    
    def _handle_failure(self) -> bool:
        if self.consecutive_failures >= 3 and not self.recovery_attempted:
            self.recovery_attempted = True
            self._attempt_recovery()
        return False
```

## Configuration Options

### Environment Variables

Health servicer supports configuration through environment variables with the `PLUGIN_` prefix:

- `PLUGIN_HEALTH_CHECK_TIMEOUT`: Health check timeout in seconds (default: 5)
- `PLUGIN_HEALTH_LOG_LEVEL`: Logging level for health checks (default: INFO)

### Foundation Integration

The health servicer integrates with the Foundation logging system:

```python
from pyvider.foundation.logging import get_logger

logger = get_logger(__name__)

def my_health_check() -> bool:
    try:
        # Health check logic
        result = check_dependencies()
        logger.info(f"Health check result: {result}")
        return result
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False
```

## Future Improvements

Planned enhancements for enterprise-grade monitoring:

- **Watch Implementation**: Streaming health status updates
- **Metrics Integration**: Prometheus and Grafana dashboard support
- **Multi-Service Health**: Dependency health aggregation
- **Custom Protocols**: Plugin-specific health check extensions

## Quick Examples

For executable code samples:

- **[Health Check](../../examples/short/health-check.md)** - Basic health monitoring setup
- **[Basic Server](../../examples/short/basic-server.md)** - Server without health checks for comparison