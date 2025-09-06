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
from pyvider.rpcplugin.server import RPCPluginServer
from grpc_health.v1 import health_pb2_grpc

class MyPluginService:
    """Example plugin service with health monitoring."""
    
    def __init__(self):
        self.is_ready = False
        self.has_errors = False
    
    async def initialize(self):
        """Initialize the service."""
        # Simulate initialization
        await asyncio.sleep(1)
        self.is_ready = True
    
    def health_check(self) -> bool:
        """Custom health check logic."""
        if not self.is_ready:
            return False
        
        if self.has_errors:
            return False
        
        # Add more checks as needed
        return True

async def main():
    # Create service instance
    service = MyPluginService()
    
    # Create health servicer with custom health check
    health_servicer = HealthServicer(
        app_is_healthy_callable=service.health_check,
        service_name="MyPluginService"
    )
    
    # Create gRPC server
    server = grpc.aio.server()
    
    # Add health servicer to server
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    
    # Add other services...
    
    # Start server
    listen_addr = "[::]:50051"
    server.add_insecure_port(listen_addr)
    
    await server.start()
    print(f"Server started on {listen_addr}")
    
    # Initialize service after server starts
    await service.initialize()
    print("Service initialized and ready")
    
    # Keep server running
    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        print("Shutting down...")
        await server.stop(5)

if __name__ == "__main__":
    asyncio.run(main())
```

### Database Health Check

```python
import asyncio
import logging
from pyvider.rpcplugin.health_servicer import HealthServicer

logger = logging.getLogger(__name__)

class DatabaseHealthChecker:
    """Health checker with database connectivity."""
    
    def __init__(self, db_connection_string: str):
        self.db_connection_string = db_connection_string
        self.last_check_time = 0
        self.last_check_result = False
        self.check_interval = 30  # Cache result for 30 seconds
    
    def is_healthy(self) -> bool:
        """Check if database connection is healthy."""
        import time
        current_time = time.time()
        
        # Use cached result if recent
        if current_time - self.last_check_time < self.check_interval:
            return self.last_check_result
        
        # Perform actual health check
        try:
            self.last_check_result = self._check_database()
            self.last_check_time = current_time
            
            if self.last_check_result:
                logger.debug("Database health check: OK")
            else:
                logger.warning("Database health check: FAILED")
            
            return self.last_check_result
            
        except Exception as e:
            logger.error(f"Database health check error: {e}")
            self.last_check_result = False
            self.last_check_time = current_time
            return False
    
    def _check_database(self) -> bool:
        """Perform actual database connection test."""
        try:
            # Example for PostgreSQL with asyncpg
            import asyncpg
            
            # Note: This is a simplified example
            # In real code, you'd want to use connection pooling
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

### File System Health Check

```python
import os
import tempfile
from pathlib import Path

class FileSystemHealthChecker:
    """Health checker for file system access."""
    
    def __init__(self, required_paths: list[str]):
        self.required_paths = [Path(p) for p in required_paths]
    
    def is_healthy(self) -> bool:
        """Check file system health."""
        try:
            # Check required paths exist and are accessible
            for path in self.required_paths:
                if not path.exists():
                    logger.warning(f"Required path does not exist: {path}")
                    return False
                
                if path.is_dir():
                    # Check directory is writable
                    if not os.access(path, os.W_OK):
                        logger.warning(f"Directory not writable: {path}")
                        return False
                    
                    # Test write to directory
                    try:
                        with tempfile.NamedTemporaryFile(dir=path, delete=True):
                            pass
                    except OSError as e:
                        logger.warning(f"Cannot write to directory {path}: {e}")
                        return False
                
                elif path.is_file():
                    # Check file is readable
                    if not os.access(path, os.R_OK):
                        logger.warning(f"File not readable: {path}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"File system health check failed: {e}")
            return False

# Usage
fs_checker = FileSystemHealthChecker([
    "/app/data",
    "/app/logs", 
    "/app/config/settings.json"
])
health_servicer = HealthServicer(
    app_is_healthy_callable=fs_checker.is_healthy,
    service_name="FileSystemService"
)
```

### Composite Health Check

```python
class CompositeHealthChecker:
    """Composite health checker combining multiple checks."""
    
    def __init__(self):
        self.checkers = {}
        self.require_all = True
    
    def add_checker(self, name: str, checker: Callable[[], bool]):
        """Add a health checker."""
        self.checkers[name] = checker
    
    def set_require_all(self, require_all: bool):
        """Set whether all checks must pass (True) or any check can pass (False)."""
        self.require_all = require_all
    
    def is_healthy(self) -> bool:
        """Perform composite health check."""
        if not self.checkers:
            return True
        
        results = {}
        for name, checker in self.checkers.items():
            try:
                results[name] = checker()
            except Exception as e:
                logger.error(f"Health check '{name}' failed with exception: {e}")
                results[name] = False
        
        # Log results
        healthy_checks = [name for name, result in results.items() if result]
        unhealthy_checks = [name for name, result in results.items() if not result]
        
        if healthy_checks:
            logger.debug(f"Healthy checks: {', '.join(healthy_checks)}")
        if unhealthy_checks:
            logger.warning(f"Unhealthy checks: {', '.join(unhealthy_checks)}")
        
        # Determine overall health
        if self.require_all:
            return all(results.values())
        else:
            return any(results.values())

# Usage
composite_checker = CompositeHealthChecker()
composite_checker.add_checker("database", db_checker.is_healthy)
composite_checker.add_checker("filesystem", fs_checker.is_healthy)
composite_checker.add_checker("memory", lambda: psutil.virtual_memory().percent < 90)
composite_checker.set_require_all(True)

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
    """Client for checking service health."""
    
    def __init__(self, target: str):
        self.target = target
        self.channel = None
        self.stub = None
    
    async def connect(self):
        """Connect to the health service."""
        self.channel = grpc.aio.insecure_channel(self.target)
        self.stub = health_pb2_grpc.HealthStub(self.channel)
    
    async def check_health(self, service: str = "") -> bool:
        """Check if service is healthy."""
        if not self.stub:
            await self.connect()
        
        try:
            request = health_pb2.HealthCheckRequest(service=service)
            response = await self.stub.Check(request)
            return response.status == health_pb2.HealthCheckResponse.SERVING
            
        except grpc.RpcError as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def get_health_status(self, service: str = "") -> str:
        """Get detailed health status."""
        if not self.stub:
            await self.connect()
        
        try:
            request = health_pb2.HealthCheckRequest(service=service)
            response = await self.stub.Check(request)
            
            status_map = {
                health_pb2.HealthCheckResponse.SERVING: "SERVING",
                health_pb2.HealthCheckResponse.NOT_SERVING: "NOT_SERVING",
                health_pb2.HealthCheckResponse.SERVICE_UNKNOWN: "SERVICE_UNKNOWN"
            }
            
            return status_map.get(response.status, "UNKNOWN")
            
        except grpc.RpcError as e:
            return f"ERROR: {e}"
    
    async def close(self):
        """Close the connection."""
        if self.channel:
            await self.channel.close()

# Usage
async def monitor_service():
    client = HealthClient("localhost:50051")
    
    try:
        # Check overall health
        is_healthy = await client.check_health()
        print(f"Service healthy: {is_healthy}")
        
        # Check specific service
        status = await client.get_health_status("MyPluginService")
        print(f"Service status: {status}")
        
    finally:
        await client.close()

asyncio.run(monitor_service())
```

### Continuous Health Monitoring

```python
import asyncio
import logging
from datetime import datetime

class HealthMonitor:
    """Continuous health monitoring for services."""
    
    def __init__(self, targets: list[str], check_interval: int = 30):
        self.targets = targets
        self.check_interval = check_interval
        self.clients = {}
        self.running = False
    
    async def start(self):
        """Start health monitoring."""
        # Create clients
        for target in self.targets:
            self.clients[target] = HealthClient(target)
            await self.clients[target].connect()
        
        self.running = True
        
        # Start monitoring loop
        await self._monitor_loop()
    
    async def stop(self):
        """Stop health monitoring."""
        self.running = False
        
        # Close all clients
        for client in self.clients.values():
            await client.close()
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            timestamp = datetime.now().isoformat()
            
            for target, client in self.clients.items():
                try:
                    is_healthy = await client.check_health()
                    status = "HEALTHY" if is_healthy else "UNHEALTHY"
                    print(f"[{timestamp}] {target}: {status}")
                    
                    if not is_healthy:
                        # Could trigger alerts here
                        logger.warning(f"Service {target} is unhealthy")
                    
                except Exception as e:
                    print(f"[{timestamp}] {target}: ERROR - {e}")
                    logger.error(f"Failed to check {target}: {e}")
            
            await asyncio.sleep(self.check_interval)

# Usage
async def main():
    monitor = HealthMonitor([
        "localhost:50051",
        "localhost:50052", 
        "localhost:50053"
    ], check_interval=15)
    
    try:
        await monitor.start()
    except KeyboardInterrupt:
        print("Stopping health monitoring...")
    finally:
        await monitor.stop()

asyncio.run(main())
```

## Container Integration

### Kubernetes Health Probes

```yaml
# Kubernetes deployment with health checks
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
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          exec:
            command: ["/usr/local/bin/grpc_health_probe", "-addr=:50051", "-service=MyPluginService"]
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
```

### Docker Health Check

```dockerfile
# Dockerfile with health check
FROM python:3.11-slim

# Install grpc_health_probe
RUN GRPC_HEALTH_PROBE_VERSION=v0.4.15 && \
    wget -qO/usr/local/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /usr/local/bin/grpc_health_probe

# Copy application
COPY . /app
WORKDIR /app

# Install dependencies
RUN pip install -r requirements.txt

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD /usr/local/bin/grpc_health_probe -addr=localhost:50051 || exit 1

EXPOSE 50051
CMD ["python", "-m", "my_plugin.server"]
```

## Best Practices

### 1. Health Check Logic

Design effective health checks:

```python
def comprehensive_health_check() -> bool:
    """Comprehensive application health check."""
    try:
        # 1. Check critical dependencies
        if not check_database():
            return False
        
        # 2. Check resource availability
        if not check_memory_usage():
            return False
        
        # 3. Check application state
        if not check_application_state():
            return False
        
        # 4. Check external dependencies (optional)
        if not check_external_apis():
            logger.warning("External APIs unhealthy, but continuing")
            # Don't fail health check for non-critical dependencies
        
        return True
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False

def check_memory_usage() -> bool:
    """Check memory usage is within acceptable limits."""
    import psutil
    memory = psutil.virtual_memory()
    return memory.percent < 90  # Fail if using > 90% memory
```

### 2. Graceful Startup

Implement proper startup sequencing:

```python
class GracefulService:
    """Service with graceful startup and shutdown."""
    
    def __init__(self):
        self.startup_complete = False
        self.shutdown_started = False
    
    async def startup(self):
        """Perform startup tasks."""
        logger.info("Starting service initialization...")
        
        # Initialize dependencies
        await self._init_database()
        await self._init_cache()
        await self._load_configuration()
        
        self.startup_complete = True
        logger.info("Service initialization complete")
    
    async def shutdown(self):
        """Perform graceful shutdown."""
        logger.info("Starting graceful shutdown...")
        self.shutdown_started = True
        
        # Cleanup tasks
        await self._cleanup_connections()
        await self._flush_pending_work()
        
        logger.info("Graceful shutdown complete")
    
    def is_healthy(self) -> bool:
        """Health check that considers startup/shutdown state."""
        if not self.startup_complete:
            # Not ready yet
            return False
        
        if self.shutdown_started:
            # Shutting down
            return False
        
        # Perform additional checks
        return self._check_dependencies()
```

### 3. Error Recovery

Implement health check recovery:

```python
class RecoveringHealthChecker:
    """Health checker with automatic recovery."""
    
    def __init__(self):
        self.consecutive_failures = 0
        self.max_failures = 5
        self.recovery_attempted = False
    
    def is_healthy(self) -> bool:
        """Health check with recovery logic."""
        try:
            # Perform health check
            if self._perform_check():
                # Reset failure count on success
                self.consecutive_failures = 0
                self.recovery_attempted = False
                return True
            else:
                self.consecutive_failures += 1
                return self._handle_failure()
                
        except Exception as e:
            logger.error(f"Health check exception: {e}")
            self.consecutive_failures += 1
            return self._handle_failure()
    
    def _handle_failure(self) -> bool:
        """Handle health check failures."""
        logger.warning(f"Health check failed ({self.consecutive_failures}/{self.max_failures})")
        
        # Attempt recovery after several failures
        if (self.consecutive_failures >= 3 and 
            not self.recovery_attempted):
            logger.info("Attempting automatic recovery...")
            self.recovery_attempted = True
            
            try:
                self._attempt_recovery()
            except Exception as e:
                logger.error(f"Recovery failed: {e}")
        
        # Still unhealthy
        return False
    
    def _attempt_recovery(self):
        """Attempt to recover from failures."""
        # Example recovery actions:
        # - Reconnect to database
        # - Clear caches
        # - Restart background tasks
        pass
```

## Future Improvements

The following advanced health monitoring features are planned for future releases:

### Service Discovery Integration

Advanced service health with discovery systems:

- **Multi-Service Monitoring**: Track health of multiple services
- **Dependency Mapping**: Monitor service dependency health
- **Health Aggregation**: Combine health status across service mesh
- **Service Registry Updates**: Update discovery systems with health status

```python
# Future API concept
health_aggregator = HealthAggregator()
health_aggregator.add_dependency("database", db_health_checker)
health_aggregator.add_dependency("cache", redis_health_checker)
health_aggregator.add_dependency("auth_service", external_service_checker)
```

### Advanced Watch Implementation

Streaming health status updates:

- **Real-time Updates**: Stream health changes as they occur
- **Filtered Watching**: Watch specific services or health aspects
- **Health History**: Track health status over time
- **Event Triggers**: Execute actions on health state changes

```python
# Future API concept
async for health_update in health_servicer.Watch(request, context):
    if health_update.status == health_pb2.HealthCheckResponse.NOT_SERVING:
        await trigger_alert(health_update.service)
```

### Metrics and Alerting

Comprehensive health monitoring:

- **Health Metrics**: Export health check metrics to Prometheus
- **Alert Integration**: Send notifications on health changes
- **Dashboard Integration**: Visualize health status in Grafana
- **SLA Monitoring**: Track health against service level agreements

```python
# Future API concept  
health_metrics = HealthMetrics(
    prometheus_registry=registry,
    alert_manager=alert_manager
)
health_servicer = HealthServicer(
    app_is_healthy_callable=app_health_check,
    metrics=health_metrics
)
```

### Custom Health Protocols

Plugin-specific health checking:

- **Custom Health Checks**: Define domain-specific health protocols
- **Health Check Plugins**: Pluggable health check implementations
- **Weighted Health**: Different importance levels for health checks
- **Cascading Health**: Health checks that depend on other checks

## Quick Examples

For executable code samples:

- **[Health Check](../../examples/short/health-check.md)** - Basic health monitoring setup
- **[Basic Server](../../examples/short/basic-server.md)** - Server without health checks for comparison

These enhancements would provide enterprise-grade health monitoring capabilities suitable for production microservice deployments.