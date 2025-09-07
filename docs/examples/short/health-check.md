# Health Check Example

A minimal plugin server with health monitoring.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.factories import plugin_protocol, plugin_server
from pyvider.rpcplugin.health_servicer import HealthServicer

class SimpleHandler:
    """Handler with health monitoring."""
    
    def __init__(self):
        self.is_healthy = True
        print("🔌 Handler initialized")
    
    def check_health(self) -> bool:
        """Health check logic."""
        return self.is_healthy

async def main():
    # Create handler and health servicer
    handler = SimpleHandler()
    health_servicer = HealthServicer(
        app_is_healthy_callable=handler.check_health,
        service_name="SimplePlugin"
    )
    
    # Create protocol and server with health monitoring
    protocol = plugin_protocol(service_name="SimplePlugin")
    server = plugin_server(
        protocol=protocol, 
        handler=handler,
        health_servicer=health_servicer
    )
    
    try:
        print("🚀 Starting plugin server with health checks...")
        await server.serve()
    except KeyboardInterrupt:
        print("🛑 Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- `HealthServicer` provides gRPC health check protocol support
- `app_is_healthy_callable` defines custom health logic
- Server automatically exposes health check endpoints
- Health status can be queried by monitoring systems

## Related Examples

- [Basic Server](basic-server.md) - Simple server without health checks
- [Full Health Guide](../../guide/server/health-checks.md)