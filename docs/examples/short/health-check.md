# Health Check Example

**Complexity**: 🟢 Beginner | **Lines**: ~20 | **Source Code:** `examples/short/health_check.py`

A minimal plugin server with gRPC health check service enabled - perfect for production deployments with Kubernetes or other monitoring systems.

```python
#!/usr/bin/env python3
"""
Server with health check enabled (20 lines).

Demonstrates enabling the gRPC health check service.
"""
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server, configure
from provide.foundation import logger


async def main():
    """Run server with health checks."""
    # Enable health check service
    configure(health_service_enabled=True)

    protocol = plugin_protocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with health checks enabled...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- **`configure(health_service_enabled=True)`** enables the gRPC Health Checking Protocol
- **Automatic health service** - no custom health logic required for basic health checks
- **Standard gRPC protocol** - compatible with Kubernetes liveness/readiness probes
- **Production-ready** - health checks are essential for container orchestration

## Related Examples

- [Basic Server](basic-server.md) - Simple server without health checks
- [Full Health Guide](../../guide/server/health-checks.md)