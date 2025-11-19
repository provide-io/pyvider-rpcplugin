# Basic Server Example

**Complexity**: 🟢 Beginner | **Lines**: ~15 | **Source Code:** `examples/short/basic_server.py`

A minimal plugin server demonstrating the absolute basics - just 15 lines to create a working RPC plugin server.

```python
#!/usr/bin/env python3
"""
Minimal plugin server example (15 lines).

Shows the absolute basics of creating a plugin server.
"""
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server
from provide.foundation import logger


async def main():
    """Run minimal plugin server."""
    protocol = plugin_protocol()  # Basic protocol
    handler = object()  # Dummy handler
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting minimal server...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- **`plugin_protocol()`** creates a basic protocol implementation (no custom RPC methods)
- **`plugin_server()`** factory creates a fully configured server with sensible defaults
- **`object()` as handler** - For this minimal example, no custom handler is needed
- **Foundation `logger`** provides structured logging (not `print()`)
- **`server.serve()`** handles the entire server lifecycle: transport setup, handshake, and request serving

## Learning Path

### Next Steps for Development
- **[Server Development Guide](../../guide/server/index.md)** - Complete guide to building production-ready plugin servers
- **[Configuration Guide](../../guide/config/index.md)** - Environment-driven configuration setup and best practices
- **[Security Implementation](../../guide/security/index.md)** - Add mTLS, authentication, and secure communication

### Understanding the Framework
- **[Transport Concepts](../../guide/concepts/transports.md)** - Learn about Unix sockets, TCP, and transport selection
- **[Security Model](../../guide/concepts/security.md)** - Understand the plugin security architecture

### Complete Examples
- **[Echo Service Examples](../echo-basic.md)** - Full-featured service examples from basic to advanced
- **[Configuration Examples](../../guide/config/index.md#configuration-examples)** - Environment-specific configuration patterns

## Related Examples

- [Full Server Guide](../../guide/server/basic-setup.md)
- [Custom Protocols](../../guide/advanced/custom-protocols.md)
## What's Next?

### Next Steps

1. **Add Custom Logic** - Replace `object()` handler with your service implementation
2. **Try Basic Client** - Connect to this server with [Basic Client Example](basic-client.md)
3. **Enable Features** - Add [Health Checks](health-check.md) or [Rate Limiting](rate-limiting.md)
4. **Go Production** - Learn about [Security Configuration](../../guide/config/configuration-security.md)

### Learning Path

- **Beginner:** [Health Check Example](health-check.md) → Add monitoring
- **Intermediate:** [Custom Protocol Example](custom-protocol.md) → Add your RPC methods
- **Advanced:** [Complete Echo Service](../echo-basic.md) → Full service example
