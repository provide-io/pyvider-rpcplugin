# Basic Server Example

> **Source Code:** `examples/short/basic_server.py`

A minimal plugin server using factory functions.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server

class SimpleHandler:
    """Basic handler for plugin server."""
    
    def __init__(self):
        print("🔌 Handler initialized")
    
    def process_message(self, message: str) -> str:
        """Example method that could be exposed via gRPC."""
        return f"Processed: {message}"

async def main():
    # Create protocol and handler
    protocol = plugin_protocol(service_name="SimplePlugin")
    handler = SimpleHandler()
    
    # Create server with default transport (Unix socket)
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        print("🚀 Starting plugin server...")
        await server.serve()  # Runs until interrupted
    except KeyboardInterrupt:
        print("🛑 Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- `plugin_server()` factory creates a fully configured server
- `plugin_protocol()` creates a basic protocol implementation
- Server prints handshake info to stdout for client connection
- Handler contains your business logic

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