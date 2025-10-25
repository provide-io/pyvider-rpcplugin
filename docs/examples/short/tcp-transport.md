# TCP Transport Example

> **Source Code:** `examples/short/tcp_transport.py`

A plugin server using TCP instead of Unix sockets.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.factories import plugin_protocol, plugin_server

class NetworkHandler:
    """Handler for TCP-based plugin."""
    
    def __init__(self):
        print("🔌 Network handler initialized")
    
    def handle_network_request(self, request: str) -> str:
        """Process network requests."""
        return f"Network response: {request}"

async def main():
    # Create server with TCP transport
    handler = NetworkHandler()
    protocol = plugin_protocol(service_name="NetworkPlugin")
    server = plugin_server(
        protocol=protocol, 
        handler=handler, 
        transport="tcp"
    )
    
    try:
        print("🚀 Starting TCP plugin server...")
        await server.serve()
    except KeyboardInterrupt:
        print("🛑 Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- `transport="tcp"` parameter forces TCP transport
- Server automatically binds to available TCP port
- Useful for Windows or network-distributed plugins
- Client automatically detects transport from handshake

## Related Examples

- [Basic Server](basic-server.md) - Default Unix socket transport
- [Transport Guide](../../guide/concepts/transports.md)