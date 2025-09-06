# TCP Transport Example

A plugin server using TCP instead of Unix sockets.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.factories import plugin_protocol, plugin_server
from pyvider.rpcplugin.config import RPCPluginConfig

class NetworkHandler:
    """Handler for TCP-based plugin."""
    
    def __init__(self):
        print("🔌 Network handler initialized")
    
    def handle_network_request(self, request: str) -> str:
        """Process network requests."""
        return f"Network response: {request}"

async def main():
    # Configure for TCP transport
    config = RPCPluginConfig(
        server_transports=["tcp"],
        server_host="127.0.0.1",
        server_port_min=50051,
        server_port_max=50100
    )
    
    # Create server with TCP transport
    handler = NetworkHandler()
    protocol = plugin_protocol(service_name="NetworkPlugin")
    server = plugin_server(
        protocol=protocol, 
        handler=handler, 
        config=config
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

- `server_transports=["tcp"]` forces TCP transport
- `server_host` and port range configure TCP binding
- Useful for Windows or network-distributed plugins
- Client automatically detects transport from handshake

## Related Examples

- [Basic Server](basic-server.md) - Default Unix socket transport
- [Transport Guide](../guide/concepts/transports.md)