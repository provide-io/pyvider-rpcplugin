# Custom Protocol Example

A server implementing a custom protocol with gRPC service registration.

```python
#!/usr/bin/env python3
import asyncio
from typing import Any
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.factories import plugin_server

# Mock gRPC module for demonstration
class MockGrpcModule:
    @staticmethod
    def add_MockServiceServicer_to_server(servicer, server):
        print(f"Registered {servicer} with server")

class CustomProtocol(RPCPluginProtocol):
    """Custom protocol implementation."""
    
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Return gRPC module and service name."""
        return MockGrpcModule, "mock.MockService"
    
    def get_method_type(self, method_name: str) -> str:
        """Return RPC method type."""
        return "unary_unary"
    
    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Register handler with gRPC server."""
        MockGrpcModule.add_MockServiceServicer_to_server(handler, server)

class CustomHandler:
    """Handler for custom protocol."""
    
    def __init__(self):
        print("🔌 Custom handler initialized")

async def main():
    # Create custom protocol and server
    handler = CustomHandler()
    protocol = CustomProtocol()
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        print("🚀 Starting custom protocol server...")
        await server.serve()
    except KeyboardInterrupt:
        print("🛑 Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- Extend `RPCPluginProtocol` for custom service registration
- `get_grpc_descriptors()` provides gRPC module and service name
- `add_to_server()` handles service registration logic
- Enables integration with any Protocol Buffer service

## Related Examples

- [Basic Server](basic-server.md) - Using default protocol
- [Custom Protocol Guide](../guide/advanced/custom-protocols.md)