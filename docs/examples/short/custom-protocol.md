# Custom Protocol Example

**Complexity**: 🟡 Intermediate | **Lines**: ~30 | **Source Code:** `examples/short/custom_protocol.py`

A server implementing a custom protocol - shows how to extend `RPCPluginProtocol` for your own gRPC services.

```python
#!/usr/bin/env python3
"""
Custom protocol example (30 lines).

Shows how to create a custom protocol wrapper.
"""
import asyncio
from typing import Any
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation import logger


class CustomProtocol(RPCPluginProtocol):
    """Custom protocol implementation."""

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Return gRPC descriptors."""
        return None, "custom.MyService"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Register services with gRPC server."""
        logger.info("Custom protocol registered")


async def main():
    """Run server with custom protocol."""
    protocol = CustomProtocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with custom protocol...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- **Extend `RPCPluginProtocol`** to create custom protocol implementations
- **`get_grpc_descriptors()`** returns the gRPC module and service name for your Protocol Buffers
- **`add_to_server()`** registers your custom gRPC servicer with the server
- **Production pattern** - for real services, implement full Protocol Buffer integration
- **Foundation logging** - use `logger.info()` for structured logging

## Related Examples

- [Basic Server](basic-server.md) - Using default protocol
- [Custom Protocol Guide](../../guide/advanced/custom-protocols.md)
## What's Next?

### Next Steps

1. **Define Service** - Create `.proto` file with your RPC service definition
2. **Generate Code** - Use `grpc_tools.protoc` to generate Python code
3. **Implement Handler** - Create servicer class implementing your RPC methods
4. **Complete Integration** - Wire up protocol, handler, and server

### Learning Path

- **Beginner:** Start with [Echo Service Example](../echo-basic.md) for complete pattern
- **Intermediate:** Learn [Protocol Development](../../guide/advanced/custom-protocols.md)
- **Advanced:** Implement [Streaming RPCs](../../guide/advanced/streaming.md)
