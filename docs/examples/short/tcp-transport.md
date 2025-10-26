# TCP Transport Example

**Complexity**: 🟢 Beginner | **Lines**: ~20 | **Source Code:** `examples/short/tcp_transport.py`

A plugin server using TCP sockets instead of Unix domain sockets - essential for Windows compatibility and network communication.

```python
#!/usr/bin/env python3
"""
Server with TCP transport (20 lines).

Demonstrates using TCP instead of Unix sockets.
"""
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server
from provide.foundation import logger


async def main():
    """Run server with TCP transport."""
    protocol = plugin_protocol()
    handler = object()

    # Use TCP transport on port 50051
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        port=50051
    )

    logger.info("Starting server with TCP transport on port 50051...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- **`transport="tcp"`** specifies TCP socket transport instead of Unix domain sockets
- **`port=50051`** sets the TCP port (use `port=0` for automatic port assignment)
- **Windows compatibility** - TCP works on all platforms (Unix sockets not available on Windows)
- **Network communication** - TCP allows plugin communication across network boundaries
- **Automatic handshake** - client detects TCP endpoint from handshake output

## Related Examples

- [Basic Server](basic-server.md) - Default Unix socket transport
- [Transport Guide](../../guide/concepts/transports.md)