# Basic Client Example

**Complexity**: 🟢 Beginner | **Lines**: ~20 | **Source Code:** `examples/short/basic_client.py`

A minimal client that connects to a plugin server - demonstrates the absolute basics of launching and connecting to a plugin subprocess.

```python
#!/usr/bin/env python3
"""
Minimal plugin client example (20 lines).

Shows the absolute basics of connecting to a plugin server.
"""
import asyncio
import sys
from pathlib import Path
from pyvider.rpcplugin import plugin_client
from provide.foundation import logger


async def main():
    """Connect to plugin server."""
    server_path = Path(__file__).parent / "basic_server.py"
    client = plugin_client(command=[sys.executable, str(server_path)])

    logger.info("Connecting to server...")
    await client.start()
    logger.info(f"Connected! Channel: {client.grpc_channel}")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- **`plugin_client()`** creates a client that handles plugin subprocess lifecycle automatically
- **`command` parameter** specifies how to launch the plugin server (typically Python interpreter + script path)
- **`await client.start()`** launches the subprocess, waits for handshake, and establishes gRPC connection
- **`client.grpc_channel`** provides access to the gRPC channel for making RPC calls
- **`await client.close()`** gracefully shuts down the plugin subprocess

## Alternative Pattern (Manual Cleanup)

For cases where you need manual control:

```python
async def main():
    client = plugin_client(command=["python", "my_server.py"])

    try:
        await client.start()
        print("Connected to plugin!")
        # Use client...
    finally:
        await client.close()
        print("Shutdown complete")
```

**Note**: The context manager pattern (first example) is recommended as it ensures cleanup even if exceptions occur.

## Related Examples

- [Full Client Guide](../../guide/client/basic-setup.md)
- [Error Handling](../../guide/client/error-handling.md)