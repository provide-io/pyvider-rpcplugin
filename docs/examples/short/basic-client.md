# Basic Client Example

> **Source Code:** `examples/short/basic_client.py`

A minimal client that connects to a plugin server using the async context manager pattern.

```python
#!/usr/bin/env python3
import asyncio

from pyvider.rpcplugin import plugin_client

async def main():
    # Use async context manager for automatic cleanup
    async with plugin_client(command=["python", "my_server.py"]) as client:
        # Start the plugin
        await client.start()
        print("Connected to plugin!")

        # Access the gRPC channel
        channel = client.grpc_channel
        if channel:
            print(f"Channel ready: {channel}")

    # Client automatically closed on context exit
    print("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- `plugin_client()` factory creates a client that handles plugin process management automatically
- **Use `async with` context manager** for automatic resource cleanup
- `await client.start()` launches the plugin subprocess and establishes connection
- Use `client.grpc_channel` to get the gRPC channel for making RPC calls
- Client is automatically closed when exiting the `async with` block

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