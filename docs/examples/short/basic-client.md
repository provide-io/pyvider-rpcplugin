# Basic Client Example

A minimal client that connects to a plugin server.

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.client import RPCPluginClient

async def main():
    # Create client for plugin command
    client = RPCPluginClient(command=["python", "my_server.py"])
    
    try:
        # Start and connect to plugin
        await client.start()
        print("✅ Connected to plugin!")
        
        # Get gRPC channel for RPC calls
        channel = client.grpc_channel
        if channel:
            print(f"Channel ready: {channel}")
            # Use channel with your gRPC stubs here
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        # Always clean up
        await client.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## Key Points

- `RPCPluginClient` handles plugin process management automatically
- Always call `client.stop()` to clean up resources
- Use `client.grpc_channel` to get the gRPC channel for making RPC calls
- The plugin process is started as a subprocess with the provided command

## Related Examples

- [Full Client Guide](../guide/client/basic-setup.md)
- [Error Handling](../guide/client/error-handling.md)