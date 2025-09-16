# Client API

The Client API provides robust client implementations for connecting to and communicating with plugin servers, with built-in connection management, retry logic, and error handling.

## Overview

The Pyvider RPC Plugin client system provides:

- **Connection Management**: Automatic connection handling with retry logic
- **Process Management**: Launch and manage plugin subprocess  
- **Handshake Negotiation**: Protocol version and transport negotiation
- **Error Handling**: Comprehensive error handling with recovery patterns
- **Resource Cleanup**: Automatic cleanup of processes and connections
- **Configuration**: Environment-driven configuration

## Core Components

### RPCPluginClient

**[📖 Complete RPCPluginClient Documentation](client.md)**

Key features:
- Process launching and management
- Handshake protocol implementation
- Connection retry with exponential backoff
- Automatic resource cleanup
- Configuration from environment

### Factory Function

```python
from pyvider.rpcplugin import plugin_client

client = plugin_client(
    command=["python", "-m", "my_plugin.server"],
    config={"timeout": 30.0}
)
```

## Usage Examples

### Basic Usage

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def main():
    client = plugin_client(command=["python", "-m", "my_plugin"])
    
    async with client:
        response = await client.my_service.process_data("example")
        print(f"Result: {response}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Manual Connection Management

```python
from pyvider.rpcplugin import RPCPluginClient

client = RPCPluginClient(
    command=["python", "-m", "my_plugin"],
    config={"handshake_timeout": 30.0, "max_retries": 5}
)

try:
    await client.start()
    result = await client.call_method("process", data="test")
finally:
    await client.stop()
```

## Configuration

Key client configuration options:

| Variable | Default | Description |
|----------|---------|-------------|
| `PLUGIN_CLIENT_RETRY_ENABLED` | `true` | Enable connection retry |
| `PLUGIN_CLIENT_MAX_RETRIES` | `3` | Maximum retry attempts |
| `PLUGIN_HANDSHAKE_TIMEOUT` | `10.0` | Handshake timeout seconds |
| `PLUGIN_CONNECTION_TIMEOUT` | `30.0` | Connection timeout seconds |

## Error Handling

```python
from pyvider.rpcplugin.exception import (
    TransportError, HandshakeError, TimeoutError
)

try:
    async with client:
        result = await client.my_service.process_request(data)
except HandshakeError as e:
    logger.error(f"Handshake failed: {e}")
except TransportError as e:
    logger.error(f"Transport error: {e}")
except TimeoutError as e:
    logger.error(f"Operation timed out: {e}")
```

## Next Steps

- **[RPCPluginClient Details](client.md)** - Complete client class documentation
- **[Configuration Guide](../../guide/config/index.md)** - Client configuration options  
- **[Error Handling](../../guide/client/error-handling.md)** - Comprehensive error handling patterns