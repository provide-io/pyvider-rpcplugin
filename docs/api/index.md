# API Reference

Complete API documentation for Pyvider RPC Plugin. This reference provides detailed information about classes, methods, and functions with code examples and usage patterns.

## Overview

The Pyvider RPC Plugin API is organized into logical modules:

- **Server** - Plugin server implementation and management
- **Client** - Plugin client with connection and retry logic
- **Transport** - Network transport abstractions (Unix, TCP)
- **Protocol** - RPC protocol definitions and gRPC integration
- **Configuration** - Environment and runtime configuration management
- **Exceptions** - Error handling and exception hierarchy

## Quick Reference

### Core Classes

| Class | Description | Module |
|-------|-------------|--------|
| [`RPCPluginServer`](server/server.md) | Main plugin server implementation | `pyvider.rpcplugin.server` |
| [`RPCPluginClient`](client/client.md) | Plugin client with connection management | `pyvider.rpcplugin.client` |
| [`RPCPluginConfig`](config/schema.md) | Configuration schema and validation | `pyvider.rpcplugin.config` |
| [`RPCPluginProtocol`](protocol/base.md) | Base protocol interface | `pyvider.rpcplugin.protocol` |

### Factory Functions

| Function | Description | Returns |
|----------|-------------|---------|
| `plugin_server()` | Create and configure a plugin server | `RPCPluginServer` |
| `plugin_client()` | Create and configure a plugin client | `RPCPluginClient` |
| `plugin_protocol()` | Create a protocol implementation | `RPCPluginProtocol` |

### Transport Classes

| Class | Description | Use Case |
|-------|-------------|----------|
| [`UnixSocketTransport`](transport/unix.md) | Unix domain socket transport | Local IPC, high performance |
| [`TCPSocketTransport`](transport/tcp.md) | TCP socket transport | Network communication |
| [`RPCPluginTransport`](transport/base.md) | Abstract transport base | Custom transport implementation |

## API Modules

<div class="grid cards" markdown>

-   :material-server: **Server API**
    
    ---
    
    Plugin server, health checks, rate limiting, and lifecycle management
    
    [:octicons-arrow-right-24: Server API](server/)

-   :material-laptop: **Client API**
    
    ---
    
    Plugin client, connection management, and retry mechanisms
    
    [:octicons-arrow-right-24: Client API](client/)

-   :material-swap-horizontal: **Transport API**
    
    ---
    
    Network transports for Unix sockets and TCP connections
    
    [:octicons-arrow-right-24: Transport API](transport/)

-   :material-api: **Protocol API**
    
    ---
    
    RPC protocols, gRPC integration, and service definitions
    
    [:octicons-arrow-right-24: Protocol API](protocol/)

-   :material-cog: **Configuration API**
    
    ---
    
    Configuration schema, environment loading, and validation
    
    [:octicons-arrow-right-24: Config API](config/)

-   :material-alert: **Exceptions API**
    
    ---
    
    Exception hierarchy, error handling, and debugging support
    
    [:octicons-arrow-right-24: Exceptions API](exceptions/)

</div>

## Usage Patterns

### Basic Server Setup

```python
from pyvider.rpcplugin import plugin_server, RPCPluginProtocol

class MyProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        # Protocol implementation
        pass
    
    async def add_to_server(self, server, handler):
        # Add services to gRPC server
        pass

# Create server with automatic configuration
server = await plugin_server(
    protocol=MyProtocol(),
    handler=MyServiceHandler()
)

# Start serving
await server.serve()
```

### Basic Client Connection

```python
from pyvider.rpcplugin import plugin_client

# Connect to plugin server
async with plugin_client() as client:
    # Use the client for RPC calls
    result = await client.call_method("my_method", param="value")
    print(f"Result: {result}")
```

### Custom Transport Configuration  

```python
from pyvider.rpcplugin.transport import UnixSocketTransport
from pyvider.rpcplugin import RPCPluginServer

# Create custom transport
transport = UnixSocketTransport(path="/tmp/my-plugin.sock")

# Create server with custom transport
server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=transport
)
```

### Configuration Management

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Access configuration values
timeout = rpcplugin_config.handshake_timeout()
transports = rpcplugin_config.server_transports()
mtls_enabled = rpcplugin_config.auto_mtls_enabled()

# Programmatic configuration
from pyvider.rpcplugin import configure

configure(
    protocol_version=1,
    transports=["unix"],
    auto_mtls=True
)
```

## Type Annotations

All APIs include comprehensive type annotations for better IDE support and type checking:

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyvider.rpcplugin.server import RPCPluginServer
    from pyvider.rpcplugin.client import RPCPluginClient
    from pyvider.rpcplugin.transport.base import RPCPluginTransport
```

## Error Handling

The API uses a structured exception hierarchy for predictable error handling:

```python
from pyvider.rpcplugin.exception import (
    RPCPluginError,      # Base exception
    TransportError,      # Transport-related errors
    HandshakeError,      # Handshake failures
    SecurityError,       # Security/authentication errors
    ConfigError,         # Configuration errors
)

try:
    await server.serve()
except TransportError as e:
    logger.error(f"Transport failed: {e}")
    # Handle transport-specific errors
except HandshakeError as e:
    logger.error(f"Handshake failed: {e}")
    # Handle handshake failures
except RPCPluginError as e:
    logger.error(f"Plugin error: {e}")
    # Handle any plugin-related error
```

## Integration with provide.foundation

Pyvider RPC Plugin is built on [provide.foundation](https://foundation.provide.io), providing:

- **Structured logging** with emoji enhancement
- **Configuration management** with environment variable support  
- **Error handling** with rich context and metadata
- **Type safety** with comprehensive annotations

```python
from provide.foundation import logger
from provide.foundation.crypto import Certificate
from pyvider.rpcplugin import plugin_server

# Foundation integration is automatic
server = await plugin_server(protocol=my_protocol, handler=my_handler)
logger.info("🚀 Plugin server created successfully")
```

## Navigation

- Browse specific API modules using the cards above
- See [Examples](../examples/) for working code samples
- Check the [User Guide](../guide/) for conceptual explanations
- Visit [Getting Started](../getting-started/) for quick setup