# RPCPluginTransport Base Class

The `RPCPluginTransport` abstract base class defines the interface that all transport implementations must follow in the Pyvider RPC Plugin system. It provides the contract for network communication between plugin clients and servers.

## Overview

The transport layer abstracts the underlying network protocol, allowing the same plugin code to work with different communication methods (Unix sockets, TCP, etc.). All transport implementations must implement the three core methods defined in this interface.

## Interface Definition

```python
from abc import ABC, abstractmethod
from pyvider.rpcplugin.transport.base import RPCPluginTransport

class MyCustomTransport(RPCPluginTransport):
    async def listen(self) -> str:
        # Implement server-side listening
        pass
    
    async def connect(self, endpoint: str) -> None:
        # Implement client-side connection
        pass
    
    async def close(self) -> None:
        # Implement cleanup
        pass
```

## Core Methods

### `listen() -> str`

**Purpose**: Start listening for incoming connections (server-side)

**Returns**: The endpoint address as a string (e.g., "127.0.0.1:50051" or "/tmp/socket.sock")

**Usage**:
```python
# Server-side usage
transport = UnixSocketTransport(path="/tmp/my-plugin.sock")
endpoint = await transport.listen()
print(f"Server listening on: {endpoint}")
```

**Implementation Requirements**:
- Bind to an appropriate socket or address
- Begin accepting connections
- Return the actual endpoint address that clients should connect to
- Handle port assignment (for TCP) or path creation (for Unix sockets)
- Raise `TransportError` if binding or listening fails

**Common Patterns**:
- TCP transports may use port 0 for automatic port assignment
- Unix socket transports should handle path normalization
- Implementations should be idempotent where possible

### `connect(endpoint: str) -> None`

**Purpose**: Connect to a remote endpoint (client-side)

**Parameters**:
- `endpoint`: The target endpoint address string

**Usage**:
```python
# Client-side usage
transport = TCPSocketTransport()
await transport.connect("127.0.0.1:50051")
```

**Implementation Requirements**:
- Establish a connection to the specified endpoint
- Handle connection timeouts appropriately
- Support retries for transient failures if appropriate
- Validate endpoint format before attempting connection
- Raise `TransportError` if connection cannot be established

**Common Patterns**:
- TCP transports should validate host:port format
- Unix socket transports should handle path normalization and verification
- Implement reasonable connection timeouts (typically 5-30 seconds)

### `close() -> None`

**Purpose**: Close the transport and release all associated resources

**Usage**:
```python
# Cleanup
await transport.close()
```

**Implementation Requirements**:
- Close all network resources (sockets, servers, connections)
- Cancel any background tasks
- Clean up temporary files (for Unix sockets)
- Be idempotent (safe to call multiple times)
- Handle cleanup errors gracefully

**Common Patterns**:
- Use try/except blocks for each cleanup operation
- Log cleanup errors but don't propagate them unless critical
- Set internal state flags to prevent resource leaks

## Attributes

### `endpoint: str | None`

The current endpoint address. This attribute is set during `listen()` or `connect()` operations:

```python
transport = UnixSocketTransport()
print(transport.endpoint)  # None initially

await transport.listen()
print(transport.endpoint)  # "/tmp/pyvider-abc12345.sock"
```

## Implementation Guidelines

### Error Handling

All transport implementations should use the `TransportError` exception for transport-specific errors:

```python
from pyvider.rpcplugin.exception import TransportError

class MyTransport(RPCPluginTransport):
    async def connect(self, endpoint: str) -> None:
        try:
            # Connection logic here
            await establish_connection(endpoint)
        except OSError as e:
            raise TransportError(
                message=f"Failed to connect to {endpoint}: {e}",
                hint="Check network connectivity and endpoint availability"
            ) from e
```

### Logging

Use structured logging with appropriate detail levels:

```python
from provide.foundation import logger

class MyTransport(RPCPluginTransport):
    async def listen(self) -> str:
        logger.debug(f"Starting to listen on {self.address}")
        try:
            # Implementation
            logger.info(f"Successfully listening on {endpoint}")
            return endpoint
        except Exception as e:
            logger.error(f"Failed to start listening: {e}")
            raise
```

### Resource Management

Implement proper resource management with cleanup:

```python
class MyTransport(RPCPluginTransport):
    def __init__(self):
        self._server = None
        self._connections = set()
        self._closing = False
    
    async def close(self) -> None:
        if self._closing:
            return  # Idempotent
        
        self._closing = True
        
        # Close all connections
        for conn in self._connections:
            try:
                await conn.close()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
        
        # Close server
        if self._server:
            try:
                self._server.close()
                await self._server.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing server: {e}")
            finally:
                self._server = None
```

## Available Implementations

The Pyvider RPC Plugin system provides two built-in transport implementations:

### Unix Socket Transport

- **Class**: `UnixSocketTransport`
- **Use Case**: Local communication, high performance, platform compatibility (Linux, macOS)
- **Endpoint Format**: File path (e.g., "/tmp/plugin.sock")
- **Documentation**: [Unix Socket Transport](unix.md)

### TCP Socket Transport  

- **Class**: `TCPSocketTransport`
- **Use Case**: Network communication, Windows compatibility, remote plugins
- **Endpoint Format**: Host:port (e.g., "127.0.0.1:50051")
- **Documentation**: [TCP Socket Transport](tcp.md)

## Creating Custom Transports

To implement a custom transport:

1. **Inherit from RPCPluginTransport**:
```python
from pyvider.rpcplugin.transport.base import RPCPluginTransport

class MyCustomTransport(RPCPluginTransport):
    pass
```

2. **Implement Required Methods**:
```python
async def listen(self) -> str:
    # Server-side listening logic
    return endpoint_address

async def connect(self, endpoint: str) -> None:
    # Client-side connection logic
    pass

async def close(self) -> None:
    # Cleanup logic
    pass
```

3. **Add Error Handling**:
```python
from pyvider.rpcplugin.exception import TransportError

# Use TransportError for transport-specific failures
```

4. **Use with Factory Functions**:
```python
from pyvider.rpcplugin.factories import plugin_server

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="custom",  # If registering transport type
    # OR
    # Directly pass transport instance:
    # transport=MyCustomTransport()
)
```

## Testing Transports

When testing custom transports, verify:

1. **Basic Functionality**:
   - Listen/connect/close operations
   - Endpoint format consistency
   - Error handling for invalid inputs

2. **Resource Management**:
   - Proper cleanup after close()
   - Idempotent close() behavior
   - No resource leaks

3. **Error Conditions**:
   - Port/address already in use
   - Permission denied
   - Network unreachable
   - Invalid endpoint formats

4. **Integration**:
   - Works with plugin servers and clients
   - Compatible with gRPC channel creation
   - Proper handshake protocol support

## Class Reference

::: pyvider.rpcplugin.transport.base.RPCPluginTransport

## Related Components

- [Unix Socket Transport](unix.md) - Local communication transport
- [TCP Socket Transport](tcp.md) - Network communication transport  
- [Server API](../server/server.md) - Using transports in servers
- [Client API](../client/client.md) - Using transports in clients
- [Factory Functions](../factories.md) - Creating transports via factories