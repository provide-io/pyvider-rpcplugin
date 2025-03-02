---
title: Transport Layer
description: How client and server communicate in Pyvider RPC Plugin
---

# Transport Layer

The transport layer in Pyvider RPC Plugin is responsible for the actual communication between the client (host application) and server (plugin). It's like the shipping company that moves packages between two businesses—except these packages are binary data, and they travel at the speed of electrons rather than the speed of a delivery van with a broken air conditioner.

## Transport Types

Pyvider supports two primary transport mechanisms:

### TCP Socket Transport

TCP sockets operate over the network stack and can communicate between processes on the same machine or across different machines. In Pyvider, we primarily use TCP sockets to communicate over the loopback interface (`127.0.0.1`), keeping everything on the local machine.

TCP transport is identified by the keyword "tcp" during negotiation and provides:

- **Universal compatibility**: Works on all operating systems
- **Standardized interface**: Familiar networking APIs
- **Firewall concerns**: May require open ports (though only locally)
- **Performance**: Slightly more overhead than Unix sockets

Think of TCP sockets as phone calls—there's a bit more overhead to connect, but they work from anywhere.

```python
class TCPSocketTransport(RPCPluginTransport):
    """TCP Socket Transport implementation."""
    
    async def listen(self) -> str:
        """Start a TCP server on a random available port."""
        # Creates TCP server, returns endpoint like "127.0.0.1:12345"
        
    async def connect(self, endpoint: str) -> None:
        """Connect to a remote TCP endpoint."""
        # Connects to the specified host:port
```

### Unix Domain Socket Transport

Unix domain sockets are a local IPC mechanism available on Unix-like operating systems (Linux, macOS). They operate through the filesystem, with socket files serving as the connection endpoints.

Unix transport is identified by the keyword "unix" during negotiation and offers:

- **Enhanced performance**: Lower overhead than TCP
- **File-based security**: Can use filesystem permissions
- **Platform limitations**: Not available on Windows
- **Namespace limitations**: Requires shared filesystem visibility

Unix sockets are like passing notes within the same office building—faster and more efficient, but everyone needs to be in the same building.

```python
class UnixSocketTransport(RPCPluginTransport):
    """Unix Domain Socket Transport implementation."""
    
    async def listen(self) -> str:
        """Create and listen on a Unix domain socket."""
        # Creates a socket file, returns path like "/tmp/plugin-12345.sock"
        
    async def connect(self, endpoint: str) -> None:
        """Connect to a Unix domain socket endpoint."""
        # Connects to the specified socket path
```

## Base Transport Interface

Both transport implementations derive from a common abstract base class that defines the required interface:

```python
class RPCPluginTransport(abc.ABC):
    """Abstract base class for all transport implementations."""
    
    @abc.abstractmethod
    async def listen(self) -> str:
        """Start listening and return the endpoint address."""
        pass
        
    @abc.abstractmethod
    async def connect(self, endpoint: str) -> None:
        """Connect to the specified endpoint."""
        pass
        
    @abc.abstractmethod
    async def close(self) -> None:
        """Close the transport."""
        pass
```

This abstraction allows the higher-level code to work with either transport type interchangeably—like how you don't need to know if your package is traveling by truck or train, as long as it arrives at its destination.

## Transport Negotiation

During the handshake process, the client advertises which transport mechanisms it supports via the `PLUGIN_TRANSPORTS` environment variable. The server then selects one that it also supports, with preference given to Unix sockets on platforms that support them.

The negotiation logic typically looks like:

```python
async def negotiate_transport(server_transports: list[str]) -> tuple[str, TransportT]:
    """Negotiate the transport type with the server."""
    if "unix" in server_transports and platform.system() != "Windows":
        return "unix", UnixSocketTransport()
    elif "tcp" in server_transports:
        return "tcp", TCPSocketTransport()
    else:
        raise TransportError("No supported transport found")
```

This ensures that both client and server agree on how they'll communicate—like deciding whether to meet for coffee or chat over video call before scheduling a meeting.

## Connection Management

Once established, transport connections must be properly managed to avoid resource leaks. Both TCP and Unix socket transports implement proper cleanup routines:

```python
async def close(self) -> None:
    """Close the transport and clean up resources."""
    # For TCP: Close the socket
    # For Unix: Close the socket and remove the socket file
```

Proper resource management is essential—like remembering to turn off the lights when you leave a room, except forgetting might cause your system to run out of file descriptors instead of just wasting electricity.

## Next Steps

Now that you understand how the transport layer works, you might want to explore:

- [Security Model](security.md) to learn how these connections are secured
- [gRPC Interface](grpc-interface.md) to see how services are defined over the transport
- [Handshake Protocol](handshake.md) to understand how transports are negotiated
