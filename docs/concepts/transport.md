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
