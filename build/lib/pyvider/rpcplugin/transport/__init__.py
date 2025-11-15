"""Transport Layer for Pyvider RPC Plugin
======================================

This package provides the network transport abstractions for communication
between plugin clients and servers. It handles the low-level socket operations,
connection management, and protocol negotiation.

Key components:
- RPCPluginTransport: Base interface for all transport implementations
- TCPSocketTransport: TCP socket-based transport implementation
- UnixSocketTransport: Unix domain socket-based transport implementation

The transport layer is responsible for:
1. Listening for connections (server-side)
2. Connecting to endpoints (client-side)
3. Managing connection lifecycle and cleanup
4. Ensuring Go-Python interoperability
"""

from pyvider.rpcplugin.transport.base import RPCPluginTransport
from pyvider.rpcplugin.transport.tcp import TCPSocketTransport
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

__all__ = [
    "RPCPluginTransport",
    "TCPSocketTransport",
    "UnixSocketTransport",
]

# 🐍🏗️🔌
