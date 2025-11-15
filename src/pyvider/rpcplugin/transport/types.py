"""Type definitions for the Pyvider RPC plugin transport system.

This module provides Protocol classes, TypeVars, and type aliases that define
the interfaces and contracts used by transport implementations. These types
enable static type checking and clear API boundaries.

Usage:
    from pyvider.rpcplugin.transport.types import TransportT

    class MyCustomTransport(RPCPluginTransport):
        async def listen(self) -> str:
            ...

    def setup_server(transport: TransportT) -> None:
        # Type-safe transport handling
        ...
"""

import asyncio
from typing import Protocol, TypeVar

from pyvider.rpcplugin.transport.base import RPCPluginTransport
from pyvider.rpcplugin.transport.tcp import TCPSocketTransport
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

TransportT = TypeVar(
    "TransportT", bound=RPCPluginTransport
)  # Generic type for any RPCPluginTransport implementation
TCPSocketT = TypeVar(
    "TCPSocketT", bound=TCPSocketTransport
)  # Generic type for TCPSocketTransport
UnixSocketT = TypeVar(
    "UnixSocketT", bound=UnixSocketTransport
)  # Generic type for UnixSocketTransport

# Simplified TransportType alias, as TCPSocketT and UnixSocketT are already specific.
type TransportType = (
    TCPSocketTransport | UnixSocketTransport
)  # Represents either a TCP or Unix socket transport


class ConnectionT(Protocol):
    """Protocol defining the interface for a transport connection."""

    async def send_data(self, data: bytes) -> None: ...
    async def receive_data(self, size: int = 16384) -> bytes: ...
    async def close(self) -> None: ...


# Stream Types
ReaderT = TypeVar("ReaderT", bound=asyncio.StreamReader)
WriterT = TypeVar("WriterT", bound=asyncio.StreamWriter)

# Transport Aliases
type EndpointType = str
type AddressType = tuple[str, int]

# 🐍🏗️🔌
