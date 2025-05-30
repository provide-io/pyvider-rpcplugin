#
# pyvider/rpcplugin/transport/types.py
#
"""
Type definitions for the Pyvider RPC plugin transport system.

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

TransportT = TypeVar("TransportT", bound=RPCPluginTransport)
TCPSocketT = TypeVar("TCPSocketT", bound=TCPSocketTransport)
UnixSocketT = TypeVar("UnixSocketT", bound=UnixSocketTransport)

type TransportType[TCPSocketT: TCPSocketTransport, UnixSocketT: UnixSocketTransport] = (
    TCPSocketT | UnixSocketT
)


class ConnectionT(Protocol):
    """Protocol for transport connections."""

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
