
# pyvider/rpcplugin/transport/types.py

import asyncio
from typing import Protocol, TypeVar

from .base import RPCPluginTransport
from .tcp import TCPSocketTransport
from .unix import UnixSocketTransport

TransportT = TypeVar("TransportT", bound=RPCPluginTransport)
TCPSocketT = TypeVar("TCPSocketT", bound=TCPSocketTransport)
UnixSocketT = TypeVar("UnixSocketT", bound=UnixSocketTransport)

type TransportType[TCPSocketT: TCPSocketTransport, UnixSocketT: UnixSocketTransport] = TCPSocketT | UnixSocketT


class ConnectionT(Protocol):
    """Protocol for transport connections."""
    async def send_data(self, data: bytes) -> None: ...
    async def receive_data(self, size: int = 16384) -> bytes: ...
    async def close(self) -> None: ...


# Stream Types
ReaderT = TypeVar('ReaderT', bound=asyncio.StreamReader)
WriterT = TypeVar('WriterT', bound=asyncio.StreamWriter)

# Transport Aliases
type EndpointType = str
type AddressType = tuple[str, int]
