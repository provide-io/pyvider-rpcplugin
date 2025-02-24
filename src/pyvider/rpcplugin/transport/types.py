
# pyvider/rpcplugin/transport/types.py

from typing import TypeAlias, TypeVar, Protocol, Union
import asyncio

from .base import RPCPluginTransport
from .tcp import TCPSocketTransport
from .unix import UnixSocketTransport

TransportT = TypeVar("TransportT", bound=RPCPluginTransport)
TCPSocketT = TypeVar("TCPSocketT", bound=TCPSocketTransport)
UnixSocketT = TypeVar("UnixSocketT", bound=UnixSocketTransport)

TransportType: TypeAlias = Union[TCPSocketT, UnixSocketT]

class ConnectionT(Protocol):
    """Protocol for transport connections."""
    async def send_data(self, data: bytes) -> None: ...
    async def receive_data(self, size: int = 16384) -> bytes: ...
    async def close(self) -> None: ...

# Stream Types
ReaderT = TypeVar('ReaderT', bound=asyncio.StreamReader)
WriterT = TypeVar('WriterT', bound=asyncio.StreamWriter)

# Transport Aliases
EndpointType: TypeAlias = str
AddressType: TypeAlias = tuple[str, int]
