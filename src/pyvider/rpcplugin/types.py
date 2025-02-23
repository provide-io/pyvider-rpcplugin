
# pyvider/rpcplugin/types.py

from typing import Any, Protocol, TypeVar

from grpc.aio import server as GRPCServer


# Core Protocol Types
class SerializableT(Protocol):
    """Protocol for objects that can be serialized to/from dict."""
    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'SerializableT': ...


# Core Type Variables
ConfigT = TypeVar('ConfigT', bound='RPCPluginConfig')
HandlerT = TypeVar('HandlerT', bound='RPCPluginHandler')
ProtocolT = TypeVar('ProtocolT', bound='RPCPluginProtocol')
TransportT = TypeVar('TransportT', bound='RPCPluginTransport')
ServerT = TypeVar('ServerT', bound=GRPCServer)

# Common Return Types
ResultT = TypeVar('ResultT')
ErrorT = TypeVar('ErrorT', bound=Exception)
