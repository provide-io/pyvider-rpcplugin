#
# pyvider/rpcplugin/types.py
#

"""
Type definitions for the Pyvider RPC plugin system.

This module provides Protocol classes, TypeVars, and type aliases that define
the interfaces and contracts used throughout the pyvider.rpcplugin package.
These types enable static type checking and clear API boundaries.

For most users, these types are used only in type annotations. Advanced users
implementing custom protocol handlers will need to implement the Protocol
interfaces defined here.
"""

import grpc
from typing import Any, Awaitable, Callable, Dict, Optional
from typing import Protocol as TypeProtocol
from typing import TypeGuard, TypeVar, Union, runtime_checkable

from pyvider.telemetry import logger


# Core TypeVars for generic type parameters
HandlerT = TypeVar("HandlerT", bound="RPCPluginHandler")
ProtocolT = TypeVar("ProtocolT", bound="RPCPluginProtocol")
TransportT = TypeVar("TransportT", bound="RPCPluginTransport")
ServerT = TypeVar("ServerT", bound="grpc.aio.Server")
ConfigT = TypeVar("ConfigT", bound="RPCPluginConfig")
ResultT = TypeVar("ResultT")
ErrorT = TypeVar("ErrorT", bound=Exception)


# Protocol Interfaces
@runtime_checkable
class RPCPluginHandler(TypeProtocol):
    """
    Protocol defining the interface that all RPC handlers must implement.

    This is a runtime-checkable protocol that defines the minimal interface
    required for a class to serve as a handler for an RPC plugin. The actual
    methods required will depend on the specific gRPC service being implemented.
    """

    pass


@runtime_checkable
class RPCPluginProtocol(TypeProtocol):
    """
    Protocol defining the interface that all RPC protocol implementations must follow.

    This protocol defines the contract for protocol implementations that bridge
    between gRPC services and Pyvider's RPC plugin system.
    """

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """
        Returns the protobuf descriptor set and service name.

        Returns:
            Tuple containing the protobuf descriptor module and service name string.
        """
        ...

    async def add_to_server(self, handler: Any, server: Any) -> None:
        """
        Adds the protocol implementation to the gRPC server.

        Args:
            handler: The handler implementing the RPC methods
            server: The gRPC async server instance
        """
        ...

    def get_method_type(self, method_name: str) -> str:
        """
        Gets the gRPC method type for a given method name.

        Args:
            method_name: The full method path (e.g., "/plugin.GRPCStdio/StreamStdio")

        Returns:
            String representing the method type (e.g., "unary_unary", "stream_stream")
        """
        ...


@runtime_checkable
class RPCPluginTransport(TypeProtocol):
    """
    Protocol defining the interface that all transport implementations must follow.

    This protocol defines the contract for transport implementations that handle
    the low-level network communication between RPC plugin components.
    """

    endpoint: Optional[str]

    async def listen(self) -> str:
        """
        Start listening for connections and return the endpoint.

        Returns:
            String representation of the endpoint (e.g., "unix:/tmp/socket" or "127.0.0.1:50051")
        """
        ...

    async def connect(self, endpoint: str) -> None:
        """
        Connect to a remote endpoint.

        Args:
            endpoint: The endpoint to connect to
        """
        ...

    async def close(self) -> None:
        """
        Close the transport and clean up resources.
        """
        ...


@runtime_checkable
class SerializableT(TypeProtocol):
    """
    Protocol for objects that can be serialized to/from dict.

    This protocol defines the minimal interface for objects that can be
    serialized to and from dictionary representations.
    """

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the object to a dictionary representation.

        Returns:
            Dictionary representation of the object
        """
        ...

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SerializableT":
        """
        Create an object from a dictionary representation.

        Args:
            data: Dictionary containing object data

        Returns:
            New instance of the class
        """
        ...


@runtime_checkable
class ConnectionT(TypeProtocol):
    """
    Protocol for transport connections.

    This protocol defines the minimal interface for connection objects
    used by transport implementations.
    """

    async def send_data(self, data: bytes) -> None:
        """
        Send data over the connection.

        Args:
            data: Bytes to send
        """
        ...

    async def receive_data(self, size: int = 16384) -> bytes:
        """
        Receive data from the connection.

        Args:
            size: Maximum number of bytes to receive

        Returns:
            Received data as bytes
        """
        ...

    async def close(self) -> None:
        """
        Close the connection and clean up resources.
        """
        ...


# Type aliases for gRPC Clients
GrpcChannelType = Union[grpc.aio.Channel, grpc.Channel]
GrpcServerType = grpc.aio.Server
RpcConfigType = Dict[str, Any]
GrpcCredentialsType = Optional[grpc.ChannelCredentials]
EndpointType = str
AddressType = tuple[str, int]

# I/O function type aliases
SendFuncType = Callable[[bytes], Awaitable[None]]
ReceiveFuncType = Callable[[int], Awaitable[bytes]]


@runtime_checkable
class SecureRpcClientT(TypeProtocol):
    """
    Protocol for an RPC client supporting secure transport and handshake.

    This protocol defines the interface for clients that support secure
    communication with mTLS and proper handshake negotiation.
    """

    async def _perform_handshake(self) -> None:
        """Perform the handshake negotiation with the server."""
        ...

    async def _setup_tls(self) -> None:
        """Set up TLS credentials for secure communication."""
        ...

    async def _create_grpc_channel(self) -> None:
        """Create a secure gRPC channel to the server."""
        ...

    async def close(self) -> None:
        """Close the client connection and clean up resources."""
        ...


def is_valid_handler(obj: Any) -> TypeGuard[RPCPluginHandler]:
    """
    TypeGuard that checks if an object implements the RPCPluginHandler protocol.

    Args:
        obj: The object to check

    Returns:
        True if the object implements RPCPluginHandler, False otherwise
    """
    logger.debug("🧰🔍✅ Checking if object implements RPCPluginHandler protocol")
    return isinstance(obj, RPCPluginHandler)

def is_valid_protocol(obj: Any) -> TypeGuard[RPCPluginProtocol]:
    """
    TypeGuard that checks if an object implements the RPCPluginProtocol protocol.

    Args:
        obj: The object to check

    Returns:
        True if the object implements RPCPluginProtocol, False otherwise
    """
    logger.debug("🧰🔍✅ Checking if object implements RPCPluginProtocol protocol")
    return isinstance(obj, RPCPluginProtocol)

def is_valid_transport(obj: Any) -> TypeGuard[RPCPluginTransport]:
    """
    TypeGuard that checks if an object implements the RPCPluginTransport protocol.

    Args:
        obj: The object to check

    Returns:
        True if the object implements RPCPluginTransport, False otherwise
    """
    logger.debug("🧰🔍✅ Checking if object implements RPCPluginTransport protocol")
    return isinstance(obj, RPCPluginTransport)


# 🐍🏗️🔌
