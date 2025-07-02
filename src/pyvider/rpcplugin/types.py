#
# src/pyvider/rpcplugin/types.py
#

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable
from collections.abc import Callable as AbcCallable
from typing import (
    TYPE_CHECKING,
    Any,
    TypeGuard,
    TypeVar,
    runtime_checkable,
)
from typing import (
    Protocol as TypeProtocol,
)

import grpc

from pyvider.telemetry import logger

"""Type definitions for the Pyvider RPC plugin system.

This module provides Protocol classes, TypeVars, and type aliases that define
the interfaces and contracts used throughout the pyvider.rpcplugin package.
These types enable static type checking and clear API boundaries.

For most users, these types are used only in type annotations. Advanced users
implementing custom protocol handlers will need to implement the Protocol
interfaces defined here.
"""

if TYPE_CHECKING:
    from .config import RPCPluginConfig  # For TypeVar bound


# Core TypeVars for generic type parameters
HandlerT = TypeVar("HandlerT", bound="RPCPluginHandler")  # pragma: no cover
ProtocolT = TypeVar("ProtocolT", bound="RPCPluginProtocol")  # pragma: no cover
TransportT = TypeVar("TransportT", bound="RPCPluginTransport")  # pragma: no cover
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
        ...  # pragma: no cover

    async def add_to_server(self, handler: Any, server: Any) -> None:
        """
        Adds the protocol implementation to the gRPC server.

        Args:
            handler: The handler implementing the RPC methods
            server: The gRPC async server instance
        """
        ...  # pragma: no cover

    def get_method_type(self, method_name: str) -> str:
        """
        Gets the gRPC method type for a given method name.

        Args:
            method_name: The full method path (e.g., "/plugin.GRPCStdio/StreamStdio")

        Returns:
            String representing the method type (e.g., "unary_unary", "stream_stream")
        """
        ...  # pragma: no cover


@runtime_checkable
class RPCPluginTransport(TypeProtocol):
    """
    Protocol defining the interface that all transport implementations must follow.

    This protocol defines the contract for transport implementations that handle
    the low-level network communication between RPC plugin components.
    """

    endpoint: str | None

    async def listen(self) -> str:
        """
        Start listening for connections and return the endpoint.

        Returns:
            String representation of the endpoint (e.g., "unix:/tmp/socket" or
            "127.0.0.1:50051")
        """
        ...  # pragma: no cover

    async def connect(self, endpoint: str) -> None:
        """
        Connect to a remote endpoint.

        Args:
            endpoint: The endpoint to connect to
        """
        ...  # pragma: no cover

    async def close(self) -> None:
        """
        Close the transport and clean up resources.
        """
        ...  # pragma: no cover


@runtime_checkable
class SerializableT(TypeProtocol):
    """
    Protocol for objects that can be serialized to/from dict.

    This protocol defines the minimal interface for objects that can be
    serialized to and from dictionary representations.
    """

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the object to a dictionary representation.

        Returns:
            Dictionary representation of the object
        """
        ...  # pragma: no cover

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SerializableT:
        """
        Create an object from a dictionary representation.

        Args:
            data: Dictionary containing object data

        Returns:
            New instance of the class
        """
        ...  # pragma: no cover


def is_valid_serializable(obj: Any) -> TypeGuard[SerializableT]:
    logger.debug(
        "🧰🔍✅ Checking if object implements SerializableT protocol "
        "(manual runtime checks)"
    )

    # Check to_dict method
    if not hasattr(obj, "to_dict"):
        logger.debug("SerializableT: Method to_dict is missing.")
        return False
    to_dict_method = obj.to_dict
    if not callable(to_dict_method):
        logger.debug("SerializableT: Attribute to_dict is not callable.")
        return False
    # Signature for obj.to_dict() should have 0 parameters (after self)
    try:
        to_dict_sig = inspect.signature(to_dict_method)
        if len(to_dict_sig.parameters) != 0:
            logger.debug(
                "SerializableT: to_dict signature incorrect. Expected 0 params, "
                f"got {len(to_dict_sig.parameters)}."
            )
            return False
    except (TypeError, ValueError):
        logger.debug("SerializableT: Could not inspect to_dict signature.")
        return False

    # Check from_dict classmethod
    if not hasattr(obj, "from_dict"):
        logger.debug("SerializableT: Method from_dict is missing.")
        return False

    from_dict_method = obj.from_dict
    if not callable(from_dict_method):
        logger.debug("SerializableT: Attribute from_dict is not callable.")
        return False

    try:
        from_dict_sig = inspect.signature(from_dict_method)
        if len(from_dict_sig.parameters) != 1:  # Expecting 1 param ('data')
            logger.debug(
                "SerializableT: from_dict signature incorrect. Expected 1 param "
                f"(data), got {len(from_dict_sig.parameters)}."
            )
            return False
    except (TypeError, ValueError):
        logger.debug("SerializableT: Could not inspect from_dict signature.")
        return False

    logger.debug("SerializableT: All structural and signature checks passed.")
    return True


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
        ...  # pragma: no cover

    async def receive_data(self, size: int = 16384) -> bytes:
        """
        Receive data from the connection.

        Args:
            size: Maximum number of bytes to receive

        Returns:
            Received data as bytes
        """
        ...  # pragma: no cover

    async def close(self) -> None:
        """
        Close the connection and clean up resources.
        """
        ...  # pragma: no cover


def is_valid_connection(obj: Any) -> TypeGuard[ConnectionT]:
    logger.debug(
        "🧰🔍✅ Checking if object implements ConnectionT protocol "
        "(manual runtime checks)"
    )

    methods_spec = {
        "send_data": {"params": 1, "is_async": True},
        "receive_data": {"params": 1, "is_async": True},
        "close": {"params": 0, "is_async": True},
    }

    for method_name, spec in methods_spec.items():
        if not hasattr(obj, method_name):
            logger.debug(f"ConnectionT: Method {method_name} is missing.")
            return False

        method = getattr(obj, method_name)
        if not callable(method):
            logger.debug(f"ConnectionT: Attribute {method_name} is not callable.")
            return False

        if spec["is_async"] and not asyncio.iscoroutinefunction(method):
            logger.debug(f"ConnectionT: Method {method_name} is not async as expected.")
            return False

        try:
            sig = inspect.signature(method)
            if len(sig.parameters) != spec["params"]:
                param_str = "param" if spec["params"] == 1 else "params"
                logger.debug(
                    f"ConnectionT: {method_name} signature incorrect. Expected "
                    f"{spec['params']} {param_str}, got {len(sig.parameters)}."
                )
                return False
        except (TypeError, ValueError):
            logger.debug(f"ConnectionT: Could not inspect {method_name} signature.")
            return False

    logger.debug("ConnectionT: All structural and signature checks passed.")
    return True

    # Type aliases for gRPC Clients
    GrpcChannelType = (  # pragma: no cover
        grpc.aio.Channel | grpc.Channel
    )  # Represents gRPC sync or async channel


GrpcServerType = grpc.aio.Server  # pragma: no cover
RpcConfigType = dict[str, Any]  # pragma: no cover
GrpcCredentialsType = (  # pragma: no cover
    grpc.ChannelCredentials | None
)  # gRPC channel credentials, possibly None
EndpointType = str  # pragma: no cover
AddressType = tuple[str, int]  # pragma: no cover

# I/O function type aliases using collections.abc
SendFuncType = AbcCallable[  # pragma: no cover
    [bytes], Awaitable[None]
]  # Type for a function that sends bytes
ReceiveFuncType = AbcCallable[  # pragma: no cover
    [int], Awaitable[bytes]
]  # Type for a function that receives bytes


@runtime_checkable
class SecureRpcClientT(TypeProtocol):
    """
    Protocol for an RPC client supporting secure transport and handshake.

    This protocol defines the interface for clients that support secure
    communication with mTLS and proper handshake negotiation.
    """

    async def _perform_handshake(self) -> None:
        """Perform the handshake negotiation with the server."""
        ...  # pragma: no cover

    async def _setup_tls(self) -> None:
        """Set up TLS credentials for secure communication."""
        ...  # pragma: no cover

    async def _create_grpc_channel(self) -> None:
        """Create a secure gRPC channel to the server."""
        ...  # pragma: no cover

    async def close(self) -> None:
        """Close the client connection and clean up resources."""
        ...  # pragma: no cover


def is_valid_secure_rpc_client(obj: Any) -> TypeGuard[SecureRpcClientT]:
    logger.debug(
        "🧰🔍✅ Checking if object implements SecureRpcClientT protocol "
        "(manual runtime checks)"
    )

    methods_spec = {
        "_perform_handshake": {"params": 0, "is_async": True},
        "_setup_tls": {"params": 0, "is_async": True},
        "_create_grpc_channel": {"params": 0, "is_async": True},
        "close": {"params": 0, "is_async": True},
    }

    for method_name, spec in methods_spec.items():
        if not hasattr(obj, method_name):
            logger.debug(f"SecureRpcClientT: Method {method_name} is missing.")
            return False

        method = getattr(obj, method_name)
        if not callable(method):
            logger.debug(f"SecureRpcClientT: Attribute {method_name} is not callable.")
            return False

        if spec["is_async"] and not asyncio.iscoroutinefunction(method):
            logger.debug(
                f"SecureRpcClientT: Method {method_name} is not async as expected."
            )
            return False

        try:
            sig = inspect.signature(method)
            if len(sig.parameters) != spec["params"]:
                logger.debug(
                    f"SecureRpcClientT: {method_name} signature incorrect. Expected "
                    f"{spec['params']} params, got {len(sig.parameters)}."
                )
                return False
        except (TypeError, ValueError):
            logger.debug(
                f"SecureRpcClientT: Could not inspect {method_name} signature."
            )
            return False

    logger.debug("SecureRpcClientT: All structural and signature checks passed.")
    return True


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
