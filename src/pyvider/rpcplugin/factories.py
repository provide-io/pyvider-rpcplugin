#
# src/pyvider/rpcplugin/factories.py
#

"""
Factory functions for creating Pyvider RPC plugin components.

This module provides convenient factory functions for instantiating core
components of the Pyvider RPC Plugin system, such as clients, servers,
and protocols. These factories encapsulate common setup logic and promote
consistent component creation.
"""

from typing import Any, TypeVar, cast

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import (
    RPCPluginServer,
    _ServerT,
    _TransportT,
)
from pyvider.rpcplugin.server import (
    _HandlerT as ServerHandlerT,  # Alias to avoid conflict if HandlerT is defined here
)
from pyvider.rpcplugin.server import (
    _ProtocolT as ServerProtocolT,
)
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)
from pyvider.rpcplugin.types import HandlerT  # Keep this for plugin_protocol's arg
from pyvider.rpcplugin.types import (
    ProtocolT as BaseProtocolTDefinition,
)
from pyvider.rpcplugin.types import RPCPluginTransport as RPCPluginTransportType
from pyvider.telemetry import logger

# TypeVar for the create_basic_protocol and plugin_protocol context
# This T_Proto is specific to this module's factory functions.
T_Proto = TypeVar("T_Proto", bound=RPCPluginProtocol)


def create_basic_protocol() -> type[RPCPluginProtocol[Any, Any]]:
    """
    Creates a basic RPCPluginProtocol.

    It's a placeholder and doesn't register specific gRPC services itself.
    The actual services (Stdio, Broker, Controller) are registered by
    `register_protocol_service` in the `RPCPluginServer`.
    """

    class BasicRPCPluginProtocol(RPCPluginProtocol[Any, Any]):
        """Basic protocol, primarily for structure or testing."""

        service_name = "pyvider.BasicRPCPluginProtocol"

        async def get_grpc_descriptors(self) -> tuple[Any, str]: # Sig matches base
            logger.debug(
                "BasicRPCPluginProtocol: get_grpc_descriptors for "
                f"{self.service_name}"
            )
            return (None, self.service_name)

        async def add_to_server(self, server: Any, handler: Any) -> None:
            logger.debug(
                f"BasicRPCPluginProtocol: add_to_server for {self.service_name} "
                "(no specific services added by this basic protocol itself)."
            )
            pass

        def get_method_type(self, method_name: str) -> str:
            logger.warning(
                f"BasicRPCPluginProtocol: get_method_type for {method_name} "
                "defaulting to unary_unary. Implement for specific protocols."
            )
            return "unary_unary"

    return BasicRPCPluginProtocol


# Use T_Proto for the generic function parameter as per UP047
def plugin_protocol[T_Proto_fn: RPCPluginProtocol]( # Bound to RPCPluginProtocol
    protocol_class: type[T_Proto_fn] | None = None,
    handler_class: type[HandlerT] | None = None, # HandlerT from .types
) -> T_Proto_fn:
    """
    Factory for creating an RPC plugin protocol instance.

    Args:
        protocol_class: The specific RPCPluginProtocol subclass to instantiate.
                        If None, a BasicRPCPluginProtocol is used.
        handler_class: The handler class for the protocol.

    Returns:
        An instance of the specified or basic RPC plugin protocol.
    """
    effective_protocol_class: type[T_Proto_fn]
    if protocol_class:
        effective_protocol_class = protocol_class
    else:
        # create_basic_protocol returns Type[RPCPluginProtocol[Any, Any]]
        # We need to cast it to Type[T_Proto_fn]
        # This assumes BasicRPCPluginProtocol is compatible with T_Proto_fn's bound
        effective_protocol_class = cast(
            type[T_Proto_fn], create_basic_protocol()
        )

    return effective_protocol_class()


def plugin_server(
    protocol: BaseProtocolTDefinition,
    handler: HandlerT,
    transport: str = "unix",
    transport_path: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    config: dict[str, Any] | None = None,
    # Use specific TypeVars imported from server.py for the return type
) -> RPCPluginServer[_ServerT, ServerHandlerT, _TransportT, ServerProtocolT]:
    """
    Factory for creating an RPC plugin server instance.
    """
    logger.debug(
        f"🏭 Creating plugin server: transport={transport}, path={transport_path}, "
        f"host={host}, port={port}"
    )
    transport_instance: RPCPluginTransportType
    if transport == "unix":
        transport_instance = UnixSocketTransport(path=transport_path)
    elif transport == "tcp":
        transport_instance = TCPSocketTransport(host=host, port=port)
    else:
        raise ValueError(f"Unsupported transport type: {transport}")

    return RPCPluginServer(
        protocol=cast(ServerProtocolT, protocol),
        handler=cast(ServerHandlerT, handler),
        passed_transport=cast(_TransportT, transport_instance),
        config=config or {},
    )


def plugin_client(
    command: list[str],
    config: dict[str, Any] | None = None,
    auto_connect: bool = True,
) -> RPCPluginClient:
    """
    Factory for creating an RPC plugin client instance.
    """
    logger.debug(f"🏭 Creating plugin client for command: {command}")
    client = RPCPluginClient(command=command, config=config or {})
    if auto_connect:
        logger.warning(
            "🏭 auto_connect=True in synchronous factory is misleading. "
            "Caller should handle async client.start()."
        )
    return client


# 🐍🏗️🔌
