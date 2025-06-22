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
import os # Ensured os is imported
from typing import Any, Type, TypeVar, cast

from pyvider.rpcplugin.client import RPCPluginClient
# ClientT was erroring from .types, it's defined in .client.types
from pyvider.rpcplugin.client.types import ClientT
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import (
    RPCPluginServer,
    _ServerT,
    _HandlerT as ServerHandlerT,
    _TransportT,
    _ProtocolT as ServerProtocolT,
)
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)
from pyvider.rpcplugin.types import HandlerT
from pyvider.rpcplugin.types import (
    ProtocolT as BaseProtocolTDefinition,
)
from pyvider.rpcplugin.types import RPCPluginTransport as RPCPluginTransportType
from pyvider.telemetry import logger

# TypeVar for plugin_protocol factory
T_Proto_fn = TypeVar("T_Proto_fn", bound=RPCPluginProtocol)


def create_basic_protocol() -> Type[RPCPluginProtocol[Any, Any]]:
    """
    Creates a basic RPCPluginProtocol.
    """

    class BasicRPCPluginProtocol(RPCPluginProtocol[Any, Any]):
        """Basic protocol, primarily for structure or testing."""
        service_name: str = "pyvider.BasicRPCPluginProtocol"

        def __init__(self, service_name_override: str | None = None) -> None:
            super().__init__()
            if service_name_override:
                self.service_name = service_name_override

        async def get_grpc_descriptors(self) -> tuple[Any, str]:
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


def plugin_protocol[PT_co]( # Use new TypeVar, assume it's covariant if protocol_class is.
    protocol_class: type[PT_co] | None = None, # PT_co bound to RPCPluginProtocol implicitly by usage
    handler_class: type[HandlerT] | None = None,
    service_name: str | None = None,
) -> PT_co:
    """
    Factory for creating an RPC plugin protocol instance.
    """
    effective_protocol_class: type[PT_co]
    instance_kwargs = {}

    if protocol_class:
        effective_protocol_class = protocol_class
        # If a custom protocol class is provided, we assume it handles its own service_name
        # or the caller doesn't intend to override it via this factory.
        # If it needs service_name, it should take it in its __init__.
        if service_name and not hasattr(protocol_class, "service_name"):
            logger.warning(f"service_name '{service_name}' provided but "
                           f"{protocol_class.__name__} may not use it via __init__.")
    else:
        # Default to BasicRPCPluginProtocol
        # Cast needed as create_basic_protocol returns Type[RPCPluginProtocol[Any, Any]]
        BasicProtoCls = create_basic_protocol()
        effective_protocol_class = cast(type[PT_co], BasicProtoCls)
        if service_name:
            instance_kwargs['service_name_override'] = service_name

    return effective_protocol_class(**instance_kwargs)


def plugin_server(
    protocol: BaseProtocolTDefinition,
    handler: HandlerT,
    transport: str = "unix",
    transport_path: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    config: dict[str, Any] | None = None,
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
        transport=cast(_TransportT, transport_instance), # Use 'transport' kwarg
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
