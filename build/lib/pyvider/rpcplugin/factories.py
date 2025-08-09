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
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol as BaseRpcAbcProtocol
from pyvider.rpcplugin.server import (
    RPCPluginServer,
    _ServerT,
    _TransportT,
)
from pyvider.rpcplugin.server import (
    _HandlerT as ServerHandlerT,
)
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)
from pyvider.rpcplugin.types import (
    HandlerT,  # Retain this for plugin_server
    RPCPluginHandler,  # For plugin_protocol factory
)
from pyvider.rpcplugin.types import (
    ProtocolT as BaseProtocolTDefinition,
)
from pyvider.rpcplugin.types import RPCPluginTransport as RPCPluginTransportType
from pyvider.telemetry import logger

# TypeVar for plugin_protocol factory
T_Proto_fn = TypeVar("T_Proto_fn", bound=RPCPluginProtocol)


def create_basic_protocol() -> type[RPCPluginProtocol[Any, Any]]:
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
                f"BasicRPCPluginProtocol: get_grpc_descriptors for {self.service_name}"
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


def plugin_protocol[
    PT_co
](  # Use new TypeVar, assume it's covariant if protocol_class is.
    protocol_class: type[PT_co]
    | None = None,  # PT_co bound to RPCPluginProtocol implicitly by usage
    handler_class: type[RPCPluginHandler]  # Use imported RPCPluginHandler
    | None = None,
    service_name: str | None = None,
    **kwargs: Any,  # Add **kwargs to accept arbitrary keyword arguments
) -> PT_co:
    """
    Factory for creating an RPC plugin protocol instance.
    """
    effective_protocol_class: type[PT_co]
    instance_kwargs = kwargs  # Initialize with all extra kwargs

    if protocol_class:
        effective_protocol_class = protocol_class
        # If service_name is provided, pass it as 'service_name_override'.
        # Custom protocols should handle 'service_name_override' for this factory
        # to configure their service name.
        if service_name:
            instance_kwargs["service_name_override"] = service_name
    else:
        # Default to BasicRPCPluginProtocol
        BasicProtoCls = create_basic_protocol()
        effective_protocol_class = cast(type[PT_co], BasicProtoCls)

        # For BasicRPCPluginProtocol, only 'service_name_override' is relevant.
        # Filter instance_kwargs to only pass this if service_name was provided,
        # or if 'service_name_override' was already in **kwargs from the call.
        final_basic_kwargs = {}
        if service_name:
            final_basic_kwargs["service_name_override"] = service_name
        elif "service_name_override" in instance_kwargs:
            # If service_name wasn't given directly to factory,
            # but was in **kwargs
            final_basic_kwargs["service_name_override"] = instance_kwargs[
                "service_name_override"
            ]
        instance_kwargs = final_basic_kwargs

    return effective_protocol_class(**instance_kwargs)


def plugin_server(
    protocol: BaseProtocolTDefinition,
    handler: HandlerT,
    transport: str = "unix",
    transport_path: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    config: dict[str, Any] | None = None,
) -> RPCPluginServer[_ServerT, ServerHandlerT, _TransportT]:
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
        protocol=cast(BaseRpcAbcProtocol[_ServerT, ServerHandlerT], protocol),
        handler=cast(ServerHandlerT, handler),
        transport=cast(_TransportT, transport_instance),  # Use 'transport' kwarg
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
