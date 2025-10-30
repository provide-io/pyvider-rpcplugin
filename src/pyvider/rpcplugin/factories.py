#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""
Factory functions for creating Pyvider RPC plugin components.

This module provides convenient factory functions for instantiating core
components of the Pyvider RPC Plugin system, such as clients, servers,
and protocols. These factories encapsulate common setup logic and promote
consistent component creation.
"""

from typing import Any, TypeVar, cast

from provide.foundation.logger import get_logger

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol, RPCPluginProtocol as BaseRpcAbcProtocol
from pyvider.rpcplugin.server import (
    RPCPluginServer,
    _HandlerT as ServerHandlerT,
    _ServerT,
    _TransportT,
)
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)
from pyvider.rpcplugin.types import (
    HandlerT,  # Retain this for plugin_server
    ProtocolT as BaseProtocolTDefinition,
    RPCPluginHandler,  # For plugin_protocol factory
    RPCPluginTransport as RPCPluginTransportType,
)

logger = get_logger(__name__)

# TypeVar for plugin_protocol factory
T_Proto_fn = TypeVar("T_Proto_fn", bound=RPCPluginProtocol[Any, Any])


def create_basic_protocol() -> type[RPCPluginProtocol[Any, Any]]:
    """
    Create a basic RPCPluginProtocol class for testing or simple use cases.

    This factory creates a minimal protocol implementation that can be used
    when no specific gRPC services are needed. It's useful for:
    - Testing the plugin framework
    - Creating placeholder protocols
    - Demonstrating the protocol interface

    Returns:
        A class that implements RPCPluginProtocol with minimal functionality.
        The class can be instantiated with an optional service_name_override.

    Example:
        ```python
        # Create the protocol class
        BasicProtocol = create_basic_protocol()

        # Instantiate with custom service name
        protocol = BasicProtocol(service_name_override="my.custom.service")

        # Use with a server
        server = plugin_server(protocol=protocol, handler=handler)
        ```

    Note:
        The returned protocol class doesn't register any actual gRPC services.
        For production use, implement a custom protocol with real services.
    """

    class BasicRPCPluginProtocol(RPCPluginProtocol[Any, Any]):
        """
        Basic protocol implementation for testing and simple use cases.

        This protocol provides the minimal interface required by the framework
        but doesn't register any actual gRPC services. It's primarily used
        for testing or as a placeholder when no specific protocol is needed.

        Attributes:
            service_name: The name of the service (default: "pyvider.BasicRPCPluginProtocol")
        """

        service_name: str = "pyvider.BasicRPCPluginProtocol"

        def __init__(self, service_name_override: str | None = None) -> None:
            super().__init__()
            if service_name_override:
                self.service_name = service_name_override

        async def get_grpc_descriptors(self) -> tuple[Any, str]:
            logger.debug(f"BasicRPCPluginProtocol: get_grpc_descriptors for {self.service_name}")
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


PT_co = TypeVar("PT_co")


def plugin_protocol(
    protocol_class: type[PT_co] | None = None,  # PT_co bound to RPCPluginProtocol implicitly by usage
    handler_class: type[RPCPluginHandler]  # Use imported RPCPluginHandler
    | None = None,
    service_name: str | None = None,
    **kwargs: Any,  # Add **kwargs to accept arbitrary keyword arguments
) -> PT_co:
    """
    Factory for creating an RPC plugin protocol instance.

    This factory provides a convenient way to instantiate protocol objects
    with proper configuration. It can either create a custom protocol instance
    or fall back to a basic protocol for testing.

    Args:
        protocol_class: Optional custom protocol class to instantiate.
                       If None, creates a BasicRPCPluginProtocol.
        handler_class: Optional handler class (currently unused but reserved
                      for future handler validation).
        service_name: Optional service name to override the default.
                     Passed as 'service_name_override' to the protocol.
        **kwargs: Additional keyword arguments passed to the protocol constructor.

    Returns:
        An instance of the specified protocol class, or BasicRPCPluginProtocol
        if no protocol_class was provided.

    Example:
        ```python
        # Create a basic protocol with default settings
        protocol = plugin_protocol()

        # Create a basic protocol with custom service name
        protocol = plugin_protocol(service_name="my.custom.service")

        # Create an instance of a custom protocol class
        from my_plugin import MyCustomProtocol
        protocol = plugin_protocol(
            protocol_class=MyCustomProtocol,
            service_name="my.service.v1",
            custom_option=True
        )

        # Use the protocol with a server
        server = plugin_server(protocol=protocol, handler=handler)
        ```

    Note:
        When using a custom protocol_class, ensure it accepts 'service_name_override'
        in its constructor if you want to use the service_name parameter.
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
            final_basic_kwargs["service_name_override"] = instance_kwargs["service_name_override"]
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

    This factory simplifies server creation by handling transport setup
    and configuration. It supports both Unix socket and TCP transports
    with sensible defaults for each platform.

    Args:
        protocol: The protocol instance defining the RPC services.
                 Usually created with plugin_protocol().
        handler: The service handler implementing the protocol's methods.
                This object will handle incoming RPC requests.
        transport: Transport type to use. Either "unix" (default) or "tcp".
                  Unix sockets are preferred for local IPC on Linux/macOS.
        transport_path: For Unix sockets, the socket file path.
                       If None, a temporary path is generated.
        host: For TCP transport, the bind address (default: "127.0.0.1").
        port: For TCP transport, the port number (default: 0 for random).
        config: Optional configuration dictionary to override defaults.
               Can include settings like timeouts, buffer sizes, etc.

    Returns:
        A configured RPCPluginServer instance ready to serve requests.
        Call the serve() method to start accepting connections.

    Raises:
        ValueError: If an unsupported transport type is specified.

    Example:
        ```python
        import asyncio
        from pyvider.rpcplugin import plugin_server, plugin_protocol

        class MyHandler:
            async def process(self, request):
                return {"result": "processed"}

        async def main():
            # Create server with Unix socket (default)
            server = plugin_server(
                protocol=plugin_protocol(),
                handler=MyHandler()
            )

            # Or create TCP server
            server = plugin_server(
                protocol=plugin_protocol(),
                handler=MyHandler(),
                transport="tcp",
                port=8080
            )

            # Start serving
            await server.serve()

        asyncio.run(main())
        ```

    Note:
        The server will automatically handle the handshake protocol,
        including magic cookie validation and transport negotiation.
        For production use, consider enabling mTLS via configuration.
    """
    logger.debug(
        f"🏭 Creating plugin server: transport={transport}, path={transport_path}, host={host}, port={port}"
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
) -> RPCPluginClient:
    """
    Factory for creating an RPC plugin client instance.

    This factory creates a client that can launch and communicate with
    a plugin subprocess. The client handles the complete lifecycle of
    the plugin process, including launching, handshake, and cleanup.

    Args:
        command: Command and arguments to launch the plugin process.
                Example: ["python", "my_plugin.py"] or ["./my-plugin"]
        config: Optional configuration dictionary. Currently only supports
               passing environment variables to the plugin subprocess via
               the "env" key: config={"env": {"VAR": "value"}}.
               To configure client behavior, set environment variables
               in your own process before creating the client.

    Returns:
        An RPCPluginClient instance. You must call the async start()
        method to launch the plugin and establish connection.

    Example:
        ```python
        import asyncio
        from pyvider.rpcplugin import plugin_client

        async def main():
            # Create client for a Python plugin (recommended: use context manager)
            async with plugin_client(
                command=["python", "path/to/plugin.py"],
                config={"env": {"PLUGIN_LOG_LEVEL": "DEBUG"}}  # Pass env vars to plugin
            ) as client:
                # Launch plugin and establish connection
                await client.start()

                # Use the client's grpc_channel for RPC calls
                stub = MyServiceStub(client.grpc_channel)
                response = await stub.ProcessRequest(request)

                # Gracefully shutdown
                await client.shutdown_plugin()

            # Client automatically closed on context exit

        asyncio.run(main())
        ```

    Advanced Example:
        ```python
        # Configure plugin subprocess environment variables
        # Note: config dict is used to pass environment variables to the plugin process
        async with plugin_client(
            command=["./my-secure-plugin"],
            config={
                "env": {
                    "PLUGIN_LOG_LEVEL": "DEBUG",
                    "PLUGIN_AUTO_MTLS": "true",
                    "MY_PLUGIN_API_KEY": "secret-key",
                }
            }
        ) as client:
            await client.start()
            # Use client...
        # Automatically closed on context exit
        ```

        # To configure the CLIENT behavior (not the plugin subprocess),
        # set environment variables in your own process:
        ```python
        import os

        # Configure client retry behavior
        os.environ["PLUGIN_CLIENT_MAX_RETRIES"] = "5"
        os.environ["PLUGIN_CLIENT_RETRY_ENABLED"] = "true"
        os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "30.0"

        # Configure client-side mTLS
        os.environ["PLUGIN_CLIENT_CERT"] = "file:///path/to/client.crt"
        os.environ["PLUGIN_CLIENT_KEY"] = "file:///path/to/client.key"

        async with plugin_client(command=["./my-secure-plugin"]) as client:
            await client.start()
            # Use client...
        ```

    Manual Cleanup (Alternative):
        ```python
        # For cases where you need manual control over lifecycle
        client = plugin_client(command=["python", "plugin.py"])
        try:
            await client.start()
            # Use client...
        finally:
            await client.close()
        ```

    Note:
        The client supports automatic retry with exponential backoff,
        subprocess management, stdio/stderr capture, and both Unix
        socket and TCP transports. The handshake protocol ensures
        secure communication via magic cookie validation.
    """
    logger.debug(f"🏭 Creating plugin client for command: {command}")
    return RPCPluginClient(command=command, config=config or {})

# 📞🔌🔚
