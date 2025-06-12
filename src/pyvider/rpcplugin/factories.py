"""Factory Functions for Pyvider RPC Plugin
=======================================

This module provides simple factory functions that serve as the primary entry points
for the Pyvider RPC plugin system. These functions create pre-configured instances
of the core classes with sensible defaults, simplifying the most common use cases.

The factory pattern enables a clean, functional API while preserving access to the
full power of the underlying implementation for advanced users.
"""

import os
import asyncio
from typing import Any # Removed Callable, Optional, Dict
from collections.abc import Callable as AbcCallable # Import Callable from collections.abc

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.types import HandlerT, ProtocolT, RPCPluginTransport # Changed TransportT to RPCPluginTransport
from pyvider.rpcplugin.exception import TransportError
from pyvider.telemetry import logger


def plugin_server(
    protocol: ProtocolT,
    handler: HandlerT,
    transport: str = "unix",
    transport_path: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    config: dict[str, Any] | None = None,
) -> RPCPluginServer:
    """
    Create a new plugin server with sensible defaults.

    This factory function simplifies server creation by handling transport selection
    and configuration. It creates a properly configured RPCPluginServer instance
    ready to be started with server.serve().

    Args:
        protocol: The protocol implementation for the server
        handler: The handler implementation for the protocol
        transport: Transport type, either "unix" or "tcp"
        transport_path: For unix transport, the path to the socket file (default: auto-generated)
        host: For TCP transport, the host address to bind to (default: 127.0.0.1)
        port: For TCP transport, the port to bind to (0 = auto-assign)
        config: Additional configuration options as a dictionary

    Returns:
        A configured RPCPluginServer instance ready to serve

    Raises:
        TransportError: If an invalid transport type is specified
    """
    logger.debug(f"🧰🚀🔍 Creating plugin server with transport={transport}")

    transport_inst: RPCPluginTransport # Changed TransportT to RPCPluginTransport
    match transport.lower():
        case "unix":
            logger.debug(f"🧰🚀✅ Creating Unix socket transport, path={transport_path}")
            transport_inst = UnixSocketTransport(path=transport_path)
        case "tcp":
            logger.debug(f"🧰🚀✅ Creating TCP socket transport, host={host}, port={port}")
            transport_inst = TCPSocketTransport(host=host, port=port)
        case _:
            logger.error(f"🧰🚀❌ Invalid transport type: {transport}")
            raise TransportError(f"Invalid transport type: {transport}")

    config_dict = config or {}

    logger.debug("🧰🚀✅ Creating RPCPluginServer instance")
    return RPCPluginServer(
        protocol=protocol,
        handler=handler,
        transport=transport_inst,
        config=config_dict,
    )


def plugin_client(
    server_path: str,
    protocol: ProtocolT | None = None,
    env: dict[str, str] | None = None,
    auto_connect: bool = False,
    timeout: float = 10.0,
    **kwargs: Any # Added type hint for kwargs
) -> RPCPluginClient:
    """
    Create a new plugin client connected to a server.

    This factory function simplifies client creation and connection to a plugin server.
    It can optionally auto-connect to the server if desired.

    Args:
        server_path: Path to the server executable
        protocol: Optional protocol implementation for custom functionality
        env: Environment variables to pass to the server process
        auto_connect: If True, automatically connect to the server
        timeout: Connection timeout in seconds
        **kwargs: Additional configuration options

    Returns:
        A configured RPCPluginClient instance

    Raises:
        FileNotFoundError: If the server executable doesn't exist
        PermissionError: If the server executable isn't executable
    """
    logger.debug(f"🧰🚀🔍 Creating plugin client for server at {server_path}")

    # Verify server executable exists and is executable
    if not os.path.exists(server_path):
        logger.error(f"🧰🚀❌ Server executable not found: {server_path}")
        raise FileNotFoundError(f"Server executable not found: {server_path}")

    if not os.access(server_path, os.X_OK):
        logger.error(f"🧰🚀❌ Server executable not executable: {server_path}")
        raise PermissionError(f"Server executable not executable: {server_path}")

    # Create configuration dictionary
    config: dict[str, Any] = {"timeout": timeout} # Modernized Dict to dict
    if env:
        config["env"] = env
    for key, value in kwargs.items():
        config[key] = value

    logger.debug("🧰🚀✅ Creating RPCPluginClient instance")
    client = RPCPluginClient(
        command=[server_path],
        config=config,
    )

    # Optionally auto-connect
    if auto_connect:
        logger.debug("🧰🚀🔄 Auto-connecting to server...")
        # Create a task to start the client but don't await it yet
        # The caller will need to await this
        asyncio.create_task(client.start())

    return client


def plugin_protocol(
    service_name: str,
    descriptor_module: Any = None,
    servicer_add_fn: AbcCallable | None = None, # Modernized Optional[Callable]
) -> RPCPluginProtocol:
    """
    Create a protocol definition for a specific gRPC service.

    This factory function simplifies the creation of protocol implementations
    for standard gRPC services.

    Args:
        service_name: The name of the gRPC service
        descriptor_module: The generated gRPC module containing the service definition
        servicer_add_fn: The function to add the servicer to a gRPC server
            (typically named add_XXXServicer_to_server)

    Returns:
        A configured RPCPluginProtocol implementation

    Example:
        ```python
        from my_proto import my_pb2, my_pb2_grpc

        protocol = plugin_protocol(
            service_name="MyService",
            descriptor_module=my_pb2,
            servicer_add_fn=my_pb2_grpc.add_MyServiceServicer_to_server
        )
        ```
    """
    logger.debug(f"🧰🚀🔍 Creating plugin protocol for service '{service_name}'")

    class GeneratedProtocol(RPCPluginProtocol):
        """Protocol implementation for a specific gRPC service."""

        async def get_grpc_descriptors(self) -> tuple[Any, str]:
            """Returns the protobuf descriptor set and service name."""
            logger.debug(f"🧰📡🔍 Returning gRPC descriptors for service '{service_name}'")
            return descriptor_module, service_name

        async def add_to_server(self, server: Any, handler: Any) -> None: # Parameter order fixed
            """Adds the protocol implementation to the gRPC server."""
            logger.debug(f"🧰📡🚀 Adding service '{service_name}' to gRPC server")
            if servicer_add_fn:
                servicer_add_fn(handler, server) # Original arg order for call
            else:
                logger.warning(f"🧰📡⚠️ No servicer_add_fn provided for '{service_name}'")
            return # Explicit return

    logger.debug(f"🧰🚀✅ Created plugin protocol for service '{service_name}'")
    return GeneratedProtocol()


def create_basic_protocol() -> RPCPluginProtocol:
    """
    Create a minimal protocol implementation for testing purposes.

    This factory function creates a very simple protocol that can be used for
    basic connectivity testing without a full service implementation.

    Returns:
        A basic RPCPluginProtocol implementation
    """
    logger.debug("🧰🚀🔍 Creating basic test protocol")

    class BasicProtocol(RPCPluginProtocol):
        """Minimal protocol implementation for basic connectivity testing."""

        async def get_grpc_descriptors(self) -> tuple[Any, str]: # Return type Awaitable removed
            """Returns placeholder descriptors."""
            return None, "TestService"

        async def add_to_server(self, server: Any, handler: Any) -> None: # Parameter order fixed, return type Awaitable removed
            """No-op implementation for testing."""
            logger.debug("🧰📡🔍 Basic protocol add_to_server called")
            return # Explicit return

    logger.debug("🧰🚀✅ Created basic test protocol")
    return BasicProtocol()

# 🐍🏗️🔌
