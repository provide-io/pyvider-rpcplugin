#!/usr/bin/env python3
"""
Server Setup Examples - Various server configuration patterns.
"""

import asyncio

from example_utils import (  # type: ignore[import-not-found]
    configure_for_example,
    get_example_port,
)

configure_for_example()

from pyvider.rpcplugin import plugin_server  # noqa: E402
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # noqa: E402
from pyvider.telemetry import logger  # noqa: E402


class BasicProtocol(RPCPluginProtocol):
    """Basic protocol for demonstration."""
    from typing import Any, Tuple # Add Any, Tuple

    async def get_grpc_descriptors(self) -> Tuple[Any | None, str]:
        # For a real service, this would return actual gRPC descriptors
        # (e.g., your_pb2_grpc) and the service name string
        # as defined in your .proto file.
        # Example: return your_pb2_grpc, "YourServiceName"
        return None, "BasicService"  # Placeholder for concept demonstration

    async def add_to_server(self, server: Any, handler: Any) -> None:
        # For a real service, this would typically call a function like:
        # your_pb2_grpc.add_YourServiceServicer_to_server(handler, server)
        # The service_name is derived from get_grpc_descriptors.
        service_name = await self.get_service_name()
        logger.info(
            f"🔌 Service '{service_name}' (conceptual) would be registered with handler: {type(handler).__name__}"
        )


class BasicHandler:
    """Basic handler for demonstration."""

    pass

from pyvider.rpcplugin.server import RPCPluginServer # For return type hint

async def tcp_server_example() -> RPCPluginServer:
    """Example: TCP server configuration."""
    logger.info("🌐 TCP Server Configuration Example")

    server = plugin_server(
        protocol=BasicProtocol(),
        handler=BasicHandler(),
        transport="tcp",
        host="127.0.0.1",
        port=get_example_port(),
        # The 'config' param here can override global settings.
        # For gRPC specific options like max_workers, these are typically
        # passed directly to the grpc.aio.server. pyvider.rpcplugin.plugin_server
        # might not directly map all arbitrary keys to gRPC options.
        # Standard pyvider.rpcplugin config keys are PLUGIN_ prefixed.
        # This example assumes 'max_workers' might be handled by a custom server
        # or is illustrative for general config passing.
        # If targeting a standard gRPC option, it might need to be
        # PLUGIN_GRPC_OPTIONS='[("grpc.max_concurrent_streams", 100)]' or similar.
        # For this example, we'll assume it's illustrative or for a custom handler.
        config={"APP_MAX_WORKERS": 4},  # Using APP_ prefix for clarity
    )

    # Log the configured endpoint
    logger.info(f"✅ TCP server configured: {server.transport.endpoint if server.transport else 'No transport'}")
    return server


async def unix_server_example() -> RPCPluginServer:
    """Example: Unix socket server configuration."""
    logger.info("🔌 Unix Socket Server Configuration Example")

    import os
    import tempfile

    # Use tempfile for a safer temporary socket path
    socket_path = os.path.join(tempfile.gettempdir(), "pyvider_example.sock")

    server = plugin_server(
        protocol=BasicProtocol(),
        handler=BasicHandler(),
        transport="unix",
        transport_path=socket_path,  # nosec B108
        # See comment in tcp_server_example regarding the 'config' dict.
        config={"APP_MAX_WORKERS": 2},  # Using APP_ prefix for clarity
    )

    # Log the configured endpoint
    logger.info(f"✅ Unix socket server configured: {server.transport.endpoint if server.transport else 'No transport'}")
    return server


async def main() -> None:
    """Run server setup examples."""
    logger.info("🚀 Server Setup Examples")

    # TCP example
    await tcp_server_example()

    # Unix socket example
    await unix_server_example()

    logger.info("✅ All server setup examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍⚙️
