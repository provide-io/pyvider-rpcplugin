#!/usr/bin/env python3
"""
Custom protocol example (30 lines).

Shows how to create a custom protocol wrapper.
"""

import asyncio
from typing import Any

from provide.foundation import logger

from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol


class CustomProtocol(RPCPluginProtocol):
    """Custom protocol implementation."""

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Return gRPC descriptors."""
        return None, "custom.MyService"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Register services with gRPC server."""
        logger.info("Custom protocol registered")


async def main():
    """Run server with custom protocol."""
    protocol = CustomProtocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with custom protocol...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
