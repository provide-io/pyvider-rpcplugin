#!/usr/bin/env python3
"""
Server with TCP transport (20 lines).

Demonstrates using TCP instead of Unix sockets.
"""
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server
from provide.foundation import logger


async def main():
    """Run server with TCP transport."""
    protocol = plugin_protocol()
    handler = object()

    # Use TCP transport on port 50051
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        port=50051
    )

    logger.info("Starting server with TCP transport on port 50051...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
