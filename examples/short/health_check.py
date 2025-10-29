#!/usr/bin/env python3
"""
Server with health check enabled (20 lines).

Demonstrates enabling the gRPC health check service.
"""
import asyncio
from pyvider.rpcplugin import plugin_protocol, plugin_server, configure
from provide.foundation import logger


async def main():
    """Run server with health checks."""
    # Enable health check service
    configure(health_service_enabled=True)

    protocol = plugin_protocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with health checks enabled...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
