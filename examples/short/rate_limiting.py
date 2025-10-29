#!/usr/bin/env python3
"""
Server with rate limiting (25 lines).

Demonstrates enabling request rate limiting.
"""

import asyncio

from provide.foundation import logger

from pyvider.rpcplugin import configure, plugin_protocol, plugin_server


async def main():
    """Run server with rate limiting."""
    # Enable rate limiting: 100 requests/sec, burst capacity 200
    configure(rate_limit_enabled=True, rate_limit_requests_per_second=100.0, rate_limit_burst_capacity=200)

    protocol = plugin_protocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with rate limiting: 100 req/s...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
