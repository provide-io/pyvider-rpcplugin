#!/usr/bin/env python3
"""
Minimal plugin client example (20 lines).

Shows the absolute basics of connecting to a plugin server.
"""

import asyncio
from pathlib import Path
import sys

from provide.foundation import logger

from pyvider.rpcplugin import plugin_client


async def main():
    """Connect to plugin server."""
    server_path = Path(__file__).parent / "basic_server.py"
    client = plugin_client(command=[sys.executable, str(server_path)])

    logger.info("Connecting to server...")
    await client.start()
    logger.info(f"Connected! Channel: {client.grpc_channel}")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
