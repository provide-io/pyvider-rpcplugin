#!/usr/bin/env python3
"""
Transport Options - Unix socket vs TCP configuration comparison.
"""

import asyncio
import tempfile
from pathlib import Path

from example_utils import configure_for_example, get_example_port

configure_for_example()

from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.telemetry import logger


async def tcp_transport_demo():
    """Demonstrate TCP transport configuration."""
    logger.info("🌐 TCP Transport Demo")

    transport = TCPSocketTransport(host="127.0.0.1", port=get_example_port())

    logger.info(f"📡 TCP transport configured: {transport}")
    logger.info("✅ TCP transport demo completed")


async def unix_transport_demo():
    """Demonstrate Unix socket transport configuration."""
    logger.info("🔌 Unix Socket Transport Demo")

    # Use temporary file for socket
    with tempfile.NamedTemporaryFile(suffix=".sock", delete=False) as tmp:
        socket_path = tmp.name

    transport = UnixSocketTransport(path=socket_path)

    logger.info(f"📁 Unix socket transport configured: {transport}")
    logger.info("✅ Unix transport demo completed")

    # Cleanup
    Path(socket_path).unlink(missing_ok=True)


async def main():
    """Compare transport options."""
    logger.info("🚀 Transport Options Comparison")

    await tcp_transport_demo()
    await unix_transport_demo()

    logger.info("💡 Transport Selection Guidelines:")
    logger.info("  🌐 TCP: Network communication, multiple hosts")
    logger.info("  🔌 Unix: Local communication, better performance")

    logger.info("✅ Transport comparison completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🚚
