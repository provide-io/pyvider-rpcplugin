#!/usr/bin/env python3
# examples/ch02_dummy_server.py
"""
A minimal RPC plugin server for the Quick Start example.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup.
"""

import asyncio
from typing import Any

import grpc  # For DummyHandler type hint; can be removed if NoOp is.
# Import from examples.example_utils
from examples.example_utils import configure_for_example # noqa: E402

# This should be called before other pyvider imports if this script is run directly.
# It sets up paths and default config (e.g., disabling mTLS for basic examples).
configure_for_example()

# from example_utils import configure_for_example  # noqa: E402 # Corrected import # This line is now redundant

from pyvider.rpcplugin import plugin_protocol, plugin_server  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.types import (  # noqa: E402
    RPCPluginProtocol as TypesRPCPluginProtocol,
)
from pyvider.telemetry import logger  # noqa: E402
# Import the shared DummyHandler
from examples.example_utils import DummyHandler # noqa: E402


async def main() -> None:
    """Sets up and runs the dummy server for Chapter 2 Quick Start."""
    logger.info(
        "🚀 ch02_dummy_server.py (Quick Start version): "
        "Starting as an executable plugin..."
    )

    # `configure_for_example()` called at the module level sets up default
    # configurations, including a default magic cookie key/value and disabling
    # mTLS by default. The launching client (ch02_quick_start_client.py) is
    # expected to set the environment variable matching PLUGIN_MAGIC_COOKIE_KEY
    # with the value from PLUGIN_MAGIC_COOKIE_VALUE from its own configuration.

    protocol: TypesRPCPluginProtocol = plugin_protocol()  # Uses BasicRPCPluginProtocol
    handler = DummyHandler()  # Using the basic handler

    # plugin_server factory will use configurations from environment/global_config
    # (e.g., transport type, which defaults to 'unix' then 'tcp').
    server: RPCPluginServer = plugin_server(protocol=protocol, handler=handler)

    try:
        logger.info(
            "Dummy server (Quick Start version) attempting to start and serve "
            "(will print handshake)..."
        )
        await server.serve()  # This performs handshake and starts serving.
        logger.info("Dummy server (Quick Start version) finished serving.")
    except KeyboardInterrupt:  # pragma: no cover
        logger.info("Dummy server (Quick Start version) stopped by user.")
    except Exception as e:  # pragma: no cover
        logger.error(
            f"Dummy server (Quick Start version) encountered an error: {e}",
            exc_info=True,
        )
    finally:
        logger.info("Dummy server (Quick Start version) shutting down.")


if __name__ == "__main__":
    # This allows the script to be run directly as a plugin executable
    # by RPCPluginClient.
    # The environment (including magic cookie) will be set by the launching client.
    asyncio.run(main())
