#!/usr/bin/env python3
# examples/ch02_dummy_server.py
"""
A minimal RPC plugin server for the Quick Start example.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup.
"""
import asyncio
from typing import Any
import grpc # Retaining for DummyHandler type hint, though not strictly needed if NoOp is removed
from example_utils import configure_for_example

# This should be called before other pyvider imports if this script is run directly.
# It sets up paths and default config (e.g., disabling mTLS for basic examples).
configure_for_example()

# from .example_utils import configure_for_example # This was the error
from example_utils import configure_for_example # Corrected import
from pyvider.rpcplugin import plugin_protocol, plugin_server
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol
from pyvider.telemetry import logger

class DummyHandler:
    """
    A basic handler for the dummy server.
    It doesn't implement any custom RPC methods that are called by the quick_start_client.
    """
    # The NoOp method is not strictly necessary for ch02_quick_start_client,
    # as the client only establishes a connection and doesn't make specific RPC calls
    # to the dummy server. However, having a placeholder method can be useful.
    async def NoOp(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        logger.info("DummyHandler: NoOp called (not expected in ch02_quick_start_client basic connection)")
        return {}

async def main() -> None:
    """Sets up and runs the dummy server for Chapter 2 Quick Start."""
    logger.info("🚀 ch02_dummy_server.py (Quick Start version): Starting as an executable plugin...")

    # `configure_for_example()` called at the module level sets up default configurations,
    # including a default magic cookie key/value and disabling mTLS by default.
    # The launching client (ch02_quick_start_client.py) is expected to set the
    # environment variable matching PLUGIN_MAGIC_COOKIE_KEY with the value from
    # PLUGIN_MAGIC_COOKIE_VALUE from its own configuration.

    protocol: TypesRPCPluginProtocol = plugin_protocol() # Uses BasicRPCPluginProtocol
    handler = DummyHandler() # Using the basic handler

    # plugin_server factory will use configurations from environment/global_config
    # (e.g., transport type, which defaults to 'unix' then 'tcp').
    server: RPCPluginServer = plugin_server(protocol=protocol, handler=handler)

    try:
        logger.info("Dummy server (Quick Start version) attempting to start and serve (will print handshake)...")
        await server.serve() # This performs handshake and starts serving.
        logger.info("Dummy server (Quick Start version) finished serving.")
    except KeyboardInterrupt: # pragma: no cover
        logger.info("Dummy server (Quick Start version) stopped by user.")
    except Exception as e: # pragma: no cover
        logger.error(f"Dummy server (Quick Start version) encountered an error: {e}", exc_info=True)
    finally:
        logger.info("Dummy server (Quick Start version) shutting down.")

if __name__ == "__main__":
    # This allows the script to be run directly as a plugin executable by RPCPluginClient.
    # The environment (including magic cookie) will be set by the launching client.
    asyncio.run(main())
