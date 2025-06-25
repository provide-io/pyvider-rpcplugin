#!/usr/bin/env python3
# examples/00_dummy_server.py
"""
A minimal RPC plugin server for use by other examples.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup.
"""

import asyncio
from typing import Any  # Standard imports at top
from pathlib import Path # Added import

import grpc  # Standard imports at top

# Ensure 'src' is in sys.path for direct execution
# This setup is done by example_utils.configure_for_example()
from example_utils import configure_for_example

configure_for_example()  # Must be called before other pyvider imports

# pyvider.rpcplugin imports
from pyvider.rpcplugin import plugin_protocol, plugin_server  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.transport import UnixSocketTransport # Added import
from pyvider.rpcplugin.types import (
    RPCPluginProtocol as TypesRPCPluginProtocol,  # noqa: E402
)
from pyvider.telemetry import logger  # noqa: E402


class DummyHandler:
    """A handler that does nothing, for basic server operation."""

    async def NoOp(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        # This method won't actually be called if launched by plugin_client
        # and no actual RPC calls are made to it.
        # It's here for completeness if the server were used differently.
        logger.info(
            "DummyHandler: NoOp called (should not happen in typical plugin launch)"
        )
        return {}


async def main() -> None:
    """Sets up and runs the dummy server.
    It expects its environment (magic cookie) to be set by the launching client.
    """
    # configure_for_example() called at module level to set up paths and basic config
    logger.info("🚀 00_dummy_server.py: Starting as an executable plugin...")

    # The `configure_for_example()` utility should have set:
    # - PLUGIN_AUTO_MTLS=False
    # - PLUGIN_MAGIC_COOKIE_KEY="PYVIDER_PLUGIN_MAGIC_COOKIE"
    # - PLUGIN_MAGIC_COOKIE_VALUE="pyvider-example-cookie"
    # The launching client (e.g., 01_quick_start.py) will set the
    # PYVIDER_PLUGIN_MAGIC_COOKIE environment variable to "pyvider-example-cookie".
    # The server's handshake logic will then validate this.

    protocol: TypesRPCPluginProtocol = plugin_protocol()  # Uses BasicRPCPluginProtocol
    handler = DummyHandler()

    # plugin_server will pick up transport (defaulting to unix if not specified)
    # and other configurations from the environment/global config.
    server: RPCPluginServer = plugin_server(
        protocol=protocol,
        handler=handler,
        # Transport can be specified here or left to defaults/env config.
        # For client-launched plugins, the client often dictates transport preference
        # via handshake, or the server announces its capabilities.
        # `plugin_server` defaults to Unix if available, then TCP.
    )

    # If using Unix transport, write the socket path to a file for 01b example
    # Ensure we import Path from pathlib
    from pathlib import Path # Add this import if not already present at top
    from pyvider.rpcplugin.transport import UnixSocketTransport # Add this import

    if isinstance(server.transport, UnixSocketTransport) and server.transport.path:
        # Determine project root to place dummy_server_socket.txt at the project root
        example_dir = Path(__file__).resolve().parent
        project_root = example_dir.parent
        socket_comm_file = project_root / "dummy_server_socket.txt"
        try:
            socket_comm_file.write_text(server.transport.path)
            logger.info(f"Dummy server: Wrote Unix socket path to {socket_comm_file}")
        except Exception as e:
            logger.error(f"Dummy server: Failed to write socket path to file: {e}")

    try:
        logger.info(
            "Dummy server attempting to start and serve (will print handshake)..."
        )
        # When launched as a plugin, server.serve() will print the handshake string
        # to stdout and then block, serving requests until stopped.
        await server.serve()
        # If server.serve() returns, it means it was stopped.
        logger.info("Dummy server finished serving.")
    except KeyboardInterrupt:  # pragma: no cover
        logger.info("Dummy server stopped by user (KeyboardInterrupt).")
    except Exception as e:  # pragma: no cover
        logger.error(f"Dummy server encountered an error: {e}", exc_info=True)
    finally:
        logger.info("Dummy server shutting down.")
        # server.stop() is implicitly called by RPCPluginServer.serve()'s finally block.


if __name__ == "__main__":
    # This allows the script to be run directly as a plugin executable.
    asyncio.run(main())
