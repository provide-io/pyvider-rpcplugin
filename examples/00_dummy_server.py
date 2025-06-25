#!/usr/bin/env python3
# examples/00_dummy_server.py
"""
A minimal RPC plugin server for use by other examples.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup.
"""

import asyncio
import sys
from pathlib import Path
from typing import Any  # Standard imports at top

import grpc  # Standard imports at top

# Ensure 'src' is in sys.path if examples are run from the project root
project_root = Path(__file__).resolve().parent.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# pyvider.rpcplugin imports
from example_utils import configure_for_example # noqa: E402
from pyvider.rpcplugin import plugin_protocol, plugin_server  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.types import (  # noqa: E402
    RPCPluginProtocol as TypesRPCPluginProtocol,
)
from pyvider.telemetry import logger  # noqa: E402


class DummyHandler:
    """A handler that does nothing, for basic server operation."""

    async def NoOp(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        logger.info("DummyHandler: NoOp called")
        return {}  # Return an empty message or a specific dummy reply type if defined


async def main() -> None:
    """Sets up and runs the dummy server."""
    logger.info("Starting 00_dummy_server.py...")

    # Configure using the centralized utility
    # For this dummy server, we use default example settings.
    # If this server were launched by a client, the client would ensure
    # the correct magic cookie env var (e.g., PYVIDER_PLUGIN_MAGIC_COOKIE) is set.
    configure_for_example(PLUGIN_LOG_LEVEL="DEBUG")

    protocol: TypesRPCPluginProtocol = plugin_protocol()
    handler = DummyHandler()

    # Let plugin_server choose transport (defaults to unix if not specified)
    # It will use configurations set by `configure_for_example`.
    server: RPCPluginServer = plugin_server(
        protocol=protocol,
        handler=handler,
    )

    try:
        logger.info("Dummy server attempting to start and serve...")
        # The server's handshake logic will use PLUGIN_MAGIC_COOKIE_KEY and
        # PLUGIN_MAGIC_COOKIE_VALUE from the config (set by configure_for_example)
        # to know what to expect. It will then check os.environ for the key named
        # by PLUGIN_MAGIC_COOKIE_KEY.
        await server.serve()  # This will print handshake to stdout and then run
        logger.info(
            "Dummy server finished serving (should not happen if started by client)."
        )
    except KeyboardInterrupt:
        logger.info("Dummy server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.error(f"Dummy server an error: {e}", exc_info=True)
    finally:
        logger.info("Dummy server shutting down.")
        # server.stop() is called internally by server.serve()'s finally block.


if __name__ == "__main__":
    asyncio.run(main())
