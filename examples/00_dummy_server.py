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

    # Configure for Unix socket by default, simple setup
    # In a real scenario, these might come from env vars set by the plugin host
    # For this dummy server, we'll rely on defaults or minimal explicit config
    # if plugin_server defaults are sufficient.
    # os.environ.setdefault("PLUGIN_MAGIC_COOKIE_KEY", "DUMMY_SERVER_COOKIE_KEY")
    # os.environ.setdefault("PLUGIN_MAGIC_COOKIE_VALUE", "dummysecret")

    protocol: TypesRPCPluginProtocol = plugin_protocol()
    handler = DummyHandler()

    # Let plugin_server choose transport (defaults to unix if not specified)
    server: RPCPluginServer = plugin_server(
        protocol=protocol,  # MyPy might require cast here
        handler=handler,
        # transport="unix" # Default
        # transport_path="/tmp/dummy_server.sock" # Example path
    )

    try:
        logger.info("Dummy server attempting to start and serve...")
        await server.serve()  # This will print handshake to stdout and then run
        logger.info(
            "Dummy server finished serving (should not happen if started by client)."
        )
    except KeyboardInterrupt:
        logger.info("Dummy server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        from pyvider.rpcplugin.exception import HandshakeError
        if isinstance(e, HandshakeError) and "Magic cookie not provided" in str(e):
            print(
                "\nERROR: This server expects to be run by a plugin host (like Terraform) "
                "which provides a magic cookie for secure handshake.\n"
                "When run standalone, the handshake will fail because this cookie is missing.\n"
                "To run this server for development or with a custom client, ensure the\n"
                f"'{server._handshake_config.magic_cookie_key}' environment variable is set to the expected value\n"
                f" (e.g., '{server._handshake_config.magic_cookie_value}' or as configured).\n"
            )
            logger.error(f"Dummy server failed due to missing magic cookie: {e}", exc_info=False)
            sys.exit(1)
        else:
            logger.error(f"Dummy server an error: {e}", exc_info=True)
            sys.exit(1) # Exit with 1 for other errors too as per instruction for failing examples
    finally:
        logger.info("Dummy server shutting down.")
        # server.stop() is called internally by server.serve()'s finally block.


if __name__ == "__main__":
    asyncio.run(main())
