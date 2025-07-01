#!/usr/bin/env python3
# examples/ch02_dummy_server.py
"""
A minimal RPC plugin server for use by other examples.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup.
"""

import asyncio
from typing import Any  # Standard imports at top

import grpc  # Standard imports at top

# Ensure 'src' is in sys.path for direct execution
# This setup is done by example_utils.configure_for_example()
from example_utils import configure_for_example

# This setup is done by example_utils.configure_for_example()
configure_for_example()  # Must be called before other pyvider imports

# pyvider.rpcplugin imports
from pyvider.rpcplugin import plugin_protocol, plugin_server  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
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
    logger.info("🚀 ch02_dummy_server.py: Starting as an executable plugin...")

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

    # Determine if running as main for the special socket path writing behavior
    is_running_as_main = __name__ == "__main__"
    server_task = None
    project_root_for_socket_file = Path(__file__).resolve().parent.parent
    socket_comm_file = project_root_for_socket_file / "dummy_server_socket.txt"

    try:
        logger.info(
            "Dummy server attempting to start and serve (will print handshake)..."
        )

        if is_running_as_main:
            # To write the socket path, we need to run serve() in a task
            # and wait for the server to be ready.
            async def serve_and_write_socket_path():
                await server.serve()

            server_task = asyncio.create_task(serve_and_write_socket_path())

            # Wait for the server to actually start and establish its transport endpoint
            await server.wait_for_server_ready(timeout=10.0) # Add timeout

            if server.transport and server.transport.endpoint:
                if server._transport_name == "unix": # Only write for unix transport
                    logger.info(f"Running as main, server ready. Writing socket path: {server.transport.endpoint} to {socket_comm_file}")
                    try:
                        with open(socket_comm_file, "w") as f:
                            f.write(str(server.transport.endpoint))
                        logger.info(f"Successfully wrote socket path to {socket_comm_file}")
                    except IOError as e:
                        logger.error(f"Failed to write socket path to {socket_comm_file}: {e}")
                else:
                    logger.info(f"Running as main, but transport is {server._transport_name}, not unix. Socket path not written.")
            else:
                logger.warning("Running as main, but server transport or endpoint not available after start. Cannot write socket path.")

            # Now wait for the server task to complete (e.g., on KeyboardInterrupt)
            if server_task: # server_task might not be set if wait_for_server_ready times out
                 await server_task # This will re-raise exceptions from serve_and_write_socket_path

        else: # Not running as main, just run serve() normally
            await server.serve()

        logger.info("Dummy server finished serving.")

    # KeyboardInterrupt is now primarily handled by RPCPluginServer's signal handler (for graceful, then hard exit)
    # or by the top-level except block around asyncio.run().
    # except KeyboardInterrupt:  # pragma: no cover
    #     logger.info("Dummy server stopped by user (KeyboardInterrupt in main coroutine).")
    #     if server_task and not server_task.done():
    #         server_task.cancel()
    except Exception as e:  # pragma: no cover
        logger.error(f"Dummy server encountered an error in main coroutine: {e}", exc_info=True)
        if server_task and not server_task.done():
            server_task.cancel()
    finally:
        logger.info("Dummy server shutting down.")
        if server_task and not server_task.done(): # Ensure task is awaited if it exists
            with suppress(asyncio.CancelledError):
                await server_task
        # server.stop() is implicitly called by RPCPluginServer.serve()'s finally block,
        # or explicitly if server_task was used and an exception occurred.
        # If we ran serve() in a task, we should ensure server.stop() is called if not already.
        if is_running_as_main and server and hasattr(server, '_server') and server._server is not None:
             if not server._serving_future.done(): # Check if server is still marked as serving
                logger.info("Ensuring server.stop() is called in finally block for main execution.")
                await server.stop()

        if is_running_as_main and socket_comm_file.exists():
            try:
                logger.info(f"Cleaning up {socket_comm_file}")
                socket_comm_file.unlink()
            except OSError as e:
                logger.warning(f"Could not remove {socket_comm_file}: {e}")


if __name__ == "__main__":
    # This allows the script to be run directly as a plugin executable.
    # Additional imports for the new logic if run as main
    from pathlib import Path
    from contextlib import suppress

    try:
        asyncio.run(main())
    except KeyboardInterrupt: # Gracefully handle Ctrl+C at the asyncio.run level too
        logger.info("Main execution interrupted by user.")
