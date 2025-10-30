#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A minimal RPC plugin server for the Quick Start example.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup."""

import asyncio

# Import example_utils directly as it's in the same directory
import example_utils  # type: ignore[import-not-found]

# This should be called before other pyvider imports if this script is run directly.
# It sets up paths and default config (e.g., disabling mTLS for basic examples).
example_utils.configure_for_example()

# Import the shared DummyHandler
from example_utils import DummyHandler  # noqa: E402
from provide.foundation import logger  # noqa: E402

from pyvider.rpcplugin import plugin_protocol, plugin_server  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.types import (  # noqa: E402
    RPCPluginProtocol as TypesRPCPluginProtocol,
)


async def main() -> None:
    """Sets up and runs the dummy server for Quick Start."""
    logger.info("🚀 dummy_server.py (Quick Start version): Starting as an executable plugin...")

    # `configure_for_example()` called at the module level sets up default
    # configurations, including a default magic cookie key/value and disabling
    # mTLS by default. The launching client (quick_start_client.py) is
    # expected to set the environment variable matching PLUGIN_MAGIC_COOKIE_KEY
    # with the value from PLUGIN_MAGIC_COOKIE_VALUE from its own configuration.

    protocol: TypesRPCPluginProtocol = plugin_protocol()  # Uses BasicRPCPluginProtocol
    handler = DummyHandler()  # Using the basic handler

    # plugin_server factory will use configurations from environment/global_config
    # (e.g., transport type, which defaults to 'unix' then 'tcp').
    server: RPCPluginServer = plugin_server(protocol=protocol, handler=handler)

    # --- Logic for direct client connection START ---
    # Determine if running as main for the special socket path writing behavior
    # or if specific env var PYVIDER_WRITE_SOCKET_PATH is set.
    # This allows direct_client_connection.py to work with this server.
    should_write_socket_path = __name__ == "__main__" or os.getenv("PYVIDER_WRITE_SOCKET_PATH") == "true"
    server_task = None
    socket_comm_file = None

    if should_write_socket_path:
        project_root_for_socket_file = Path(__file__).resolve().parent.parent
        socket_comm_file = project_root_for_socket_file / "dummy_server_socket.txt"
    # --- Logic for direct client connection END ---

    try:
        logger.info(
            "Dummy server (Quick Start version) attempting to start and serve (will print handshake)..."
        )

        if should_write_socket_path:

            async def serve_and_write_socket_path() -> None:
                await server.serve()

            server_task = asyncio.create_task(serve_and_write_socket_path())
            await server.wait_for_server_ready(timeout=10.0)

            if server.transport and server.transport.endpoint and socket_comm_file:
                if server._transport_name == "unix":
                    logger.info(f"Writing socket path: {server.transport.endpoint} to {socket_comm_file}")
                    try:
                        with open(socket_comm_file, "w") as f:
                            f.write(str(server.transport.endpoint))
                    except OSError as e:
                        logger.error(f"Failed to write socket path: {e}")
                else:
                    logger.info(f"{server._transport_name} (not unix), no socket path written.")
            else:
                logger.warning("Server transport/endpoint not available. Cannot write socket path.")

            if server_task:  # server_task might not be set if wait_for_server_ready times out
                await server_task
        else:
            await server.serve()  # This performs handshake and starts serving.

        logger.info("Dummy server (Quick Start version) finished serving.")
    except KeyboardInterrupt:  # pragma: no cover
        logger.info("Dummy server (Quick Start version) stopped by user.")
        if server_task and not server_task.done():  # Also cancel task here
            server_task.cancel()
    except Exception as e:  # pragma: no cover
        logger.error(
            f"Dummy server (Quick Start version) encountered an error: {e}",
            exc_info=True,
        )
        if server_task and not server_task.done():  # Also cancel task here
            server_task.cancel()
    finally:
        logger.info("Dummy server (Quick Start version) shutting down.")
        if server_task and not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                logger.info("Server task cancelled during shutdown.")

        # Attempt to gracefully stop the server if it was started.
        # server.stop() is designed to be idempotent.
        if server:  # Check if server object exists
            await server.stop()

        if should_write_socket_path and socket_comm_file and socket_comm_file.exists():
            try:
                logger.info(f"Cleaning up {socket_comm_file}")
                socket_comm_file.unlink()
            except OSError as e:
                logger.warning(f"Could not remove {socket_comm_file}: {e}")


if __name__ == "__main__":
    # This allows the script to be run directly as a plugin executable
    # by RPCPluginClient, or for the direct connection example.
    import os  # Required for getenv and Path
    from pathlib import Path  # Required for Path

    from pyvider.rpcplugin import (
        configure as pyvider_core_configure,
        rpcplugin_config,
    )  # For standalone setup

    if os.getenv("PYVIDER_WRITE_SOCKET_PATH") == "true":
        # If run for direct connection, ensure magic cookie is set for self-handshake
        cookie_key_to_set_in_env = rpcplugin_config.plugin_magic_cookie_key
        expected_cookie_value = rpcplugin_config.plugin_magic_cookie_value
        env_var_name_for_cookie = "PYVIDER_PLUGIN_MAGIC_COOKIE"  # Default from example_utils
        if cookie_key_to_set_in_env != env_var_name_for_cookie:
            env_var_name_for_cookie = cookie_key_to_set_in_env
        os.environ[env_var_name_for_cookie] = expected_cookie_value
        pyvider_core_configure(PLUGIN_MAGIC_COOKIE_KEY=env_var_name_for_cookie)
        logger.info(
            f"Standalone server mode (for direct connection): "
            f"Set os.environ['{env_var_name_for_cookie}'] = '{expected_cookie_value}'. "
            f"RPCPlugin configured to use '{env_var_name_for_cookie}' as cookie key."
        )

    import sys

    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: dummy_server.py")
        print(__doc__)
        sys.exit(0)

    asyncio.run(main())

# 🔌📞🔚
