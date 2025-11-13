#!/usr/bin/env python3
"""
Quick Start Example - Client launching an executable plugin server.
This example demonstrates the `plugin_client` launching the `00_dummy_server.py`
executable and establishing a connection.
"""

import asyncio
import sys
from pathlib import Path

# Setup example environment by calling configure_for_example()
# This ensures paths are set and basic configuration (like disabling mTLS by default
# and setting a default magic cookie) is applied for examples.
from example_utils import configure_for_example

configure_for_example()

from pyvider.rpcplugin import plugin_client  # noqa: E402
from pyvider.rpcplugin.client.base import RPCPluginClient  # noqa: E402
from pyvider.rpcplugin.exception import RPCPluginError  # noqa: E402
from pyvider.telemetry import logger  # noqa: E402


async def main():
    """Run the quick start client example."""
    logger.info(
        "🚀 Starting pyvider-rpcplugin Quick Start Example (Client Launching Plugin)"
    )

    # Determine the path to the 00_dummy_server.py executable
    example_dir = Path(__file__).resolve().parent
    dummy_server_executable = example_dir / "00_dummy_server.py"

    if not dummy_server_executable.exists():
        logger.error(f"Dummy server executable not found at: {dummy_server_executable}")
        logger.error("Please ensure 00_dummy_server.py is in the same directory.")
        return

    # The command to launch the plugin server
    # Using sys.executable ensures we use the same Python interpreter
    dummy_server_command = [sys.executable, str(dummy_server_executable)]

    # `configure_for_example()` should have set these:
    # PLUGIN_AUTO_MTLS=False
    # PLUGIN_MAGIC_COOKIE_KEY="PYVIDER_PLUGIN_MAGIC_COOKIE"
    # PLUGIN_MAGIC_COOKIE_VALUE="pyvider-example-cookie"
    # `plugin_client` will read these from config and set the
    # PYVIDER_PLUGIN_MAGIC_COOKIE environment variable for the
    # dummy_server_command process.

    client: RPCPluginClient | None = None  # Ensure client is defined for finally block
    try:
        logger.info(
            f"Client attempting to launch plugin: {' '.join(dummy_server_command)}"
        )
        client = plugin_client(command=dummy_server_command)

        logger.info("Starting client and connecting to plugin...")
        await client.start()  # This launches the subprocess and performs handshake

        logger.info("✅ Client connected to dummy_server plugin successfully!")
        logger.info(
            "   The dummy_server provides a basic protocol with no custom methods."
        )
        logger.info(
            "   If it had methods defined in a .proto, "
            "you would use generated stubs here:"
        )
        logger.info("   e.g., stub = YourServiceStub(client.grpc_channel)")
        logger.info("         await stub.YourMethod(YourRequest())")
        logger.info("   For this example, successful connection is the main goal.")

        # Keep the connection open for a short while to observe
        await asyncio.sleep(2)  # Show it's running

    except RPCPluginError as e:
        logger.error(f"❌ Client RPCPluginError: {e.message}", exc_info=True)
        if e.hint:
            logger.error(f"   Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)
    finally:
        if client and client.is_started:
            logger.info("Shutting down client and plugin...")
            # This will also request the plugin server (00_dummy_server.py) to shut down
            # via its controller service, and then terminate the process if needed.
            await client.close()
            logger.info("Client and plugin shut down.")
        elif client:  # If client was created but not started (e.g. error before start)
            await client.close()  # Still attempt cleanup
            logger.info("Client (not started) resources cleaned up.")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🚀
