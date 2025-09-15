#!/usr/bin/env python3
# examples/ch02_quick_start_client.py
"""
Quick Start Example - Client launching an executable plugin server.
"""

import asyncio
import sys
from pathlib import Path

# Import example_utils directly as it's in the same directory
import example_utils  # type: ignore[import-not-found] # noqa: E402

example_utils.configure_for_example(clear_env=True)  # Client context

from pyvider.rpcplugin import plugin_client  # noqa: E402
from pyvider.rpcplugin.client import (  # noqa: E402
    RPCPluginClient,
)  # Retaining for clarity if user inspects client object
from pyvider.rpcplugin.exception import RPCPluginError  # noqa: E402
from provide.foundation import logger  # noqa: E402


async def main() -> None:
    logger.info("🚀 Starting Quick Start Example (Client Launching Plugin)")
    example_dir = Path(__file__).resolve().parent
    dummy_server_executable = example_dir / "ch02_dummy_server.py"

    if not dummy_server_executable.exists():  # Good practice check
        logger.error(f"Dummy server executable not found at: {dummy_server_executable}")
        return

    dummy_server_command = [sys.executable, str(dummy_server_executable)]
    client: RPCPluginClient | None = None

    try:
        logger.info(f"Client launching plugin: {' '.join(dummy_server_command)}")
        client = plugin_client(command=dummy_server_command)

        logger.info("Starting client and connecting to plugin...")
        await client.start()

        logger.info("✅ Client connected to dummy_server plugin successfully!")
        logger.info(
            "   The dummy_server uses a basic protocol with no custom RPC methods."
        )
        # If your plugin had defined services (e.g., via .proto files),
        # you would create a gRPC stub here using client.grpc_channel:
        # stub = YourServiceStub(client.grpc_channel)
        # response = await stub.YourMethod(YourRequest())
        await asyncio.sleep(2)  # Keep connection alive for demonstration

    except RPCPluginError as e:
        logger.error(f"❌ Client RPCPluginError: {e.message}", exc_info=True)
        if e.hint:
            logger.error(f"   Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)
    finally:
        if client and client.is_started:
            logger.info("Shutting down client and plugin...")
            await client.close()
            logger.info("Client and plugin shut down.")
        elif client:  # Handle case where client was instantiated but not started
            await client.close()
            logger.info("Client (not started) resources cleaned up.")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔌🖥️🪄
