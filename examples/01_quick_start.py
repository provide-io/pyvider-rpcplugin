#!/usr/bin/env python3
# examples/01_quick_start.py
"""Demonstrates basic RPC plugin server and client setup with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path
from typing import Any  # For type hints

import grpc  # For ServicerContext
from attrs import define, field

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_client,
    plugin_protocol,
    plugin_server,
)
from pyvider.rpcplugin.config import rpcplugin_config  # noqa: E402
from pyvider.telemetry import logger  # noqa: E402


# HelloReply and SimpleGreeterHandler removed as they are no longer used
# in this client-focused example that uses 00_dummy_server.py.

async def main() -> None:
    """Run a self-contained server and client example."""
    print("🚀 pyvider-rpcplugin Quick Start Example")
    print("=========================================")

    # This example now demonstrates connecting a client to 00_dummy_server.py
    client = None
    dummy_server_command = ["python", str(example_dir / "00_dummy_server.py")]

    try:
        logger.info(f"Attempting to start client with command: {' '.join(dummy_server_command)}")
        client = plugin_client(command=dummy_server_command)
        await client.start() # This starts 00_dummy_server.py and connects
        logger.info("Client connected to 00_dummy_server.py successfully!")

        if client.is_started:
            print("\n✅ Client is connected to the 00_dummy_server.py!")
            print("   The dummy server has a simple NoOp method.")
            print("   In a real app with a matching proto, you could make calls here.")
            # e.g., if dummy server had a 'NoOp' method available via a stub:
            # await stub.NoOp(NoOpRequest())

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
    finally:
        # --- Shutdown ---
        if client and client.is_started:
            await client.close() # This will also stop the 00_dummy_server.py process
            logger.info("Client closed (and dummy server stopped).")
        elif client: # if client object exists but not started (e.g. start failed)
            await client.close() # Ensure cleanup of any partial resources
            logger.info("Client (which may not have fully started) closed.")

        print("\n✅ Quick Start Example Finished.")


if __name__ == "__main__":
    asyncio.run(main())
