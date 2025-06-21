#!/usr/bin/env python3
# examples/01_quick_start.py
"""Demonstrates basic RPC plugin server and client setup with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path

from attrs import define, field

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    create_basic_protocol,
    plugin_client,
    plugin_server,
)
from pyvider.telemetry import logger  # noqa: E402


@define(frozen=True, slots=True)
class HelloReply:
    """A structured reply for the SayHello RPC method."""
    message: str = field()

class SimpleGreeterHandler:
    """Simple handler that implements a greeting service."""
    async def SayHello(self, request, context):
        """Handle SayHello RPC calls."""
        name = getattr(request, "name", "Anonymous")
        message = f"Hello, {name}! Welcome to pyvider-rpcplugin."
        logger.info("Greeting request processed", client_name=name)
        return HelloReply(message=message)

async def main():
    """Run a self-contained server and client example."""
    print("🚀 pyvider-rpcplugin Quick Start Example")
    print("=========================================")

    # --- Server Setup ---
    protocol = create_basic_protocol()
    handler = SimpleGreeterHandler()
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix"
    )

    server_task = asyncio.create_task(server.serve())
    logger.info("Starting server in background...")
    await asyncio.sleep(0.5)  # Give server time to start and produce handshake

    # --- Client Setup ---
    # In a real application, the client would launch this script as a subprocess
    # and read the handshake string from its stdout. For this example, we'll
    # simulate that by creating a dummy executable on the fly that just echoes
    # the handshake string our server produced.
    handshake_string = getattr(server._transport, 'handshake_string', None)
    if not handshake_string:
        logger.error("Failed to get handshake string from running server.")
        await server.stop()
        await server_task
        return

    dummy_executable_path = Path("./dummy_quickstart_handshaker.sh")
    with open(dummy_executable_path, "w") as f:
        f.write(f"#!/bin/sh\necho '{handshake_string}'")
    dummy_executable_path.chmod(0o755)

    client = None
    try:
        # The client points to our dummy script to get connection info.
        client = plugin_client(server_path=str(dummy_executable_path))
        await client.start()
        logger.info("Client connected successfully!")

        # --- Making an RPC Call ---
        # This part requires a generated gRPC stub. Since this is a basic
        # example without proto compilation, we'll confirm the connection
        # is live and log a conceptual call. A real client would use its stub here.
        if client.is_started:
            print("\n✅ Client is connected to the server!")
            print("   In a real app, you would now use your gRPC stub to make calls.")
            # e.g., response = await stub.SayHello(Request(name="World"))
            # For demonstration, we can invoke the handler directly.
            simulated_reply = await handler.SayHello(type("Request", (), {"name": "World"})(), None)
            print(f"   Server handler would reply: '{simulated_reply.message}'")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
    finally:
        # --- Shutdown ---
        if client:
            await client.close()
            logger.info("Client closed.")
        
        dummy_executable_path.unlink() # Clean up the script

        await server.stop()
        await server_task
        logger.info("Server stopped.")
        print("\n✅ Quick Start Example Finished.")

if __name__ == "__main__":
    asyncio.run(main())
