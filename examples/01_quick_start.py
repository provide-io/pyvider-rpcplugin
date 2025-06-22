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


@define(frozen=True, slots=True)
class HelloReply:
    """A structured reply for the SayHello RPC method."""

    message: str = field()


class SimpleGreeterHandler:
    """Simple handler that implements a greeting service."""

    async def SayHello(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> HelloReply:
        """Handle SayHello RPC calls."""
        name = getattr(request, "name", "Anonymous")
        message = f"Hello, {name}! Welcome to pyvider-rpcplugin."
        logger.info("Greeting request processed", client_name=name)
        return HelloReply(message=message)


async def main() -> None:
    """Run a self-contained server and client example."""
    print("🚀 pyvider-rpcplugin Quick Start Example")
    print("=========================================")

    # --- Server Setup ---
    protocol = plugin_protocol()  # Use plugin_protocol factory
    handler = SimpleGreeterHandler()
    # For this example, let's specify a transport_path for predictability
    server_socket_path = Path("./quickstart_server.sock")
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",
        transport_path=str(server_socket_path),
    )

    server_task = asyncio.create_task(server.serve())
    logger.info("Starting server in background...")

    try:
        # Wait for server to be ready and its transport configured
        await server.wait_for_server_ready(timeout=5.0)
        logger.info("Server is ready.")

        # Construct the handshake string that this server would produce
        # This is specific to this example's setup (unix, no TLS)
        # Core Version | Protocol Version | Network Type | Address | Cert (empty)
        core_version = rpcplugin_config.get("PLUGIN_CORE_VERSION")
        # Accessing private _protocol_version and _transport for example purposes
        protocol_version = getattr(
            server, "_protocol_version", "1"
        )  # Default if not found
        transport_type = "unix"
        server_endpoint = getattr(getattr(server, "_transport", None), "endpoint", None)

        if not server_endpoint:
            raise RuntimeError("Server endpoint not available after server ready.")

        handshake_string = (
            f"{core_version}|{protocol_version}|{transport_type}|{server_endpoint}|"
        )
        logger.info(f"Simulated handshake string for dummy: {handshake_string}")

        dummy_executable_path = Path("./dummy_quickstart_handshaker.sh")
        with open(dummy_executable_path, "w") as f:
            f.write(f"#!/bin/sh\necho '{handshake_string}'")
        dummy_executable_path.chmod(0o755)

        client = None
        # The client points to our dummy script to get connection info.
        client = plugin_client(
            command=[str(dummy_executable_path)]
        )  # Changed to command
        await client.start()
        logger.info("Client connected successfully!")

        # --- Making an RPC Call ---
        if client.is_started:
            print("\n✅ Client is connected to the server!")
            print("   In a real app, you would now use your gRPC stub to make calls.")
            simulated_reply = await handler.SayHello(
                type("Request", (), {"name": "World"})(), None
            )
            print(f"   Server handler would reply: '{simulated_reply.message}'")

    except Exception as e:
        logger.error(
            f"An error occurred during server/client operations: {e}", exc_info=True
        )
    finally:
        # --- Shutdown ---
        if client and client.is_started:
            await client.close()
            logger.info("Client closed.")

        if dummy_executable_path.exists():  # Check if created before unlinking
            dummy_executable_path.unlink()
            logger.info("Dummy executable cleaned up.")

        if server_socket_path.exists():
            server_socket_path.unlink(missing_ok=True)
            logger.info("Server socket file cleaned up.")

        # Ensure server stops and task completes
        if server_task:
            if not server_task.done():
                logger.info("Requesting server stop...")
                server.stop()  # This should set the future for server.serve()
                try:
                    await asyncio.wait_for(server_task, timeout=5.0)
                    logger.info("Server task completed after stop request.")
                except TimeoutError:
                    logger.error(
                        "Timeout waiting for server task to complete after stop."
                    )
                    server_task.cancel()  # Force cancel if stop doesn't work quickly
                    try:
                        await server_task
                    except asyncio.CancelledError:
                        logger.info("Server task forcefully cancelled.")
                except Exception as e_task:
                    logger.error(
                        f"Server task raised an exception during shutdown: {e_task}"
                    )

            else:  # Server task already done
                exc = server_task.exception()
                if exc:
                    logger.error(
                        f"Server task had already exited with exception: {exc}",
                        exc_info=exc,
                    )
                else:
                    logger.info("Server task was already completed successfully.")
        logger.info("Server shutdown process complete.")
        print("\n✅ Quick Start Example Finished.")


if __name__ == "__main__":
    asyncio.run(main())
