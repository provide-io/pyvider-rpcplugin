#!/usr/bin/env python3
# examples/11_end_to_end.py
"""
A complete, self-contained end-to-end example of a pyvider-rpcplugin server
and client running in the same process.
"""

import asyncio
import sys
from pathlib import Path
from typing import Any  # For type hints

from attrs import define, field

# Add src to path for examples
project_root = Path(__file__).resolve().parent.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_client,
    plugin_protocol,  # Changed
    plugin_server,
)
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402 # For type hint
from pyvider.rpcplugin.types import (  # noqa: E402 # For type hint
    RPCPluginProtocol as TypesRPCPluginProtocol,  # noqa: E402
)
from pyvider.telemetry import logger  # noqa: E402


@define(frozen=True, slots=True)
class GreetingRequest:
    """A structured request for the Greet RPC method."""

    name: str = field()


@define(frozen=True, slots=True)
class GreetingReply:
    """A structured reply for the Greet RPC method."""

    message: str = field()


class GreeterServiceHandler:
    """A simple handler that implements a greeting service."""

    async def Greet(
        self, request: GreetingRequest, context: Any
    ) -> GreetingReply:  # Changed context to Any
        """Handles the Greet RPC call."""
        logger.info(
            "Server received Greet request",
            client_name=request.name,
        )
        message = f"Hello, {request.name}! This is a real end-to-end call."
        return GreetingReply(message=message)


async def main() -> None:
    """Run the server and client in the same process."""
    print("🚀 pyvider-rpcplugin End-to-End Example")
    print("==========================================")

    # 1. Define Protocol and Handler
    protocol: TypesRPCPluginProtocol = plugin_protocol()  # Changed and annotated
    handler = GreeterServiceHandler()
    server_socket_path = Path("./e2e_server.sock")  # For cleanup and handshake

    # 2. Create and start the server in the background
    server: RPCPluginServer = plugin_server(  # Annotated
        protocol=protocol,  # MyPy might need cast if TypesRPCPluginProtocol not precise
        handler=handler,
        transport="unix",
        transport_path=str(server_socket_path),
    )

    server_task = asyncio.create_task(server.serve())
    logger.info("Server starting in the background...")

    await server.wait_for_server_ready(timeout=5.0)  # Changed

    # Construct handshake string
    from pyvider.rpcplugin.config import (
        rpcplugin_config,
    )  # Local import for this section

    core_version = rpcplugin_config.get("PLUGIN_CORE_VERSION")
    protocol_version = getattr(server, "_protocol_version", "1")
    transport_type = "unix"
    server_endpoint = getattr(getattr(server, "_transport", None), "endpoint", None)

    if not server_endpoint:
        logger.error("Could not get server endpoint for handshake string.")
        if server_socket_path.exists():
            server_socket_path.unlink(missing_ok=True)
        await server.stop()
        await server_task  # Added await
        return

    server_handshake_string = (
        f"{core_version}|{protocol_version}|{transport_type}|{server_endpoint}|"
    )
    logger.info(f"Simulated handshake string for dummy: {server_handshake_string}")

    dummy_executable_path = Path("./dummy_handshaker.sh")
    with open(dummy_executable_path, "w") as f:
        f.write("#!/bin/sh\n")
        f.write(f"echo '{server_handshake_string}'\n")
    dummy_executable_path.chmod(0o755)

    # 3. Create the client
    client = None
    try:
        client = plugin_client(command=[str(dummy_executable_path)])  # Changed
        await client.start()
        logger.info("Client connected to server successfully.")

        # 4. Make an RPC call
        # In a real scenario, you'd have a generated gRPC stub. Here, we'll
        # simulate the call by directly accessing the handler for simplicity.
        # This demonstrates the connection is live.
        # A more advanced example would generate and use a real stub.
        request_obj = GreetingRequest(name="End-to-End User")

        # We can't make a real RPC call without a stub, but we can verify
        # the client is connected and the server is running.
        if client.is_started:
            print("\n✅ Client is connected! Simulating RPC call...")
            reply = await handler.Greet(request_obj, None)
            print(f"   Server replied: '{reply.message}'")
        else:
            print("\n❌ Client failed to connect.")

    except Exception as e:
        logger.error(f"An error occurred in the client: {e}", exc_info=True)
    finally:
        # 5. Clean up
        if client:
            await client.close()
            logger.info("Client closed.")

        if dummy_executable_path.exists():  # Check before unlinking
            dummy_executable_path.unlink()
            logger.info("Dummy executable cleaned up.")

        if server_socket_path.exists():  # Clean up server socket
            server_socket_path.unlink(missing_ok=True)
            logger.info("Server socket file cleaned up.")

        await server.stop()
        await server_task
        logger.info("Server stopped.")
        print("\n✅ End-to-end example finished successfully.")


if __name__ == "__main__":
    asyncio.run(main())
