#!/usr/bin/env python3
# examples/01_quick_start.py
"""Demonstrates basic RPC plugin server and client setup with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path

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


class SimpleGreeterHandler:
    """Simple handler that implements a greeting service."""

    async def SayHello(self, request, context):
        """Handle SayHello RPC calls."""
        name = getattr(request, "name", "Anonymous")
        message = f"Hello, {name}! Welcome to pyvider-rpcplugin."

        logger.info(
            "Greeting request processed",
            domain="rpc",
            action="say_hello",
            status="success",
            client_name=name,
            response_length=len(message),
        )

        # For this example, we'll return a simple dict-like response
        # In production, this would be a proper protobuf message
        return type("HelloReply", (), {"message": message})()


async def example_1_basic_server():
    """
    Example 1A: Demonstrates basic RPC server setup.

    Shows how to create a minimal RPC server using the factory functions
    with default configuration and a simple handler.
    """
    print("\n" + "=" * 60)
    print("🛎️ Example 1A: Basic RPC Server Setup")
    print(" Demonstrates: Simple server creation and startup")
    print("=" * 60)

    # Create a basic protocol for demonstration
    # In production, you'd use your actual protobuf definitions
    protocol = create_basic_protocol()

    # Create handler instance
    handler = SimpleGreeterHandler()

    # Create server with default settings (Unix socket transport)
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",  # Use Unix socket for fast local communication
    )

    logger.info(
        "Starting RPC server",
        domain="server",
        action="startup",
        status="starting",
        transport="unix",
        protocol="basic",
    )

    # Start server in background
    server_task = asyncio.create_task(server.serve())

    # Let server initialize
    await asyncio.sleep(0.5)

    logger.info(
        "RPC server started successfully",
        domain="server",
        action="startup",
        status="success",
        endpoint=getattr(server._transport, "endpoint", "unknown"),
    )

    # Stop server gracefully
    await server.stop()
    await server_task

    logger.info(
        "RPC server stopped", domain="server", action="shutdown", status="success"
    )


async def example_1_basic_client():  # No server_path needed if using dummy executable
    """
    Example 1B: Demonstrates basic RPC client connection.

    Shows how to create a client, connect to a server, and make
    basic RPC calls with proper connection management.
    This version uses a dummy executable for client startup.
    """
    print("\n" + "=" * 60)
    print("🙋 Example 1B: Basic RPC Client Connection (using dummy server)")
    print(" Demonstrates: Client creation and RPC calls (simulated)")
    print("=" * 60)

    logger.info(
        "Creating RPC client with dummy server path",
        domain="client",
        action="create",
        status="starting",
        server_executable=str(example_dir / "dummy_server.sh"),
    )

    # plugin_client expects path to an executable
    client = plugin_client(server_path=example_dir / "dummy_server.sh")

    try:
        # For dummy_server.sh, we don't want to fully start the client,
        # as it's not a real gRPC server. We'll skip client.start().
        # await client.start()  # This replaces connect()
        logger.info(
            "Client instance created for dummy server process (connection not established)",
            domain="client",
            action="create_for_simulation",
            status="simulated_connection",
        )

        # Simulate making an RPC call as direct calls will fail with dummy_server.sh
        logger.info(
            "Simulating RPC call to SayHello",
            domain="client",
            action="rpc_call_simulation",  # Renamed
            status="simulating",
            method="SayHello",
            request_data={"name": "QuickStartClient"},
        )

        # Fake response
        simulated_response_message = (
            "Hello, QuickStartClient! Welcome from dummy server."
        )
        logger.info(
            "Simulated RPC call completed",
            domain="client",
            action="rpc_call_simulation",  # Renamed
            status="success",
            method="SayHello",
            response=simulated_response_message,
        )

    except Exception as e:
        logger.error(
            "Client operation failed",
            domain="client",
            action="client_lifecycle",  # Generic action
            status="error",
            error=str(e),
        )
    finally:
        # Always clean up client resources
        # RPCPluginClient has shutdown_plugin and close
        if (
            hasattr(client, "_controller_stub") and client._controller_stub
        ):  # Check if stubs were created
            await client.shutdown_plugin()  # Gracefully ask server to shutdown
        await client.close()  # Close client-side resources
        logger.info(
            "Client connection closed",
            domain="client",
            action="disconnect",  # Kept "disconnect" for consistency
            status="success",
        )


async def example_1_full_workflow():
    """
    Example 1C: Demonstrates a complete server-client workflow.

    Shows how server and client work together in a realistic
    scenario with proper lifecycle management.
    """
    print("\n" + "=" * 60)
    print("🔄 Example 1C: Complete Server-Client Workflow")
    print(" Demonstrates: Full RPC communication lifecycle")
    print("=" * 60)

    # This demonstrates the conceptual workflow
    # In practice, server and client often run in separate processes

    workflow_steps = [
        "🚀 Initialize RPC framework",
        "🛎️ Start RPC server with service handlers",
        "🙋 Create client and establish connection",
        "📤 Send RPC requests from client to server",
        "⚙️ Process requests in server handlers",
        "📥 Receive responses back at client",
        "🔌 Close client connections gracefully",
        "🛑 Shutdown server and cleanup resources",
    ]

    for i, step in enumerate(workflow_steps, 1):
        logger.info(
            f"Workflow step {i}",
            domain="workflow",
            action="step",
            status="completed",
            step=step,
            progress=f"{i}/{len(workflow_steps)}",
        )
        await asyncio.sleep(0.1)  # Simulate processing time

    logger.info(
        "Complete workflow demonstrated",
        domain="workflow",
        action="complete",
        status="success",
        total_steps=len(workflow_steps),
    )


async def main():
    """Run all quick start examples."""
    print("🚀 pyvider-rpcplugin Quick Start Examples")
    print("=========================================")

    # Server part: Start a real server.
    # Client part: Will use plugin_client with dummy_server.sh, so it's independent.

    # --- Server Setup and Run ---
    server_protocol = create_basic_protocol()
    server_handler = SimpleGreeterHandler()
    actual_server = plugin_server(
        protocol=server_protocol, handler=server_handler, transport="unix"
    )
    server_task = None

    try:
        logger.info("Starting actual server for example...")
        # The server will print its handshake string to stdout here.
        # For this example, the client part won't use this server directly,
        # but it's good to show a server running.
        server_task = asyncio.create_task(actual_server.serve())
        await asyncio.sleep(0.5)  # Let server initialize

        actual_server_socket_path = getattr(
            actual_server._transport, "endpoint", "unknown_socket"
        )
        logger.info(f"Actual server started, socket path: {actual_server_socket_path}")

        # --- Client Run (uses dummy_server.sh, independent of actual_server) ---
        await example_1_basic_client()  # No longer needs server_path from actual_server

        # --- Conceptual Workflow ---
        await example_1_full_workflow()  # This logs conceptual steps

        print("\n" + "=" * 60)
        print("✅ All Quick Start Examples Completed Successfully!")
        print("=" * 60)
        print("\n🎯 Next Steps:")
        print("  • Try example 02_server_setup.py for advanced server configuration")
        print("  • See example 03_client_connection.py for robust client patterns")
        print("  • Check out the complete example series in examples/README.md")

    except Exception as e:
        logger.error(
            "Quick start example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e),
        )
        # Ensure actual_server is stopped in case of an error
        if (
            actual_server
            and actual_server._serving_future
            and not actual_server._serving_future.done()
        ):
            logger.info("Stopping actual_server due to an error in examples...")
            await actual_server.stop()  # Use await server.stop()
            # The server_task should also be awaited or cancelled
            if server_task and not server_task.done():
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    logger.info("Server task cancelled.")
        raise
    finally:
        # Ensure actual_server is always stopped cleanly
        if (
            actual_server
            and actual_server._serving_future
            and not actual_server._serving_future.done()
        ):
            logger.info("Stopping actual_server after examples completion...")
            await actual_server.stop()  # Use await server.stop()
            if server_task and not server_task.done():
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    logger.info("Server task cancelled during final cleanup.")
            logger.info("Actual server stopped.")
        elif server_task and server_task.done():
            try:
                server_task.result()  # Retrieve potential exceptions from server task
            except Exception as task_exc:
                logger.error(
                    f"Actual server task finished with an exception: {task_exc}"
                )


if __name__ == "__main__":
    asyncio.run(main())
