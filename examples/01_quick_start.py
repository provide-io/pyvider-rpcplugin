#!/usr/bin/env python3
# examples/01_quick_start.py
"""Demonstrates basic RPC plugin server and client setup with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path
import os
import grpc # Added for grpc.aio.AioRpcError

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Add demo directory to sys.path to import echo_pb2 and echo_pb2_grpc
demo_dir = example_dir / "demo"
if demo_dir.exists() and str(demo_dir) not in sys.path:
    sys.path.insert(0, str(demo_dir))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    plugin_protocol,
    create_basic_protocol,
)
from pyvider.telemetry import logger  # noqa: E402

# Attempt to import Echo service definitions
try:
    import echo_pb2
    import echo_pb2_grpc
except ImportError as e:
    logger.error(f"Failed to import echo_pb2 or echo_pb2_grpc: {e}")
    logger.error("Please ensure you've compiled the protobuf definitions in the 'examples/demo' directory.")
    sys.exit(1)


class SimpleGreeterService:
    """Simple handler that implements a greeting service."""
    async def SayHello(self, request, context):
        name = getattr(request, 'name', 'World')
        message = f"Hello, {name}!"
        
        logger.info(
            "Greeting request processed",
            domain="rpc",
            action="say_hello", 
            status="success",
            client_name=name,
            response_length=len(message)
        )
        # For this example, we'll return a simple dict-like response
        # In production, this would be a proper protobuf message
        class HelloReply: # Mock protobuf message
            def __init__(self, message):
                self.message = message
        return HelloReply(message=message)

async def example_1_basic_server():
    """
    Example 1A: Demonstrates basic RPC server setup.
    """
    print("\n" + "=" * 60)
    print("🛎️ Example 1A: Basic RPC Server Setup")
    print(" Demonstrates: Simple server creation and startup")
    print("=" * 60)

    protocol = create_basic_protocol() # Uses a dummy "TestService"
    handler = SimpleGreeterService() # This handler won't be called by basic_protocol

    server = plugin_server(
        protocol=protocol,
        handler=handler, # Handler is passed but basic_protocol doesn't use it
        transport="unix"
    )

    logger.info(
        "Starting RPC server (Example 1A)",
        domain="server",
        action="startup",
        status="starting",
        transport="unix",
        protocol="basic"
    )

    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5) # Give server time to initialize

    server_address = getattr(server.transport, 'endpoint', None)
    if not server_address:
        logger.error("Server address not found for Example 1A server.")
        await server.stop()
        await server_task
        raise RuntimeError("Server address not found after startup for Example 1A.")

    logger.info(
        "RPC server (Example 1A) started successfully",
        domain="server",
        action="startup",
        status="success",
        endpoint=server_address
    )

    # This server is self-contained and shuts down after this example part.
    await server.stop()
    await server_task

    logger.info(
        "RPC server (Example 1A) stopped",
        domain="server",
        action="shutdown",
        status="success"
    )


async def example_1_basic_client():
    """
    Example 1B: Demonstrates basic RPC client connection to the Echo server.
    """
    print("\n" + "=" * 60)
    print("🙋 Example 1B: Basic RPC Client Connection (to Echo Server)")
    print(" Demonstrates: Client creation and RPC calls using echo_server.py")
    print("=" * 60)

    server_script_path = str(example_dir / "demo" / "echo_server.py")

    logger.info(
        "Creating RPC client for Echo service",
        domain="client",
        action="create",
        status="starting",
        server_path=server_script_path
    )

    # Define the protocol for the Echo service
    echo_service_protocol = plugin_protocol(
        service_name="EchoService", # Matches the service name in echo.proto
        descriptor_module=echo_pb2,
        servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server
    )
    
    # Environment variables for the plugin process
    plugin_env_vars = {
        "PYTHONUNBUFFERED": "1",
        "PLUGIN_MAGIC_COOKIE_KEY": "ECHO_PLUGIN_COOKIE",      # Server will use this as the key name for the cookie it expects
        "PLUGIN_MAGIC_COOKIE_VALUE": "standalonesecret",      # Server will expect this value for that cookie
        "ECHO_PLUGIN_COOKIE": "standalonesecret"              # This IS the cookie value the client provides, made available to server env
    }

    # Set environment variables for the CLIENT process *before* RPCPluginClient is initialized
    # This ensures the client sends the correct cookie value.
    os.environ["PLUGIN_MAGIC_COOKIE"] = "standalonesecret"
    # This key tells the client what environment variable to look for in the server's handshake response (if no cert)
    # or what key to use if it needs to send its own cookie value (which is PLUGIN_MAGIC_COOKIE).
    # For the server side, this means the server will announce itself with this cookie key.
    os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "ECHO_PLUGIN_COOKIE"


    client = plugin_client(
        server_path=server_script_path,
        protocol=echo_service_protocol,
        env=plugin_env_vars, # Pass environment variables to the server process
        auto_connect=False # We will connect manually
    )

    try:
        await client.start() # Start the client (which includes connecting)
        logger.info(
            "Client connected successfully to Echo server",
            domain="client",
            action="connect",
            status="success"
            # target=client.transport.endpoint if client.transport else "N/A" # Removed
        )

        # Access the stub for EchoService
        if not client._channel:
            logger.error("Client channel is not available after start.")
            await client.close()
            return

        echo_stub = echo_pb2_grpc.EchoServiceStub(client._channel)

        # Make an RPC call
        message_to_send = "Hello from QuickStart Client!"
        logger.info(
            "Making RPC call to EchoService.Echo",
            domain="client",
            action="rpc_call",
            status="starting",
            method="Echo",
            request_data={"message": message_to_send}
        )

        request = echo_pb2.EchoRequest(message=message_to_send)
        response = await echo_stub.Echo(request)

        logger.info(
            "RPC call completed",
            domain="client",
            action="rpc_call",
            status="success",
            method="Echo",
            response=response.reply
        )
        print(f"Client received: {response.reply}")

    except Exception as e:
        logger.error(
            "Client operation failed",
            domain="client",
            action="rpc_call",
            status="error",
            error=str(e),
            exc_info=True
        )
    finally:
        if client:
            await client.close()
            logger.info(
                "Client connection closed",
                domain="client",
                action="disconnect",
                status="success"
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
    
    workflow_steps = [
        "🚀 Initialize RPC framework",
        "🛎️ Start RPC server with service handlers", 
        "🙋 Create client and establish connection",
        "📤 Send RPC requests from client to server",
        "⚙️ Process requests in server handlers",
        "📥 Receive responses back at client",
        "🔌 Close client connections gracefully",
        "🛑 Shutdown server and cleanup resources"
    ]
    
    for i, step in enumerate(workflow_steps, 1):
        logger.info(
            f"Workflow step {i}",
            domain="workflow",
            action="step",
            status="completed",
            step=step,
            progress=f"{i}/{len(workflow_steps)}"
        )
        await asyncio.sleep(0.1)  # Simulate processing time
    
    logger.info(
        "Complete workflow demonstrated",
        domain="workflow",
        action="complete", 
        status="success",
        total_steps=len(workflow_steps)
    )


async def main():
    """Run all quick start examples."""
    print("🚀 pyvider-rpcplugin Quick Start Examples")
    print("=========================================")
    
    try:
        # Run example 1A (Server)
        await example_1_basic_server()

        # Run example 1B (Client) - this will start its own server instance
        await example_1_basic_client()

        # Run example 1C (Conceptual Workflow)
        await example_1_full_workflow()
        
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
            exc_info=True
        )
        raise
    finally:
        logger.info("Main function finished.")


if __name__ == "__main__":
    # Ensure the script is run from the project root or adjust paths accordingly
    # For simplicity, we assume it's run from the directory containing 'examples' and 'src'
    # or that 'src' is in PYTHONPATH.

    # The following lines are important if you run this script directly from the examples/ directory
    # and your project root is one level up.
    # current_dir = Path(__file__).parent
    # project_root_dir = current_dir.parent
    # sys.path.insert(0, str(project_root_dir / "src"))

    asyncio.run(main())
