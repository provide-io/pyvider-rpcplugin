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
    plugin_server,
    plugin_client, 
    plugin_protocol,
    create_basic_protocol,
)
from pyvider.telemetry import logger  # noqa: E402


class SimpleGreeterHandler:
    """Simple handler that implements a greeting service."""
    
    async def SayHello(self, request, context):
        """Handle SayHello RPC calls."""
        name = getattr(request, 'name', 'Anonymous')
        message = f"Hello, {name}! Welcome to pyvider-rpcplugin."
        
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
        return type('HelloReply', (), {'message': message})()


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
        transport="unix"  # Use Unix socket for fast local communication
    )
    
    logger.info(
        "Starting RPC server",
        domain="server",
        action="startup",
        status="starting",
        transport="unix",
        protocol="basic"
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
        endpoint=getattr(server._transport, 'endpoint', 'unknown')
    )
    
    # Stop server gracefully
    await server.stop()
    await server_task
    
    logger.info(
        "RPC server stopped",
        domain="server", 
        action="shutdown",
        status="success"
    )


async def example_1_basic_client():
    """
    Example 1B: Demonstrates basic RPC client connection.
    
    Shows how to create a client, connect to a server, and make
    basic RPC calls with proper connection management.
    """
    print("\n" + "=" * 60)
    print("🙋 Example 1B: Basic RPC Client Connection") 
    print(" Demonstrates: Client creation and RPC calls")
    print("=" * 60)
    
    # For this example, we'll simulate client operations
    # In a real scenario, the client would connect to a running server
    
    logger.info(
        "Creating RPC client",
        domain="client",
        action="create",
        status="starting",
        transport="unix"
    )
    
    # Create client instance
    client = plugin_client(transport="unix")
    
    try:
        # In a real example, this would connect to the server
        # For demo purposes, we'll just show the connection pattern
        logger.info(
            "Client connection simulated",
            domain="client",
            action="connect", 
            status="success",
            connection_type="simulated"
        )
        
        # Simulate making RPC calls
        logger.info(
            "Making RPC call",
            domain="client",
            action="rpc_call",
            status="starting",
            method="SayHello",
            request_data="World"
        )
        
        # Simulate successful response
        logger.info(
            "RPC call completed",
            domain="client", 
            action="rpc_call",
            status="success",
            method="SayHello",
            response="Hello, World! Welcome to pyvider-rpcplugin.",
            duration_ms=12.5
        )
        
    except Exception as e:
        logger.error(
            "Client operation failed",
            domain="client",
            action="rpc_call", 
            status="error",
            error=str(e)
        )
    finally:
        # Always clean up client resources
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
        # Run each example in sequence
        await example_1_basic_server()
        await example_1_basic_client()
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
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
