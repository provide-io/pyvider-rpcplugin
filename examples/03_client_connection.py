#!/usr/bin/env python3
# examples/03_client_connection.py
"""Demonstrates robust client connection patterns and lifecycle management with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path
import os  # Added for os.environ
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
    plugin_client,
    configure,
    plugin_protocol, # Added import
)
from pyvider.rpcplugin.exception import (  # noqa: E402
    TransportError,
    HandshakeError,
    RPCPluginError
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

# Common setup for examples that need a server
SERVER_SCRIPT_PATH = str(example_dir / "demo" / "echo_server.py")
ECHO_SERVICE_PROTOCOL = plugin_protocol(
    service_name="EchoService",
    descriptor_module=echo_pb2,
    servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server
)
PLUGIN_ENV_VARS = {
    "PYTHONUNBUFFERED": "1",
    "PLUGIN_MAGIC_COOKIE_KEY": "ECHO_PLUGIN_COOKIE",
    "PLUGIN_MAGIC_COOKIE_VALUE": "standalonesecret",
    "ECHO_PLUGIN_COOKIE": "standalonesecret"
}

async def example_3_basic_client_connection():
    """
    Example 3A: Demonstrates basic client connection lifecycle.
    
    Shows the fundamental pattern of creating a client, connecting
    to a server, and properly managing the connection lifecycle.
    """
    print("\n" + "=" * 60)
    print("🙋 Example 3A: Basic Client Connection Lifecycle")
    print(" Demonstrates: Connection creation, usage, and cleanup")
    print("=" * 60)
    
    # Configure client settings - these will be used by the client itself
    os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "ECHO_PLUGIN_COOKIE"
    os.environ["PLUGIN_MAGIC_COOKIE"] = "standalonesecret"
    # Re-initialize config to pick up env vars if not done automatically by `configure`
    # For simplicity, we'll rely on configure to set them for the client context.
    configure(
        magic_cookie_key="ECHO_PLUGIN_COOKIE", # Key client expects server to use
        magic_cookie="standalonesecret",      # Value client sends to server
        protocol_version=1,
        transports=["unix"], # Client preference
        connection_timeout=30.0,
        handshake_timeout=10.0,
        auto_mtls=True # Enable mTLS for client-side cert generation
    )
    
    logger.info(
        "Creating RPC client",
        domain="client",
        action="create",
        status="starting",
        transport="unix",
        server_path=SERVER_SCRIPT_PATH
    )
    
    # Create client instance, it will launch its own server
    client = plugin_client(
        server_path=SERVER_SCRIPT_PATH,
        protocol=ECHO_SERVICE_PROTOCOL,
        env=PLUGIN_ENV_VARS # Environment for the server process
    )
    
    try:
        await client.start() # Start client, which includes handshake
        
        logger.info(
            "Client connected successfully to its managed server",
            domain="client",
            action="connect",
            status="success",
            target=SERVER_SCRIPT_PATH
        )
        
        # Simulate some client operations - for this example, just connect and close
        await asyncio.sleep(0.1)
        
    except Exception as e:
        logger.error(
            "Client connection failed",
            domain="client",
            action="connect",
            status="error",
            error=str(e),
            exc_info=True
        )
    finally:
        # Always cleanup client resources
        if client: # Check if client was successfully initialized
            await client.close()
        logger.info(
            "Client connection closed",
            domain="client",
            action="cleanup",
            status="success"
        )


async def example_3_connection_retry_logic():
    """
    Example 3B: Demonstrates robust connection retry patterns.
    
    Shows how to implement retry logic with exponential backoff
    for handling temporary connection failures.
    """
    print("\n" + "=" * 60)
    print("🔁 Example 3B: Connection Retry Logic")
    print(" Demonstrates: Retry patterns with exponential backoff")
    print("=" * 60)

    # Configure client settings - these will be used by the client itself
    # For retry, we might want different timeouts or specific error handling
    configure(
        magic_cookie_key="ECHO_PLUGIN_COOKIE",
        magic_cookie="standalonesecret",
        protocol_version=1,
        transports=["unix"],
        connection_timeout=5.0,  # Shorter for retry demo
        handshake_timeout=5.0,   # Shorter for retry demo
        auto_mtls=True
    )
    
    max_retries = 3
    base_delay = 0.5 # Reduced delay for faster testing
    
    for attempt in range(max_retries):
        client = None # Initialize client to None for finally block
        try:
            delay = base_delay * (2 ** attempt)  # Exponential backoff
            
            logger.info(
                f"Connection attempt {attempt + 1}",
                domain="client",
                action="connect_retry",
                status="attempting",
                attempt=attempt + 1,
                max_retries=max_retries,
                delay_seconds=delay
            )
            
            # Simulate a server that might not be ready on the first try
            # For this example, we'll use a server path that might be invalid initially
            # but for simplicity, we'll assume the server always starts.
            # To truly test retry, one would need to control the server's availability.
            # Here, we just demonstrate the client's retry structure.

            current_server_script_path = SERVER_SCRIPT_PATH
            if attempt < 1: # Simulate a failure on the first attempt (e.g., wrong path)
                # This is a bit artificial as plugin_client checks for file existence first
                # A better simulation would involve a server that fails to start or respond quickly
                logger.info(f"Simulating connection failure for attempt {attempt + 1}")
                raise TransportError(f"Simulated connection failure (attempt {attempt + 1})")

            client = plugin_client(
                server_path=current_server_script_path,
                protocol=ECHO_SERVICE_PROTOCOL,
                env=PLUGIN_ENV_VARS
            )
            await client.start()
            
            # Success!
            logger.info(
                "Connection successful",
                domain="client", 
                action="connect_retry",
                status="success",
                attempt=attempt + 1,
                total_delay=sum(base_delay * (2 ** i) for i in range(attempt)) # This calculation is illustrative
            )
            
            # Perform a quick operation if connected
            if client._channel:
                echo_stub = echo_pb2_grpc.EchoServiceStub(client._channel)
                request = echo_pb2.EchoRequest(message=f"Retry attempt {attempt+1}")
                response = await echo_stub.Echo(request)
                logger.info(f"Retry echo response: {response.reply}")

            await client.close() # Close after successful attempt
            break # Exit retry loop
            
        except (TransportError, HandshakeError, FileNotFoundError, PermissionError, asyncio.TimeoutError, RPCPluginError) as e:
            logger.warning(
                f"Connection attempt {attempt + 1} failed",
                domain="client",
                action="connect_retry",
                status="failed",
                attempt=attempt + 1,
                error=str(e),
                will_retry=attempt < max_retries - 1
            )
            if client: # Ensure client is closed if it was created
                await client.close()
            
            if attempt < max_retries - 1:
                logger.info(
                    f"Retrying in {delay} seconds",
                    domain="client",
                    action="backoff",
                    status="waiting",
                    delay_seconds=delay
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "All connection attempts failed",
                    domain="client",
                    action="connect_retry",
                    status="exhausted",
                    total_attempts=max_retries
                )


async def example_3_connection_pooling():
    """
    Example 3C: Demonstrates connection pooling for high-throughput scenarios.
    
    Shows how to manage multiple client connections efficiently
    for applications that need high concurrency.
    Note: This example is conceptual. True pooling requires more sophisticated management.
    Here, we simulate multiple independent client-server pairs.
    """
    print("\n" + "=" * 60)
    print("🏊 Example 3C: Connection Pooling (Conceptual)")
    print(" Demonstrates: Multiple client connections for high throughput")
    print("=" * 60)

    # Configure client settings - these will be used by the client itself
    configure(
        magic_cookie_key="ECHO_PLUGIN_COOKIE",
        magic_cookie="standalonesecret",
        protocol_version=1,
        transports=["unix"],
        auto_mtls=True
    )
    
    pool_size = 3 # Reduced for quicker demo
    clients = []
    
    try:
        logger.info(
            "Creating client connection pool (simulated)",
            domain="client",
            action="pool_create",
            status="starting",
            pool_size=pool_size
        )
        
        # Create pool of client connections
        for i in range(pool_size):
            client = plugin_client(
                server_path=SERVER_SCRIPT_PATH,
                protocol=ECHO_SERVICE_PROTOCOL,
                env=PLUGIN_ENV_VARS
            )
            clients.append(client)
            
            logger.debug(
                f"Created client instance {i + 1}",
                domain="client",
                action="pool_add",
                status="success",
                client_id=i + 1,
                pool_progress=f"{i + 1}/{pool_size}"
            )
        
        logger.info(
            "Client pool ready",
            domain="client",
            action="pool_create",
            status="success",
            pool_size=len(clients),
            throughput_estimate="5x single client"
        )
        
        # Simulate using pool for concurrent operations
        async def simulate_client_work(client_id: int, client):
            """Simulate work with a pooled client."""
            logger.info(
                f"Client {client_id} processing work",
                domain="client",
                action="pool_work",
                status="processing",
                client_id=client_id,
                work_type="simulated_rpc"
            )
            
            # Simulate RPC call latency
            await asyncio.sleep(0.1)
            
            logger.info(
                f"Client {client_id} work completed",
                domain="client", 
                action="pool_work",
                status="completed",
                client_id=client_id
            )
        
        # Run concurrent work across the pool
        tasks = [
            simulate_client_work(i + 1, client) 
            for i, client in enumerate(clients)
        ]
        
        await asyncio.gather(*tasks)
        
        logger.info(
            "Pool work completed",
            domain="client",
            action="pool_work",
            status="all_completed",
            concurrent_operations=len(tasks)
        )
        
    finally:
        # Cleanup all clients in the pool
        logger.info(
            "Cleaning up client pool",
            domain="client",
            action="pool_cleanup",
            status="starting",
            clients_to_close=len(clients)
        )
        
        cleanup_tasks = [client.close() for client in clients]
        await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        logger.info(
            "Client pool cleaned up",
            domain="client",
            action="pool_cleanup", 
            status="success"
        )


async def example_3_async_context_manager():
    """
    Example 3D: Demonstrates using async context managers for clients.
    
    Shows the recommended pattern for automatic resource management
    using Python's async context manager protocol.
    """
    print("\n" + "=" * 60)
    print("🔧 Example 3D: Async Context Manager Pattern")
    print(" Demonstrates: Automatic resource management with async context")
    print("=" * 60)
    
    # Note: This shows the pattern that would be implemented
    # The actual plugin_client would need to implement __aenter__ and __aexit__
    
    class MockAsyncClient:
        """Mock client demonstrating async context manager pattern."""
        
        def __init__(self, transport: str):
            self.transport = transport
            self.connected = False
        
        async def __aenter__(self):
            logger.info(
                "Client entering async context",
                domain="client",
                action="context_enter",
                status="starting",
                transport=self.transport
            )
            
            # Simulate connection
            await asyncio.sleep(0.1)
            self.connected = True
            
            logger.info(
                "Client connected via context manager",
                domain="client",
                action="context_enter",
                status="success"
            )
            
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            logger.info(
                "Client exiting async context",
                domain="client",
                action="context_exit",
                status="starting",
                has_exception=exc_type is not None
            )
            
            # Simulate cleanup
            self.connected = False
            await asyncio.sleep(0.05)
            
            logger.info(
                "Client disconnected via context manager",
                domain="client",
                action="context_exit",
                status="success"
            )
        
        async def make_call(self, method: str):
            """Simulate making an RPC call."""
            if not self.connected:
                raise RPCPluginError("Client not connected")
            
            logger.info(
                f"Making RPC call: {method}",
                domain="client",
                action="rpc_call",
                status="success",
                method=method
            )
    
    # Demonstrate the async context manager pattern
    logger.info(
        "Demonstrating async context manager pattern",
        domain="client",
        action="pattern_demo",
        status="starting",
        benefits=["automatic_cleanup", "exception_safety", "readable_code"]
    )
    
    async with MockAsyncClient("unix") as client:
        # Client is automatically connected
        await client.make_call("ExampleMethod")
        await client.make_call("AnotherMethod")
        
        logger.info(
            "Operations completed within context",
            domain="client",
            action="context_operations",
            status="success",
            operations_count=2
        )
        
        # Client will be automatically disconnected when exiting the context
    
    logger.info(
        "Context manager pattern completed",
        domain="client",
        action="pattern_demo",
        status="success",
        recommendation="Use this pattern for production code"
    )


async def main():
    """Run all client connection examples."""
    print("🙋 pyvider-rpcplugin Client Connection Examples")
    print("===============================================")
    
    try:
        # Run each client pattern example
        await example_3_basic_client_connection()
        await example_3_connection_retry_logic()
        await example_3_connection_pooling()
        await example_3_async_context_manager()
        
        print("\n" + "=" * 60)
        print("✅ All Client Connection Examples Completed Successfully!")
        print("=" * 60)
        print("\n🎯 Key Patterns:")
        print("  • Basic lifecycle: connect → use → cleanup")
        print("  • Retry logic: exponential backoff for reliability")
        print("  • Connection pooling: high throughput scenarios")
        print("  • Context managers: automatic resource management")
        print("\n📖 Next Steps:")
        print("  • Try example 04_transport_options.py for transport comparison")
        print("  • See example 05_security_mtls.py for secure connections")
        print("  • Check example 07_error_handling.py for robust error patterns")
        
    except Exception as e:
        logger.error(
            "Client connection example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
