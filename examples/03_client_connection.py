#!/usr/bin/env python3
# examples/03_client_connection.py
"""Demonstrates robust client connection patterns and lifecycle management with pyvider-rpcplugin."""

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
    configure,
    plugin_client,
)
from pyvider.rpcplugin.exception import (  # noqa: E402
    HandshakeError,
    RPCPluginError,
    TransportError,
)
from pyvider.telemetry import logger  # noqa: E402


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

    # Configure client settings
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="client-example-cookie",  # This was already correct
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_CLIENT_TRANSPORTS=["unix"],  # This was already correct
        PLUGIN_CONNECTION_TIMEOUT=30.0,  # This was already correct
        PLUGIN_HANDSHAKE_TIMEOUT=10.0,  # This was already correct
    )

    logger.info(
        "Creating RPC client",
        domain="client",
        action="create",
        status="starting",
        transport="unix",
    )

    # Create client instance
    # The plugin_client factory expects a server_path (executable)
    # Using a placeholder here as this example focuses on client patterns,
    # not actual server interaction with a specific executable.
    client = plugin_client(server_path=example_dir / "dummy_server.sh")

    try:
        # Simulate connection lifecycle
        logger.info(
            "Client connection lifecycle",
            domain="client",
            action="lifecycle",
            status="demonstrating",
            steps=["connect", "authenticate", "ready", "disconnect"],
        )

        # In a real scenario, you would connect to an actual server:
        # await client.connect("/tmp/my_service.sock")

        logger.info(
            "Client ready for RPC calls",
            domain="client",
            action="ready",
            status="success",
            capabilities=["method_calls", "streaming", "metadata"],
        )

        # Simulate some client operations
        await asyncio.sleep(0.1)

    except Exception as e:
        logger.error(
            "Client connection failed",
            domain="client",
            action="connect",
            status="error",
            error=str(e),
        )
    finally:
        # Always cleanup client resources
        await client.close()
        logger.info(
            "Client connection closed",
            domain="client",
            action="cleanup",
            status="success",
        )


async def example_3_connection_retry_logic():
    """
    Example 3B: Demonstrates robust connection retry patterns.

    Shows how to implement retry logic with exponential backoff
    for handling temporary connection failures.
    """
    # This function demonstrates an example of application-level retry logic.
    print("\n" + "=" * 60)
    print("🔁 Example 3B: Connection Retry Logic")
    print(" Demonstrates: Retry patterns with exponential backoff")
    print("=" * 60)

    max_retries = 3
    base_delay = 1.0

    for attempt in range(max_retries):
        try:
            delay = base_delay * (2**attempt)  # Exponential backoff

            logger.info(
                f"Connection attempt {attempt + 1}",
                domain="client",
                action="connect_retry",
                status="attempting",
                attempt=attempt + 1,
                max_retries=max_retries,
                delay_seconds=delay,
            )

            # Create new client for each attempt
            # Using a placeholder for server_path.
            client = plugin_client(server_path=example_dir / "dummy_server.sh")

            # Simulate connection attempt
            # In reality: await client.connect(endpoint)

            # Simulate random connection failures for demonstration
            import random

            if random.random() < 0.7:  # nosec B311 # random is not used for security/crypto here, just for demo/jitter. # 70% chance of "failure" for demo
                raise TransportError(
                    f"Simulated connection failure (attempt {attempt + 1})"
                )

            # Success!
            logger.info(
                "Connection successful",
                domain="client",
                action="connect_retry",
                status="success",
                attempt=attempt + 1,
                total_delay=sum(base_delay * (2**i) for i in range(attempt)),
            )

            await client.close()
            break

        except (TransportError, HandshakeError) as e:
            logger.warning(
                f"Connection attempt {attempt + 1} failed",
                domain="client",
                action="connect_retry",
                status="failed",
                attempt=attempt + 1,
                error=str(e),
                will_retry=attempt < max_retries - 1,
            )

            if attempt < max_retries - 1:
                logger.info(
                    f"Retrying in {delay} seconds",
                    domain="client",
                    action="backoff",
                    status="waiting",
                    delay_seconds=delay,
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "All connection attempts failed",
                    domain="client",
                    action="connect_retry",
                    status="exhausted",
                    total_attempts=max_retries,
                )


async def example_3_connection_pooling():
    """
    Example 3C: Demonstrates connection pooling for high-throughput scenarios.

    Shows how to manage multiple client connections efficiently
    for applications that need high concurrency.
    """
    # This function demonstrates a conceptual application-level pattern for managing multiple client instances (pooling).
    print("\n" + "=" * 60)
    print("🏊 Example 3C: Connection Pooling")
    print(" Demonstrates: Multiple client connections for high throughput")
    print("=" * 60)

    pool_size = 5
    clients = []

    try:
        logger.info(
            "Creating client connection pool",
            domain="client",
            action="pool_create",
            status="starting",
            pool_size=pool_size,
        )

        # Create pool of client connections
        for i in range(pool_size):
            # Using a placeholder for server_path.
            client = plugin_client(server_path=example_dir / "dummy_server.sh")
            clients.append(client)

            logger.debug(
                f"Created client {i + 1}",
                domain="client",
                action="pool_add",
                status="success",
                client_id=i + 1,
                pool_progress=f"{i + 1}/{pool_size}",
            )

        logger.info(
            "Client pool ready",
            domain="client",
            action="pool_create",
            status="success",
            pool_size=len(clients),
            throughput_estimate="5x single client",
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
                work_type="simulated_rpc",
            )

            # Simulate RPC call latency
            await asyncio.sleep(0.1)

            logger.info(
                f"Client {client_id} work completed",
                domain="client",
                action="pool_work",
                status="completed",
                client_id=client_id,
            )

        # Run concurrent work across the pool
        tasks = [
            simulate_client_work(i + 1, client) for i, client in enumerate(clients)
        ]

        await asyncio.gather(*tasks)

        logger.info(
            "Pool work completed",
            domain="client",
            action="pool_work",
            status="all_completed",
            concurrent_operations=len(tasks),
        )

    finally:
        # Cleanup all clients in the pool
        logger.info(
            "Cleaning up client pool",
            domain="client",
            action="pool_cleanup",
            status="starting",
            clients_to_close=len(clients),
        )

        cleanup_tasks = [client.close() for client in clients]
        await asyncio.gather(*cleanup_tasks, return_exceptions=True)

        logger.info(
            "Client pool cleaned up",
            domain="client",
            action="pool_cleanup",
            status="success",
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

    # This `MockAsyncClient` illustrates the async context manager pattern.
    # The actual `RPCPluginClient` (returned by `plugin_client()`) also supports
    # this pattern directly, automatically managing `start()` and `close()`/`shutdown_plugin()` calls.
    # See docs/api-reference.md for an example using `RPCPluginClient` with `async with`.

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
                transport=self.transport,
            )

            # Simulate connection
            await asyncio.sleep(0.1)
            self.connected = True

            logger.info(
                "Client connected via context manager",
                domain="client",
                action="context_enter",
                status="success",
            )

            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            logger.info(
                "Client exiting async context",
                domain="client",
                action="context_exit",
                status="starting",
                has_exception=exc_type is not None,
            )

            # Simulate cleanup
            self.connected = False
            await asyncio.sleep(0.05)

            logger.info(
                "Client disconnected via context manager",
                domain="client",
                action="context_exit",
                status="success",
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
                method=method,
            )

    # Demonstrate the async context manager pattern
    logger.info(
        "Demonstrating async context manager pattern",
        domain="client",
        action="pattern_demo",
        status="starting",
        benefits=["automatic_cleanup", "exception_safety", "readable_code"],
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
            operations_count=2,
        )

        # Client will be automatically disconnected when exiting the context

    logger.info(
        "Context manager pattern completed",
        domain="client",
        action="pattern_demo",
        status="success",
        recommendation="Use this pattern for production code",
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
            error=str(e),
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
