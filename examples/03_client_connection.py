#!/usr/bin/env python3
# examples/03_client_connection.py
"""Robust client connection patterns and lifecycle management."""

import asyncio
import contextlib
import sys
from collections.abc import AsyncGenerator  # For type hint
from pathlib import Path

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_client,
    plugin_protocol,  # Changed
    plugin_server,
)
from pyvider.rpcplugin.config import rpcplugin_config  # noqa: E402
from pyvider.rpcplugin.exception import (  # noqa: E402
    HandshakeError,
    TransportError,
)
from pyvider.telemetry import logger  # noqa: E402


# --- Helper to manage a background server for the examples ---
@contextlib.asynccontextmanager
async def managed_server() -> AsyncGenerator[str]:
    """An async context manager to start and stop a server for tests."""
    server_socket_path = Path(f"./managed_server_{Path().name}.sock")  # Unique path
    server = plugin_server(
        protocol=plugin_protocol(),  # Changed
        handler=type("DummyHandler", (), {})(),
        transport="unix",
        transport_path=str(
            server_socket_path
        ),  # Explicit path for cleanup and handshake
    )
    server_task = asyncio.create_task(server.serve())

    await server.wait_for_server_ready(timeout=5.0)  # Added wait

    # Construct handshake string
    core_version = rpcplugin_config.get("PLUGIN_CORE_VERSION")
    protocol_version = getattr(server, "_protocol_version", "1")
    transport_type = "unix"
    server_endpoint = getattr(getattr(server, "_transport", None), "endpoint", None)

    if not server_endpoint:
        # Clean up before raising
        if server_socket_path.exists():
            server_socket_path.unlink(missing_ok=True)
        server.stop()
        await server_task
        raise RuntimeError("Managed server endpoint not available after server ready.")

    handshake_string = (
        f"{core_version}|{protocol_version}|{transport_type}|{server_endpoint}|"
    )

    dummy_executable_path = Path("./dummy_conn_handshaker.sh")
    with open(dummy_executable_path, "w") as f:
        f.write(f"#!/bin/sh\necho '{handshake_string}'")
    dummy_executable_path.chmod(0o755)

    try:
        yield str(dummy_executable_path)
    finally:
        if dummy_executable_path.exists():
            dummy_executable_path.unlink()
        if server_socket_path.exists():
            server_socket_path.unlink(missing_ok=True)

        # Graceful server shutdown
        if not server_task.done():
            server.stop()
            try:
                await asyncio.wait_for(server_task, timeout=5.0)
            except TimeoutError:
                logger.warning(
                    "Timeout waiting for managed server task to complete, cancelling."
                )
                server_task.cancel()
                await asyncio.gather(server_task, return_exceptions=True)
        else:
            # If already done, check for exceptions
            exc = server_task.exception()
            if exc:
                logger.error(
                    f"Managed server task exited with exception: {exc}", exc_info=exc
                )


async def example_3_basic_client_connection() -> None:
    """Example 3A: Demonstrates basic client connection lifecycle."""
    print("\n" + "=" * 60)
    print("🙋 Example 3A: Basic Client Connection Lifecycle")
    print("=" * 60)

    async with managed_server() as server_executable:
        client = plugin_client(command=[server_executable])  # Changed
        try:
            await client.start()
            logger.info(
                "Client connected successfully.", endpoint=client.target_endpoint
            )
            # In a real scenario, you would now make RPC calls.
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error("Client connection failed", error=str(e))
        finally:
            await client.close()
            logger.info("Client connection closed.")


async def example_3_connection_retry_logic() -> None:
    """Example 3B: Demonstrates robust connection retry patterns."""
    print("\n" + "=" * 60)
    print("🔁 Example 3B: Connection Retry Logic")
    print("=" * 60)

    max_retries = 3
    base_delay = 0.2
    client = None

    # This example simulates a server that isn't ready immediately.
    server_ready_event = asyncio.Event()
    shared_context = {"server_script_path": None} # To store the script path

    async def start_server_delayed() -> None:
        await asyncio.sleep(base_delay * 2)  # Delay server startup
        async with managed_server() as server_executable_path_from_managed_server:
            shared_context["server_script_path"] = server_executable_path_from_managed_server
            logger.info(
                f"Delayed server is now up. Handshaker script at: "
                f"{server_executable_path_from_managed_server}"
            )
            server_ready_event.set()
            # Keep the server alive for the duration of retry attempts
            # Use a try-except block to handle potential cancellation during sleep
            try:
                await asyncio.sleep(max_retries * base_delay * 4) # Slightly longer
            except asyncio.CancelledError:
                logger.info("Delayed server task cancelled during sleep.")
                raise


    server_task = asyncio.create_task(start_server_delayed())

    for attempt in range(max_retries):
        client = None  # Define client here to close it in finally if needed
        try:
            logger.info(f"Connection attempt {attempt + 1}/{max_retries}...")

            if not server_ready_event.is_set() or not shared_context["server_script_path"]:
                # Simulate failure if server (and its handshaker script) isn't ready
                logger.info("Server or its handshaker script not ready yet, simulating connection failure.")
                raise TransportError(
                    "Simulated: Server's handshaker script not ready or server down."
                )

            # Server is supposedly ready, try to connect using the script path from shared_context
            logger.info(f"Attempting to connect to server using script: {shared_context['server_script_path']}")
            client = plugin_client(command=[str(shared_context["server_script_path"])])
            await client.start()

            logger.info("Connection successful!")
            assert client.is_started
            # In a real app, do something with the client here.
            await (
                client.close()
            )  # Close the client as we're done with this successful attempt.
            break  # Exit retry loop

        except (TransportError, HandshakeError) as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
            if client:  # Ensure client is closed if created but start failed partially
                await client.close()
            if attempt < max_retries - 1:
                delay = base_delay * (2**attempt)
                logger.info(f"Retrying in {delay:.2f} seconds...")
                await asyncio.sleep(delay)
            else:
                logger.error("All connection attempts failed.")

    server_task.cancel()
    await asyncio.gather(server_task, return_exceptions=True)


async def example_3_async_context_manager() -> None:
    """Example 3D: Demonstrates using async context managers for clients."""
    print("\n" + "=" * 60)
    print("🔧 Example 3D: Async Context Manager Pattern")
    print("=" * 60)

    async with managed_server() as server_executable:
        try:
            async with plugin_client(command=[server_executable]) as client:  # Changed
                logger.info("Client entered async context and connected.")
                assert client.is_started
                # RPC calls would go here
                await asyncio.sleep(0.1)
            logger.info("Client exited async context and was automatically closed.")
        except Exception as e:
            logger.error(f"Error in context manager example: {e}")


async def main() -> None:
    """Run all client connection examples."""
    await example_3_basic_client_connection()
    await example_3_connection_retry_logic()
    # The connection pooling example is more conceptual and harder to demonstrate
    # without significant setup, so we'll omit its execution here.
    print("\nNOTE: Connection pooling example is conceptual and not executed here.")
    await example_3_async_context_manager()
    print("\n✅ All executable client connection examples completed.")


if __name__ == "__main__":
    asyncio.run(main())
