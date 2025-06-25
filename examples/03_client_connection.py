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

from example_utils import configure_for_example, clear_plugin_env_vars # noqa: E402
from pyvider.rpcplugin import (  # noqa: E402
    plugin_client,
    plugin_protocol,
    plugin_server,
)
from pyvider.rpcplugin.config import rpcplugin_config # For reading active config
from pyvider.rpcplugin.exception import (  # noqa: E402
    HandshakeError,
    TransportError,
)
from pyvider.telemetry import logger  # noqa: E402


# --- Helper to manage a background server for the examples ---
@contextlib.asynccontextmanager
async def managed_server(unique_id: str) -> AsyncGenerator[str]:
    """An async context manager to start and stop a server for tests."""
    # Configure the server part using example_utils
    # Each managed server instance might need a slightly different cookie or port if run concurrently
    # For simplicity, we'll use a unique cookie per managed_server instance.
    server_cookie_value = f"managed-server-cookie-{unique_id}"
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE=server_cookie_value,
        PLUGIN_SERVER_TRANSPORTS=["unix"], # Keep it simple
        PLUGIN_LOG_LEVEL="WARNING", # Reduce noise from managed server
    )

    server_socket_path = Path(f"./managed_server_{unique_id}.sock")
    server = plugin_server(
        protocol=plugin_protocol(),
        handler=type("DummyHandler", (), {})(), # Simple no-op handler
        transport="unix",
        transport_path=str(server_socket_path),
    )
    server_task = asyncio.create_task(server.serve())

    await server.wait_for_server_ready(timeout=5.0)

    # Construct handshake string based on the *active* server's configuration
    # The rpcplugin_config here reflects what the server is using due to its own configure_for_example call
    active_server_config = rpcplugin_config
    core_version = active_server_config.get("PLUGIN_CORE_VERSION")
    protocol_version = getattr(server, "_protocol_version", active_server_config.get_list("PLUGIN_PROTOCOL_VERSIONS")[0])
    transport_type = "unix" # Matching server's transport
    server_endpoint = getattr(getattr(server, "_transport", None), "endpoint", None)

    if not server_endpoint:
        if server_socket_path.exists():
            server_socket_path.unlink(missing_ok=True)
        server.stop() # Ensure server resources are released
        await server_task # Wait for task to finish
        raise RuntimeError(f"Managed server '{unique_id}' endpoint not available after server ready.")

    handshake_string = f"{core_version}|{protocol_version}|{transport_type}|{server_endpoint}|grpc|" # Added grpc protocol

    dummy_executable_path = Path(f"./dummy_conn_handshaker_{unique_id}.sh")
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

    # Client configuration for this example
    clear_plugin_env_vars()
    # The client needs to be configured with the cookie value that the managed_server (for basic_client) expects.
    # managed_server uses "managed-server-cookie-basic_client"
    configure_for_example(PLUGIN_MAGIC_COOKIE_VALUE="managed-server-cookie-basic_client")


    async with managed_server(unique_id="basic_client") as server_executable:
        client = plugin_client(command=[server_executable])
        try:
            await client.start()
            logger.info(
                "Client connected successfully.", endpoint=client.target_endpoint
            )
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Client connection failed: {e}", exc_info=True)
        finally:
            await client.close()
            logger.info("Client connection closed.")


async def example_3_connection_retry_logic() -> None:
    """Example 3B: Demonstrates robust connection retry patterns."""
    print("\n" + "=" * 60)
    print("🔁 Example 3B: Connection Retry Logic")
    print("=" * 60)

    # Client configuration for this example
    clear_plugin_env_vars()
    # The client needs to be configured with the cookie value that the managed_server (for retry_logic) expects.
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="managed-server-cookie-retry_logic",
        PLUGIN_CLIENT_RETRY_ENABLED=True, # Ensure retry is enabled for client
        PLUGIN_CLIENT_MAX_RETRIES=3,
        PLUGIN_CLIENT_INITIAL_BACKOFF_MS=100, # Faster backoff for example
    )

    max_retries = rpcplugin_config.get_int("PLUGIN_CLIENT_MAX_RETRIES", 3) # Get from config
    base_delay = 0.2 # This is for server delay, client backoff is from config
    client = None
    server_ready_event = asyncio.Event()
    unique_server_id = "retry_logic" # Used for managed_server and dummy script

    async def start_server_delayed() -> None:
        await asyncio.sleep(base_delay * 2)
        async with managed_server(unique_id=unique_server_id) as server_executable_path_from_managed_server:
            logger.info(
                f"Delayed server '{unique_server_id}' is now up. Handshaker script at: "
                f"{server_executable_path_from_managed_server}"
            )
            server_ready_event.set()
            await asyncio.sleep(max_retries * base_delay * 4) # Keep server alive longer

    server_task = asyncio.create_task(start_server_delayed())

    # The plugin_client will use its configured retry settings.
    # We don't need to loop here; the client's `start()` will handle retries.
    try:
        logger.info(f"Attempting connection with client-side retries enabled...")
        # Wait a bit for server to potentially start, or let client retry logic handle it
        await asyncio.sleep(base_delay) # Give a slight chance for server to start before client

        # The command for the client should be the handshaker script for *this* server instance
        dummy_handshaker_script = Path(f"./dummy_conn_handshaker_{unique_server_id}.sh")

        # Ensure the client is configured to expect the cookie from this specific server
        # This is already done by configure_for_example above.

        client = plugin_client(command=[str(dummy_handshaker_script)])
        await client.start() # This will internally use retry logic

        logger.info("Connection successful after client-side retries (if any)!")
        assert client.is_started
        await client.close()

    except (TransportError, HandshakeError) as e:
        logger.error(f"All client connection attempts failed: {e}", exc_info=True)
        if client:
            await client.close()
    except Exception as e:
        logger.error(f"Unexpected error during retry example: {e}", exc_info=True)
        if client:
            await client.close()
    finally:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)


async def example_3_async_context_manager() -> None:
    """Example 3D: Demonstrates using async context managers for clients."""
    print("\n" + "=" * 60)
    print("🔧 Example 3D: Async Context Manager Pattern")
    print("=" * 60)

    # Client configuration for this example
    clear_plugin_env_vars()
    # Configure client for the cookie expected by managed_server("context_manager")
    configure_for_example(PLUGIN_MAGIC_COOKIE_VALUE="managed-server-cookie-context_manager")

    async with managed_server(unique_id="context_manager") as server_executable:
        try:
            # The plugin_client will use the config set by configure_for_example
            async with plugin_client(command=[server_executable]) as client:
                logger.info("Client entered async context and connected.")
                assert client.is_started
                await asyncio.sleep(0.1)
            logger.info("Client exited async context and was automatically closed.")
        except Exception as e:
            logger.error(f"Error in context manager example: {e}", exc_info=True)


async def main() -> None:
    """Run all client connection examples."""
    # It's important that each example configures itself cleanly,
    # as configure_for_example modifies global state (rpcplugin_config singleton).
    await example_3_basic_client_connection()
    await example_3_connection_retry_logic()
    print("\nNOTE: Connection pooling example is conceptual and not executed here.")
    await example_3_async_context_manager()
    print("\n✅ All executable client connection examples completed.")


if __name__ == "__main__":
    asyncio.run(main())
