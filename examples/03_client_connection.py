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
    # This server needs to be the actual 00_dummy_server.py for the client examples
    # to interact with a pyvider-rpcplugin server.
    # We will start it with the necessary magic cookie environment variable.

    server_script_path = Path(__file__).resolve().parent / "00_dummy_server.py"

    # Get the magic cookie key and value from the current config
    # (which might be the global default or set by a previous example part)
    # If not set, use a default that 00_dummy_server.py would expect if run by a host.
    current_config = rpcplugin_config
    magic_cookie_key = current_config.magic_cookie_key()
    magic_cookie_value = current_config.magic_cookie_value()

    env = {**sys.modules["os"].environ, magic_cookie_key: magic_cookie_value}

    # Start 00_dummy_server.py as a subprocess
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(server_script_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    # The client examples will use this server_script_path as their command.
    # The server will output its handshake string to its stdout.
    # The RPCPluginClient will read this handshake string.

    try:
        # Yield the command that clients should use to "run" this server.
        # In this managed setup, the server is already running.
        # The client just needs a command that *would* produce the handshake.
        # We give it the actual server script path. The client's _launch_process
        # will run it, and since it's already running with the cookie,
        # the new instance will handshake correctly.
        # Alternatively, for a truly "managed" external server, we'd capture its
        # handshake here and provide a dummy script that echoes it, but that's
        # more complex than needed if the client can just relaunch the server.
        yield str(server_script_path)
    finally:
        logger.info("Managed server: stopping subprocess...")
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except TimeoutError:
                logger.warning("Managed server: timeout during terminate, killing.")
                process.kill()
                await process.wait()
        logger.info(f"Managed server: subprocess exited with {process.returncode}")

        # Clean up stderr/stdout from the server process if needed
        if process.stdout:
            stdout_bytes = await process.stdout.read()
            if stdout_bytes:
                logger.debug(
                    f"Managed server stdout: {stdout_bytes.decode(errors='replace')}"
                )
        if process.stderr:
            stderr_bytes = await process.stderr.read()
            if stderr_bytes:
                logger.debug(
                    f"Managed server stderr: {stderr_bytes.decode(errors='replace')}"
                )

        # No dummy_executable_path or server_socket_path to clean up in this new setup.
        # The server (00_dummy_server.py) manages its own socket if it uses one.

        # No server_task to manage here as it's an external process.
        # The original server_task was for an in-process asyncio server.
        # server.stop() is also not applicable to the external process.
        pass  # Keep finally block for structure, even if empty after refactor
        # The following block was part of the old server_task logic
        # else:
        #     # If already done, check for exceptions
        #     exc = server_task.exception()
        #     if exc:
        #         logger.error(
        #             f"Managed server task exited with exception: {exc}", exc_info=exc
        #         )


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
    # dummy_handshaker_script_path was unused, removed.

    async def start_server_delayed() -> None:
        await asyncio.sleep(base_delay * 2)  # Delay server startup

        # managed_server will create/use its own dummy script.
        # To align names for this example, we'll tell managed_server to use our path.
        # This requires managed_server to accept a path for its dummy script.
        # Assume managed_server uses a fixed name like dummy_conn_handshaker.sh
        # and our client will point to that.

        # orig_dummy_path = Path("./dummy_conn_handshaker.sh") # Unused

        async with managed_server() as server_executable_path_from_managed_server:
            # server_executable_path_from_managed_server is the path to the script
            # created by managed_server (e.g. dummy_conn_handshaker.sh)
            logger.info(
                f"Delayed server is now up. Handshaker script at: "
                f"{server_executable_path_from_managed_server}"
            )
            server_ready_event.set()
            # Keep the server alive for the duration of retry attempts
            await asyncio.sleep(max_retries * base_delay * 3)

    server_task = asyncio.create_task(start_server_delayed())

    for attempt in range(max_retries):
        client = None  # Define client here to close it in finally if needed
        try:
            logger.info(f"Connection attempt {attempt + 1}/{max_retries}...")

            if not server_ready_event.is_set():
                # Simulate failure if server (and its handshaker script) isn't ready
                # This could be a failure to find the script or the script failing.
                logger.info("Server not ready yet, simulating connection failure.")
                raise TransportError(
                    "Simulated: Server's handshaker script not ready or server down."
                )

            # Server is supposedly ready. The client needs a command to "launch"
            # the server to get the handshake.
            # The `managed_server` (when called by `start_server_delayed`) sets up
            # the necessary environment (e.g., magic cookie) for 00_dummy_server.py.
            # So, the client should "launch" 00_dummy_server.py.
            client = plugin_client(
                command=[str(Path(__file__).resolve().parent / "00_dummy_server.py")]
            )
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
