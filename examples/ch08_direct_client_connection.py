#!/usr/bin/env python3
# examples/ch08_direct_client_connection.py
"""
Demonstrates a client connecting directly to a pyvider-rpcplugin server.

This example first launches a dummy server (`ch08_dummy_server.py`) as a
subprocess. The server is configured to write its Unix socket path to a
temporary file. This client script then reads the socket path from that
file and establishes a direct gRPC connection to the server, bypassing
the typical `RPCPluginClient` handshake that occurs when a client
manages the full lifecycle of a plugin it launches.

This illustrates how to connect to a `pyvider.rpcplugin` server that might
be running independently, once its transport address is known.
"""

import asyncio
import os
import sys
from pathlib import Path
import subprocess

import grpc  # For direct gRPC channel usage

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from example_utils import (  # type: ignore[import-not-found] # noqa: E402
    clear_plugin_env_vars,
    configure_for_example,
)

from pyvider.telemetry import logger  # noqa: E402

# Path to the file where ch08_dummy_server.py writes its socket path
SOCKET_COMM_FILE = project_root / "dummy_server_socket.txt"


async def run_direct_client() -> None:
    """Launches the dummy server, then connects to it directly."""
    logger.info("🚀 pyvider-rpcplugin Direct Client Connection Example (Self-Launching Server)")

    server_script_path = Path(__file__).resolve().parent / "ch08_dummy_server.py"
    server_proc = None
    channel = None # Define channel here to be accessible in finally
    # Ensure socket_path_read is defined for logging in TimeoutError
    socket_path_read = "unknown_socket_path"
    target = "unknown_target"

    try:
        logger.info(f"Attempting to launch server: {server_script_path}")
        python_exe = sys.executable
        # Pass current environment variables to the subprocess
        server_env = os.environ.copy()
        server_proc = subprocess.Popen([python_exe, str(server_script_path)], env=server_env)
        logger.info(f"Server process launched (PID: {server_proc.pid}). Waiting for it to initialize...")

        # Wait for the server to write the socket file
        max_wait_time = 10  # seconds
        wait_interval = 0.5 # seconds
        waited_time = 0
        while not SOCKET_COMM_FILE.exists() and waited_time < max_wait_time:
            if server_proc.poll() is not None: # Check if server exited
                logger.error(f"Server process exited prematurely with code: {server_proc.returncode}")
                return
            await asyncio.sleep(wait_interval)
            waited_time += wait_interval

        if not SOCKET_COMM_FILE.exists():
            logger.error(f"Socket file {SOCKET_COMM_FILE} not found after {max_wait_time}s.")
            if server_proc.poll() is not None:
                 logger.error(f"Server process exited with code: {server_proc.returncode}")
            return

        socket_path_read = SOCKET_COMM_FILE.read_text().strip()
        if not socket_path_read:
            logger.error(f"Socket path in {SOCKET_COMM_FILE} is empty.")
            return
        logger.info(f"Read socket path from {SOCKET_COMM_FILE}: {socket_path_read}")

        target = f"unix:{socket_path_read}"

        logger.info(f"Creating insecure gRPC channel directly to target: {target}...")
        channel = grpc.aio.insecure_channel(target)

        logger.info("Waiting for channel to be ready (timeout 5s)...")
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        logger.info(f"✅ Successfully connected to server at {target}")
        print(f"\n✅ Successfully connected to server at {target}")

        print("   (No RPC calls made in this basic connection example.)")
        await asyncio.sleep(1) # Keep connection for a moment

    except TimeoutError: # This specifically refers to channel_ready timeout
        logger.error(
            f"Timeout: Failed to connect to {target} within 5 seconds. "
            f"Is the server running and the socket path '{socket_path_read}' correct?"
        )
        print(
            f"❌ Timeout connecting to {target}. Check server status "
            f"and socket path '{socket_path_read}'."
        )
    except grpc.aio.AioRpcError as e:
        logger.error(
            f"gRPC Error during connection to {target}: {e.code()} - {e.details()}",
            exc_info=True,
        )
        print(f"❌ gRPC error: {e.details()}")
    except Exception as e:
        logger.error(f"An unexpected error occurred in run_direct_client: {e}", exc_info=True)
        print(f"❌ Unexpected error: {e}")
    finally:
        if channel:
            logger.info(f"Closing gRPC channel to {target}.")
            await channel.close()
            print("   gRPC channel closed.")

        if server_proc:
            logger.info(f"Terminating server process (PID: {server_proc.pid})...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
                logger.info("Server process terminated.")
            except subprocess.TimeoutExpired:
                logger.warning("Server process did not terminate in time, killing.")
                server_proc.kill()
                try:
                    server_proc.wait(timeout=2) # Brief wait after kill
                except subprocess.TimeoutExpired:
                    logger.error("Server process still running after kill command.")

        if SOCKET_COMM_FILE.exists():
            try:
                SOCKET_COMM_FILE.unlink()
                logger.info(f"Cleaned up {SOCKET_COMM_FILE}")
            except OSError as e:
                logger.warning(f"Could not remove {SOCKET_COMM_FILE} during client cleanup: {e}")

        print("\n✅ Direct Client Connection Example Finished.")


if __name__ == "__main__":
    # Client-specific configuration. Server subprocess will manage its own.
    clear_plugin_env_vars()
    # configure_for_example() # This is called by the client internally if needed,
                              # but for direct grpc connection, less pyvider config is used.
                              # We still want logging and path setup from it.
    configure_for_example()

    from pyvider.rpcplugin import configure as pyvider_core_configure
    pyvider_core_configure(
        log_level="DEBUG", # Set client log level
        auto_mtls=False # Client not using mTLS for this direct connection
    )
    asyncio.run(run_direct_client())
"""
Demonstrates a client connecting directly to an independently running
pyvider-rpcplugin server using a known transport path (e.g., Unix socket).

This version has been modified to launch the server itself to make it
runnable as a single script.
"""

import asyncio
import os # Added
import sys
from pathlib import Path
import subprocess # Added

import grpc  # For direct gRPC channel usage

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from example_utils import (  # type: ignore[import-not-found] # noqa: E402
    clear_plugin_env_vars,
    configure_for_example,
)

from pyvider.telemetry import logger  # noqa: E402

# Path to the file where ch08_dummy_server.py writes its socket path
SOCKET_COMM_FILE = project_root / "dummy_server_socket.txt"


async def run_direct_client() -> None:
    """Launches the dummy server, then connects to it directly."""
    logger.info("🚀 pyvider-rpcplugin Direct Client Connection Example (Self-Launching Server)")

    server_script_path = Path(__file__).resolve().parent / "ch08_dummy_server.py"
    server_proc = None
    channel = None # Define channel here to be accessible in finally
    # Ensure socket_path_read is defined for logging in TimeoutError
    socket_path_read = "unknown_socket_path"
    target = "unknown_target"

    try:
        logger.info(f"Attempting to launch server: {server_script_path}")
        python_exe = sys.executable
        # Pass current environment variables to the subprocess
        server_env = os.environ.copy()
        server_proc = subprocess.Popen([python_exe, str(server_script_path)], env=server_env)
        logger.info(f"Server process launched (PID: {server_proc.pid}). Waiting for it to initialize...")

        # Wait for the server to write the socket file
        max_wait_time = 10  # seconds
        wait_interval = 0.5 # seconds
        waited_time = 0
        while not SOCKET_COMM_FILE.exists() and waited_time < max_wait_time:
            if server_proc.poll() is not None: # Check if server exited
                logger.error(f"Server process exited prematurely with code: {server_proc.returncode}")
                return
            await asyncio.sleep(wait_interval)
            waited_time += wait_interval

        if not SOCKET_COMM_FILE.exists():
            logger.error(f"Socket file {SOCKET_COMM_FILE} not found after {max_wait_time}s.")
            if server_proc.poll() is not None:
                 logger.error(f"Server process exited with code: {server_proc.returncode}")
            return

        socket_path_read = SOCKET_COMM_FILE.read_text().strip()
        if not socket_path_read:
            logger.error(f"Socket path in {SOCKET_COMM_FILE} is empty.")
            return
        logger.info(f"Read socket path from {SOCKET_COMM_FILE}: {socket_path_read}")

        target = f"unix:{socket_path_read}"

        logger.info(f"Creating insecure gRPC channel directly to target: {target}...")
        channel = grpc.aio.insecure_channel(target)

        logger.info("Waiting for channel to be ready (timeout 5s)...")
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        logger.info(f"✅ Successfully connected to server at {target}")
        print(f"\n✅ Successfully connected to server at {target}")

        print("   (No RPC calls made in this basic connection example.)")
        await asyncio.sleep(1) # Keep connection for a moment

    except TimeoutError: # This specifically refers to channel_ready timeout
        logger.error(
            f"Timeout: Failed to connect to {target} within 5 seconds. "
            f"Is the server running and the socket path '{socket_path_read}' correct?"
        )
        print(
            f"❌ Timeout connecting to {target}. Check server status "
            f"and socket path '{socket_path_read}'."
        )
    except grpc.aio.AioRpcError as e:
        logger.error(
            f"gRPC Error during connection to {target}: {e.code()} - {e.details()}",
            exc_info=True,
        )
        print(f"❌ gRPC error: {e.details()}")
    except Exception as e:
        logger.error(f"An unexpected error occurred in run_direct_client: {e}", exc_info=True)
        print(f"❌ Unexpected error: {e}")
    finally:
        if channel:
            logger.info(f"Closing gRPC channel to {target}.")
            await channel.close()
            print("   gRPC channel closed.")

        if server_proc:
            logger.info(f"Terminating server process (PID: {server_proc.pid})...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
                logger.info("Server process terminated.")
            except subprocess.TimeoutExpired:
                logger.warning("Server process did not terminate in time, killing.")
                server_proc.kill()
                try:
                    server_proc.wait(timeout=2) # Brief wait after kill
                except subprocess.TimeoutExpired:
                    logger.error("Server process still running after kill command.")

        if SOCKET_COMM_FILE.exists():
            try:
                SOCKET_COMM_FILE.unlink()
                logger.info(f"Cleaned up {SOCKET_COMM_FILE}")
            except OSError as e:
                logger.warning(f"Could not remove {SOCKET_COMM_FILE} during client cleanup: {e}")

        print("\n✅ Direct Client Connection Example Finished.")


if __name__ == "__main__":
    # Client-specific configuration. Server subprocess will manage its own.
    clear_plugin_env_vars()
    # configure_for_example() # This is called by the client internally if needed,
                              # but for direct grpc connection, less pyvider config is used.
                              # We still want logging and path setup from it.
    configure_for_example()

    from pyvider.rpcplugin import configure as pyvider_core_configure
    pyvider_core_configure(
        log_level="DEBUG", # Set client log level
        auto_mtls=False # Client not using mTLS for this direct connection
    )
    asyncio.run(run_direct_client())
