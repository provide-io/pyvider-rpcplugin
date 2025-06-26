#!/usr/bin/env python3
# examples/01b_direct_client_connection.py
"""
Demonstrates a client connecting directly to an independently running
pyvider-rpcplugin server using a known transport path (e.g., Unix socket).

This contrasts with examples that use `plugin_client` to launch the server.
To run this example:
1. Start a compatible server first (e.g., `examples/00_dummy_server.py` configured for Unix socket).
   Example: `python examples/00_dummy_server.py`
   (Ensure it's configured with PLUGIN_AUTO_MTLS=False or certs are set up if True)
   Note the Unix socket path it prints (e.g., /tmp/pyvider-XXXX.sock)
2. Update `SOCKET_PATH` in this script to match the server's socket path.
3. Run this script: `python examples/01b_direct_client_connection.py`
"""

import asyncio
import sys
from pathlib import Path

import grpc  # For direct gRPC channel usage

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from example_utils import clear_plugin_env_vars, configure_for_example  # noqa: E402

from pyvider.telemetry import logger  # noqa: E402

# Path to the file where 00_dummy_server.py writes its socket path
SOCKET_COMM_FILE = project_root / "dummy_server_socket.txt"


async def run_direct_client():
    """Connects to an independently running server."""
    print("🚀 pyvider-rpcplugin Direct Client Connection Example")
    print("======================================================")

    socket_path_read = (
        None  # Renamed to avoid conflict with global SOCKET_PATH if it were used
    )
    try:
        socket_path_read = SOCKET_COMM_FILE.read_text().strip()
        logger.info(f"Read socket path from {SOCKET_COMM_FILE}: {socket_path_read}")
    except FileNotFoundError:
        logger.error(
            f"Socket communication file not found: {SOCKET_COMM_FILE}. "
            "Ensure 00_dummy_server.py ran successfully and wrote this file."
        )
        print(f"❌ Socket path file not found: {SOCKET_COMM_FILE}. Start server first.")
        return
    except Exception as e:
        logger.error(f"Error reading socket path file: {e}", exc_info=True)
        print(f"❌ Error reading socket path from {SOCKET_COMM_FILE}: {e}")
        return

    if not socket_path_read:  # Check the renamed variable
        logger.error("Socket path is empty. Cannot connect.")
        print("❌ Socket path is empty in communication file.")
        return

    logger.info(
        f"Attempting to connect directly to server at Unix socket: {socket_path_read}"
    )
    logger.warning(f"Ensure a server is running and listening on '{socket_path_read}'.")

    # Configure client-side aspects if necessary (e.g., logging)
    # No magic cookie env vars needed by this client as it's not launching the server.
    clear_plugin_env_vars()
    configure_for_example(
        PLUGIN_LOG_LEVEL="DEBUG", PLUGIN_AUTO_MTLS=False
    )  # Match typical dummy server config

    # THIS IS THE LINE THAT HAD THE TYPO - USING socket_path_read (lowercase)
    target = f"unix:{socket_path_read}"
    channel = None
    try:
        # For a server script not launched by this client, connect directly using grpc.aio.
        # This example assumes an insecure channel (no mTLS).
        # For mTLS, you would use grpc.aio.secure_channel() with credentials.
        logger.info(f"Creating insecure gRPC channel to {target}...")
        channel = grpc.aio.insecure_channel(target)

        logger.info("Waiting for channel to be ready (timeout 5s)...")
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        logger.info(f"Successfully connected to {target}")
        print(f"\n✅ Successfully connected to server at {target}")

        # At this point, you would typically use a gRPC stub generated from your .proto file
        # to make RPC calls. For example:
        # stub = YourServiceStub(channel)
        # response = await stub.YourMethod(YourRequest(data="hello from direct client"))
        # logger.info(f"Received response: {response.message}")
        print("   (No RPC calls made in this basic connection example.)")

    except TimeoutError:
        logger.error(
            # Corrected to use socket_path_read in log message
            f"Timeout: Failed to connect to {target} within 5 seconds. "
            f"Is the server running and the socket path '{socket_path_read}' correct?"
        )
        # Corrected to use socket_path_read in print message
        print(
            f"❌ Timeout connecting to {target}. Check server status and socket path '{socket_path_read}'."
        )
    except grpc.aio.AioRpcError as e:
        logger.error(
            f"gRPC Error during connection: {e.code()} - {e.details()}",
            exc_info=True,
        )
        print(f"❌ gRPC error: {e.details()}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        print(f"❌ Unexpected error: {e}")
    finally:
        if channel:
            logger.info("Closing gRPC channel.")
            await channel.close()
            print("   gRPC channel closed.")
        print("\n✅ Direct Client Connection Example Finished.")


if __name__ == "__main__":
    asyncio.run(run_direct_client())
