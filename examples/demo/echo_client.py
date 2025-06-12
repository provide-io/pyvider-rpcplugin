#!/usr/bin/env python3
import asyncio
import os
import sys
import grpc
import logging
from pathlib import Path
from pyvider.rpcplugin.client import RPCPluginClient # Moved here

# Assuming a basic logger setup (can use logging module directly)
# from pyvider.telemetry import logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import generated code (assuming it's in the same directory or accessible via PYTHONPATH)
try:
    import echo_pb2
    import echo_pb2_grpc
except ImportError:
    logger.error("Could not import generated echo_pb2/echo_pb2_grpc. "
                 "Did you generate them using grpc_tools.protoc?")
    sys.exit(1)

# --- Client Logic ---
class EchoClient:
    """A client to interact with the Echo Plugin Server."""

    def __init__(self, server_script_path: str):
        self.server_script_path = server_script_path
        self._client: RPCPluginClient | None = None
        self._stub: echo_pb2_grpc.EchoServiceStub | None = None

        # --- Crucial: Environment must match server expectation for handshake ---
        # These should ideally be set externally or configured consistently.
        # For this example, we set them directly to match the standalone server example.
        self.plugin_env = {
            "PLUGIN_MAGIC_COOKIE_KEY": "ECHO_PLUGIN_COOKIE", # Must match server
            "PLUGIN_MAGIC_COOKIE_VALUE": "standalonesecret", # Server will expect this value
            "PLUGIN_MAGIC_COOKIE": "standalonesecret",      # Client will send this value / Server actual value
            "PLUGIN_PROTOCOL_VERSIONS": "1",                # Must be compatible
            "PLUGIN_TRANSPORTS": "unix,tcp",                # What the client supports
            "PLUGIN_AUTO_MTLS": "true",                     # Use mTLS (recommended)
            "PYTHONUNBUFFERED": "1",                        # Good practice for plugins
        }
        # Pass these environment variables TO the server process
        self.client_config = {"env": self.plugin_env}

    async def start(self) -> bool:
        """Launch the server, connect, and prepare the stub."""
        logger.info(f"Attempting to start and connect to server: {self.server_script_path}")
        try:
            # Ensure server script exists and is executable
            if not os.path.exists(self.server_script_path):
                 logger.error(f"Server script not found: {self.server_script_path}")
                 return False
            # Note: Checking execute permissions might be complex across platforms,
            # relying on subprocess to fail if it's not executable.

            self._client = RPCPluginClient(
                command=[sys.executable, self.server_script_path], # Command to launch server
                config=self.client_config
            )

            # Start the client (launches server, performs handshake, creates channel)
            # Use a reasonable timeout
            await asyncio.wait_for(self._client.start(), timeout=15.0)

            if not self._client._channel:
                logger.error("gRPC channel was not established after client start.")
                await self.close()
                return False

            # Create the gRPC stub using the established channel
            self._stub = echo_pb2_grpc.EchoServiceStub(self._client._channel)
            logger.info("Client started and connected successfully.")
            return True

        except asyncio.TimeoutError:
            logger.error("Timeout occurred while starting or connecting to the server.")
            await self.close()
            return False
        except Exception as e:
            logger.error(f"Failed to start client: {e}", exc_info=True)
            await self.close()
            return False

    async def call_echo(self, message: str) -> str | None:
        """Call the Echo RPC method on the server."""
        if not self._stub:
            logger.error("Client not started or stub not available.")
            return None

        logger.info(f"Sending Echo request: '{message}'")
        try:
            request = echo_pb2.EchoRequest(message=message)
            # Add timeout to the RPC call itself
            response = await asyncio.wait_for(self._stub.Echo(request), timeout=5.0)
            logger.info(f"Received Echo reply: '{response.reply}'")
            return response.reply
        except asyncio.TimeoutError:
             logger.error("RPC call to Echo method timed out.")
             return None
        except grpc.aio.AioRpcError as e:
            logger.error(f"gRPC Error during Echo call: {e.code()} - {e.details()}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during Echo call: {e}", exc_info=True)
            return None

    async def close(self):
        """Cleanly close the client and shut down the server process."""
        if self._client:
            logger.info("Closing client connection and terminating server process...")
            try:
                # Ask the server to shutdown (optional, relies on GRPCController)
                # await self._client.shutdown_plugin()
                # await asyncio.sleep(0.5) # Give server time to react

                # Close client resources and kill process
                await self._client.close()
                logger.info("Client closed.")
            except Exception as e:
                logger.error(f"Error during client close: {e}", exc_info=True)
            finally:
                self._client = None
                self._stub = None


# --- Main Execution ---
async def run_client():
    # Define path to the server script relative to this client script
    client_dir = Path(__file__).parent
    server_script = client_dir / "echo_server.py" # Assumes server is in same dir

    client = EchoClient(str(server_script))

    if not await client.start():
        logger.error("Failed to initialize client. Exiting.")
        return

    # Call the Echo method
    reply = await client.call_echo("Hello from pyvider client!")

    if reply:
        logger.info(f"Verification: Client received reply -> {reply}")
    else:
        logger.warning("Verification: Did not receive a valid reply.")

    # Example of calling again
    await client.call_echo("Testing again!")

    # Clean up
    await client.close()
    logger.info("Client finished.")


if __name__ == "__main__":
    try:
        asyncio.run(run_client())
    except KeyboardInterrupt:
        logger.info("Client interrupted by user.")
    except Exception as e:
         logger.error(f"Client run failed: {e}", exc_info=True)
