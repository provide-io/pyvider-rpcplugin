#!/usr/bin/env python3
import asyncio
import os

# Import generated code
from examples.demo import echo_pb2
from examples.demo import echo_pb2_grpc

from pyvider.rpcplugin.factories import plugin_server

# Import pyvider components
from pyvider.rpcplugin.protocol import RPCPluginProtocol

# Assuming a basic logger setup
from pyvider.telemetry import logger


# --- Implement the Handler (Servicer) ---
class EchoHandler(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(self, request, context):
        logger.info(f"Handler: Received Echo request: '{request.message}'")
        reply_message = f"Server echoed: {request.message}"
        return echo_pb2.EchoResponse(reply=reply_message)


# --- Implement the Protocol Wrapper ---
class EchoProtocol(RPCPluginProtocol):
    def get_grpc_descriptors(self):
        # Return the generated _pb2_grpc module and the Service name string
        return echo_pb2_grpc, "EchoService"

    async def add_to_server(self, handler, server):
        # Register the handler with the gRPC server
        echo_pb2_grpc.add_EchoServiceServicer_to_server(handler, server)
        logger.info("Handler registered with gRPC server.")


# --- Main Server Logic ---
async def main():
    logger.info("Starting Echo Plugin Server...")

    # Check for required environment variable (set by host)
    if "PLUGIN_MAGIC_COOKIE" not in os.environ:
        logger.warning(
            "PLUGIN_MAGIC_COOKIE env var not set. Using default for standalone run."
        )
        os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "ECHO_PLUGIN_COOKIE"
        os.environ["PLUGIN_MAGIC_COOKIE"] = "standalonesecret"  # Must match host
        # Host also sets PLUGIN_PROTOCOL_VERSIONS, PLUGIN_TRANSPORTS etc.

    handler = EchoHandler()

    # Configuration for mTLS
    # These paths are relative to the repository root when the server is run.
    # PLUGIN_AUTO_MTLS=True is expected to be set in the environment for the client.
    # For the server, we explicitly provide paths.
    # Paths are relative to the execution directory of echo_server.py (examples/demo/)
    mtls_config = {
        "PLUGIN_SERVER_CERT": "../../example_certs_output/server.crt",
        "PLUGIN_SERVER_KEY": "../../example_certs_output/server.key",
        "PLUGIN_SERVER_ROOT_CERTS": "../../example_certs_output/ca.crt",
        "PLUGIN_AUTO_MTLS": False,  # Ensure server uses these specific certs for mTLS
    }

    server = plugin_server(
        protocol=EchoProtocol(),
        handler=handler,
        config=mtls_config,
        # transport='unix' # Default, or 'tcp'
    )

    try:
        # This runs the server, including the handshake
        await server.serve()
    except Exception as e:
        logger.error(f"Server execution failed: {e}", exc_info=True)
    finally:
        logger.info("Echo server shutting down.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user.")
