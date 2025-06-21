#!/usr/bin/env python3
import asyncio
import os

# Import generated code
from examples.demo import echo_pb2, echo_pb2_grpc
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
    server = plugin_server(
        protocol=EchoProtocol(),
        handler=handler,
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
