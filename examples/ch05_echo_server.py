#!/usr/bin/env python3
# examples/ch05_echo_server.py
import asyncio
import os
from typing import Any, cast
import grpc

# Ensure 'src' and project root are in sys.path for direct execution of examples
# This needs to happen BEFORE attempting to import from 'examples.proto'
from example_utils import configure_for_example
configure_for_example(clear_env=False) # Server context, do not clear client-set env vars

# Import generated code from the examples/proto directory
# Assumes 'examples' is in PYTHONPATH or you run from project root.
from examples.proto import echo_pb2, echo_pb2_grpc

# Import pyvider components
from pyvider.rpcplugin.factories import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol
from pyvider.telemetry import logger

# --- Implement the Handler (Servicer) ---
class EchoHandler(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        logger.info(f"Handler: Received Echo request: '{request.message}'")
        reply_message = f"Server echoed: {request.message}"
        return echo_pb2.EchoResponse(reply=reply_message)

# --- Implement the Protocol Wrapper ---
class EchoProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        # Return the generated _pb2_grpc module and the Service name string
        return echo_pb2_grpc, "echo.EchoService" # Matches package.Service from .proto

    def get_method_type(self, method_name: str) -> str:
        # For this EchoService, 'Echo' is unary-unary.
        if "Echo" in method_name: # A more robust check might inspect descriptors
            return "unary_unary"
        logger.warning(f"Unknown method {method_name} in EchoProtocol, defaulting to unary_unary.")
        return "unary_unary" # Default for safety

    async def add_to_server(self, server: Any, handler: Any) -> None:
        # Register the handler with the gRPC server
        echo_pb2_grpc.add_EchoServiceServicer_to_server(
            cast(EchoHandler, handler), server
        )
        logger.info("EchoService handler registered with gRPC server.")

# --- Main Server Logic ---
async def main() -> None:
    logger.info("Starting Echo Plugin Server (ch05_echo_server.py)...")

    # Basic env setup for standalone run, mimicking what a client might set.
    # In a real plugin scenario, these are set by the host application.
    # example_utils.configure_for_example() might handle this if called early.
    if "PLUGIN_MAGIC_COOKIE_KEY" not in os.environ:
        # This check is for the key, the value is set by the client.
        # The server reads the value from the key specified by PLUGIN_MAGIC_COOKIE_KEY.
        logger.warning(
            "PLUGIN_MAGIC_COOKIE_KEY env var not set. Using default for standalone run."
        )
        os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "ECHO_PLUGIN_COOKIE_EXAMPLE"
        # The actual cookie value is usually set by the client that launches this server.
        # For standalone testing, if the client isn't setting it,
        # the server might need a default value for PLUGIN_MAGIC_COOKIE_VALUE
        # if it's directly checking it, rather than just the handshake output.
        # However, standard behavior is server prints handshake, client verifies it.
        # The server itself doesn't need PLUGIN_MAGIC_COOKIE or PLUGIN_MAGIC_COOKIE_VALUE
        # to *start*, but it needs to output them correctly during handshake if hardcoded.
        # The `plugin_server` factory and `RPCPluginServer` handle handshake output
        # based on env vars like `PLUGIN_HOST_ADDRESS`, `PLUGIN_MAGIC_COOKIE_VALUE` (if set for it to use).
        # For this example, we'll rely on the client to set the value.

    handler = EchoHandler()
    # Ensure EchoProtocol is cast to the expected base type for plugin_server
    echo_protocol_instance = cast(TypesRPCPluginProtocol, EchoProtocol())

    server: RPCPluginServer = plugin_server(
        protocol=echo_protocol_instance,
        handler=handler,
        # transport='unix' # Default, or 'tcp' can be specified
    )

    try:
        # This runs the server, including the handshake, and starts serving.
        await server.serve()
    except Exception as e:
        logger.error(f"Server execution failed: {e}", exc_info=True)
    finally:
        logger.info("Echo server (ch05_echo_server.py) shutting down.")
        # server.stop() is called within RPCPluginServer.serve()'s finally block.

if __name__ == "__main__":
    try:
        # configure_for_example() is now called at the top of the module
        asyncio.run(main())
    except KeyboardInterrupt: # pragma: no cover
        logger.info("Server stopped by user.")
