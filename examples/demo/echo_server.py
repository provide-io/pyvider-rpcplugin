#!/usr/bin/env python3
import asyncio
import os
from typing import Any, cast  # For type hints

import grpc  # For ServicerContext

# Import generated code
from examples.demo import echo_pb2, echo_pb2_grpc
from pyvider.rpcplugin.factories import plugin_server

# Import pyvider components
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # Corrected import path
from pyvider.rpcplugin.server import RPCPluginServer  # For type hint
from pyvider.rpcplugin.types import (
    RPCPluginProtocol as TypesRPCPluginProtocol,
)  # For cast

# Assuming a basic logger setup
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
    async def get_grpc_descriptors(self) -> tuple[Any, str]:  # Annotated and made async
        # Return the generated _pb2_grpc module and the Service name string
        return echo_pb2_grpc, "EchoService"

    def get_method_type(self, method_name: str) -> str:  # Added
        # Determine based on method_name if it's unary-unary, unary-stream, etc.
        # For this EchoService, 'Echo' is unary-unary.
        # Real impl: check method name carefully (e.g., vs descriptors).
        if "Echo" in method_name:  # More robust check
            return "unary_unary"
        logger.warning(f"Unknown method {method_name} in EchoProtocol, defaulting.")
        return "unary_unary"  # Default

    async def add_to_server(
        self, server: Any, handler: Any
    ) -> None:  # Corrected signature
        # Register the handler with the gRPC server
        # Cast handler; add_EchoServiceServicer_to_server expects specific type.
        echo_pb2_grpc.add_EchoServiceServicer_to_server(
            cast(EchoHandler, handler), server
        )
        logger.info("Handler registered with gRPC server.")


# --- Main Server Logic ---
async def main() -> None:  # Annotated
    logger.info("Starting Echo Plugin Server...")

    # Check for required environment variable (set by host)
    if "PLUGIN_MAGIC_COOKIE" not in os.environ:
        logger.warning(
            "PLUGIN_MAGIC_COOKIE env var not set. Using default for standalone run."
        )
        os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "ECHO_PLUGIN_COOKIE"
        os.environ["PLUGIN_MAGIC_COOKIE"] = "standalonesecret"  # Must match host
        # Host also sets PLUGIN_PROTOCOL_VERSIONS, PLUGIN_TRANSPORTS etc.

    handler: EchoHandler = EchoHandler()
    # Cast EchoProtocol for plugin_server (expects TypesRPCPluginProtocol compatible).
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, EchoProtocol()),
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
