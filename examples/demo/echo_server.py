#!/usr/bin/env python3
import asyncio
import os
import sys # Import sys for debug prints
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

    # --- BEGIN DEBUG PRINT ---
    print(f"ECHO_SERVER.PY (main start): ECHO_PLUGIN_COOKIE = {os.environ.get('ECHO_PLUGIN_COOKIE')}", file=sys.stderr)
    print(f"ECHO_SERVER.PY (main start): PLUGIN_MAGIC_COOKIE_KEY = {os.environ.get('PLUGIN_MAGIC_COOKIE_KEY')}", file=sys.stderr)
    print(f"ECHO_SERVER.PY (main start): PLUGIN_MAGIC_COOKIE_VALUE = {os.environ.get('PLUGIN_MAGIC_COOKIE_VALUE')}", file=sys.stderr)
    # --- END DEBUG PRINT ---

    from pyvider.rpcplugin.config import rpcplugin_config # Ensure it's loaded based on current env

    # Determine what cookie configuration this server instance will use and expect.
    # It prioritizes environment variables specific to this server's intended config,
    # otherwise falls back to its own defaults.
    server_expects_cookie_key_name = os.environ.get("PLUGIN_MAGIC_COOKIE_KEY", "ECHO_PLUGIN_COOKIE")
    server_expects_cookie_value = os.environ.get("PLUGIN_MAGIC_COOKIE_VALUE", "standalonesecret")

    # Update the global rpcplugin_config to reflect what this server expects.
    # This is crucial because validate_magic_cookie() will read from this global config.
    rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_KEY", server_expects_cookie_key_name)
    rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_VALUE", server_expects_cookie_value)
    logger.info(f"EchoServer: Configured to expect cookie key='{server_expects_cookie_key_name}' with value='{server_expects_cookie_value}'")

    # For validate_magic_cookie() to pass, the environment variable named by server_expects_cookie_key_name
    # must exist and have the server_expects_cookie_value.
    # This is typically set by the client process that launches this server.
    # If running standalone, or if the client didn't set it, we can self-set it here for the check to pass.
    # The `demo/env.sh` (sourced by echo_client.py) should set ECHO_PLUGIN_COOKIE="standalonesecret".
    # If it's not set, this is a fallback for direct execution or if env propagation failed.
    if os.environ.get(server_expects_cookie_key_name) != server_expects_cookie_value:
        logger.warning(
            f"EchoServer: Env var '{server_expects_cookie_key_name}' is not '{server_expects_cookie_value}'. "
            f"Current value: '{os.environ.get(server_expects_cookie_key_name)}'. Setting it now."
        )
        os.environ[server_expects_cookie_key_name] = server_expects_cookie_value


    handler: EchoHandler = EchoHandler()
    # Cast EchoProtocol for plugin_server (expects TypesRPCPluginProtocol compatible).
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, EchoProtocol()),
        handler=handler,
        # transport, host, port will use defaults from rpcplugin_config
        # (which should be suitable as per demo/env.sh or server's own logic)
        # No specific 'config' dict needed here if global config is now correct.
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
