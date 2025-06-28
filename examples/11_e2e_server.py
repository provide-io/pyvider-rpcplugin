#!/usr/bin/env python3
# examples/11_e2e_server.py
"""
End-to-End Greeter Plugin Server.
"""
import asyncio
import os
from typing import Any, cast

import grpc

# Import pyvider components
from pyvider.rpcplugin.factories import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol
from pyvider.telemetry import logger

# Import generated protobuf code for E2E Greeting service
from examples.proto import e2e_greeting_pb2
from examples.proto import e2e_greeting_pb2_grpc


# --- Implement the Handler (Servicer) ---
class GreeterServiceHandler(e2e_greeting_pb2_grpc.GreeterServicer):
    """
    Implements the Greeter service.
    """
    async def Greet(
        self, request: e2e_greeting_pb2.GreetingRequest, context: grpc.aio.ServicerContext
    ) -> e2e_greeting_pb2.GreetingReply:
        logger.info(
            "GreeterServiceHandler: Received Greet request",
            client_name=request.name,
        )
        message = f"Hello, {request.name}! This is a real end-to-end call from the E2E server."
        return e2e_greeting_pb2.GreetingReply(message=message)

# --- Implement the Protocol Wrapper ---
class E2EGreetingProtocol(RPCPluginProtocol):
    """
    RPCPluginProtocol implementation for the E2E Greeter service.
    """
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        # Return the generated _pb2_grpc module and the Service name string
        return e2e_greeting_pb2_grpc, "examples.e2e_greeting.Greeter"

    def get_method_type(self, method_name: str) -> str:
        if "Greet" in method_name:
            return "unary_unary"
        logger.warning(f"Unknown method {method_name} in E2EGreetingProtocol, defaulting to unary_unary.")
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        # Register the handler with the gRPC server
        e2e_greeting_pb2_grpc.add_GreeterServicer_to_server(
            cast(GreeterServiceHandler, handler), server
        )
        logger.info("GreeterService handler registered with gRPC server.")

# --- Main Server Logic ---
async def main() -> None:
    logger.info("Starting E2E Greeting Plugin Server (11_e2e_server.py)...")

    # example_utils.configure_for_example() called in __main__ will set up defaults
    # like magic cookie key if not set by the launching client.
    # The client (11_e2e_client.py) will set the expected PLUGIN_MAGIC_COOKIE_KEY
    # and PLUGIN_MAGIC_COOKIE_VALUE in the environment for this server.

    handler = GreeterServiceHandler()
    e2e_protocol_instance = cast(TypesRPCPluginProtocol, E2EGreetingProtocol())

    server: RPCPluginServer = plugin_server(
        protocol=e2e_protocol_instance,
        handler=handler,
    )

    try:
        await server.serve()
    except Exception as e:
        logger.error(f"E2E Greeting Server execution failed: {e}", exc_info=True)
    finally:
        logger.info("E2E Greeting Server (11_e2e_server.py) shutting down.")

if __name__ == "__main__":
    # It's important that example_utils.configure_for_example() is called
    # to set up necessary paths and default configurations if this server
    # is run directly, or to respect environment set by a client.
    from examples.example_utils import configure_for_example
    configure_for_example()

    asyncio.run(main())
