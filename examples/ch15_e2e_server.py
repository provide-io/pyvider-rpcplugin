#!/usr/bin/env python3
# examples/ch15_e2e_server.py
"""
End-to-End Greeter Plugin Server.
"""

import asyncio
import os
from typing import Any, cast

import grpc

# Ensure 'src' and project root are in sys.path for direct execution of examples
# This needs to happen BEFORE attempting to import from 'examples.proto'
from example_utils import configure_for_example  # type: ignore[import-not-found]

configure_for_example(
    clear_env=False
)  # Server context, do not clear client-set env vars

# Import pyvider components
# Import generated protobuf code for E2E Greeting service
from examples.proto import e2e_greeting_pb2, e2e_greeting_pb2_grpc # noqa: E402
from pyvider.rpcplugin.factories import plugin_server # noqa: E402
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer # noqa: E402
from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol # noqa: E402
from pyvider.telemetry import logger # noqa: E402


# --- Implement the Handler (Servicer) ---
class GreeterServiceHandler(e2e_greeting_pb2_grpc.GreeterServicer):
    """
    Implements the Greeter service.
    """

    async def Greet(
        self,
        request: e2e_greeting_pb2.GreetingRequest,
        context: grpc.aio.ServicerContext,
    ) -> e2e_greeting_pb2.GreetingReply:
        logger.info(
            "GreeterServiceHandler: Received Greet request",
            client_name=request.name,
        )
        message = (
            f"Hello, {request.name}! This is a real end-to-end call "
            f"from the E2E server."
        )
        return e2e_greeting_pb2.GreetingReply(message=message)


# --- Implement the Protocol Wrapper ---
class E2EGreetingProtocol(RPCPluginProtocol):
    """
    RPCPluginProtocol implementation for the E2E Greeter service.
    """

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        # Return the generated _pb2_grpc module and the Service name string
        return e2e_greeting_pb2_grpc, "examples.e2e_greeting.Greeter"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        # Register the handler with the gRPC server
        e2e_greeting_pb2_grpc.add_GreeterServicer_to_server(
            cast(GreeterServiceHandler, handler), server
        )
        logger.info("GreeterService handler registered with gRPC server.")


# --- Main Server Logic ---
async def main() -> None:
    logger.info("Starting E2E Greeting Plugin Server (ch15_e2e_server.py)...")

    # example_utils.configure_for_example() called in __main__ will set up defaults
    # like magic cookie key if not set by the launching client.
    # The client (ch15_e2e_client.py) will set the expected PLUGIN_MAGIC_COOKIE_KEY
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
        logger.info("E2E Greeting Server (ch15_e2e_server.py) shutting down.")


if __name__ == "__main__":
    # For standalone server execution, ensure the magic cookie env var is set
    # so it can pass its own handshake validation.
    # configure_for_example() is called at module top, so rpcplugin_config is populated.
    from pyvider.rpcplugin import rpcplugin_config  # Get config after example_utils

    cookie_key_to_set = rpcplugin_config.magic_cookie_key()
    cookie_value_to_set = rpcplugin_config.magic_cookie_value()
    os.environ[cookie_key_to_set] = cookie_value_to_set
    logger.info(
        f"Standalone server mode (ch15): Set env var '{cookie_key_to_set}' to "
        f"'{cookie_value_to_set}' for self-handshake."
    )
    asyncio.run(main())
