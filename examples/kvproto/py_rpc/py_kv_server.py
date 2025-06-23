#!/usr/bin/env python3

import os
import sys

# Ensure /app/src and /app are in sys.path for module resolution
# Workaround for PYTHONPATH/editable install issues in test env.
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src"))
)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

import asyncio

# os is already imported by sys.path block
from typing import Any, cast  # Consolidated typing imports

import grpc

from examples.kvproto.py_rpc.proto import (
    KVProtocol,
    kv_pb2,
    kv_pb2_grpc,
)
from pyvider.rpcplugin.factories import plugin_server  # Added
from pyvider.rpcplugin.server import RPCPluginServer  # For type hint
from pyvider.rpcplugin.types import (
    RPCPluginProtocol as TypesRPCPluginProtocol,
)  # For cast
from pyvider.telemetry import logger

"""
py-kv-server.py

This Python key/value (KV) plugin server uses the RPCPluginServer to set up a gRPC
server and implements a file‑based key/value store. Each key/value pair is persisted
in a text file called "kv-data-<key>".

On startup, the server performs a self‑test by executing a Put/Get with a key of
"status" and a value of "pyvider server listening". This validates that the internal
storage functions work correctly and assists during gRPC debugging.
"""


# ------------------------------------------------------------------------------
# Dummy context for self‑testing (to satisfy the context parameter)
# ------------------------------------------------------------------------------
class DummyContext:
    async def abort(self, code: grpc.StatusCode, details: str) -> None:  # Annotated
        raise Exception(f"Abort: {code}, {details}")

    def peer(self) -> str:
        return "dummy_peer"

    def auth_context(self) -> dict[Any, Any]:  # Annotated
        return {}


# ------------------------------------------------------------------------------
# Helper: Summarize a text value by showing first and last 32 characters.
# ------------------------------------------------------------------------------
def summarize_text(text: str, length: int = 32) -> str:
    if len(text) <= 2 * length:
        return text
    return f"{text[:length]} ... {text[-length:]}"


# ------------------------------------------------------------------------------
# KVHandler: File‑based KV store with detailed logging
# ------------------------------------------------------------------------------
class KVHandler(kv_pb2_grpc.KVServicer):
    """
    KV service implementation that persists each key/value pair to a file.
    The file is named "kv-data-<key>" and stores the value as plain text.
    Detailed logging is added to both Put and Get methods.
    """

    _server_cert_obj: Any  # Placeholder for potential attribute

    def __init__(self) -> None:
        logger.debug("🐍 S> 🛎️📡✅ KVHandler: Initialized with file‑based persistence.")
        self._server_cert_obj = None  # Initialize if it's an instance var
        # Removed problematic certificate logging block that assumed _server_cert_obj

    async def Put(
        self, request: kv_pb2.PutRequest, context: grpc.aio.ServicerContext
    ) -> kv_pb2.Empty:
        """
        🛎️📡🚀 Put:
          - Receives a key/value pair.
          - Writes value (UTF-8 decoded) to file "kv-data-<key>".
          - Logs key, filename, and value summary (first/last 32 chars).
        """
        try:
            key = request.key
            logger.info(f"🐍 S> 🛎️📡🚀 Put: Received request for key: '{key}'")
            value_str = request.value.decode("utf-8", errors="replace")
            summary = summarize_text(value_str)
            logger.debug(
                f"🐍 S> 🛎️📡📝 Put: Storing key '{key}' with value (summary): {summary}"
            )
            filename = f"/tmp/kv-data-{key}"  # nosec B108 # Example code, /tmp is acceptable here.
            with open(filename, "w", encoding="utf-8") as f:
                f.write(value_str)
            logger.debug(
                f"🐍 S> Put: Stored key '{key}' in file '{filename}'." # Shortened
            )
            return kv_pb2.Empty()
        except Exception as e:
            logger.error(
                f"🐍 S> 🛎️📡❌ Put: Error storing key '{request.key}': {e}",
                extra={"error": str(e)},
            )
            await context.abort(grpc.StatusCode.INTERNAL, str(e))

    async def Get(
        self, request: kv_pb2.GetRequest, context: grpc.aio.ServicerContext
    ) -> kv_pb2.GetResponse:
        """
        🛎️📡🚀 Get:
          - Retrieves value for key by reading file "kv-data-<key>".
          - Logs lookup and value summary (first/last 32 chars).
        """
        try:
            key = request.key
            logger.info(f"🐍 S> 🛎️📡🚀 Get: Received request for key: '{key}'")
            filename = f"/tmp/kv-data-{key}"  # nosec B108 # Example code, /tmp is acceptable here.
            logger.debug(
                f"🐍 S> 🛎️📡📝 Get: Looking for file '{filename}' for key '{key}'."
            )
            if not os.path.exists(filename):
                logger.warning( # Shortened
                    f"🐍 S> Get: Key '{key}' not found (file '{filename}' missing)."
                )
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Key not found: {key}")
            with open(filename, encoding="utf-8") as f:
                value_str = f.read()
            summary = summarize_text(value_str)
            logger.debug(
                f"🐍 S> Get: Retrieved key '{key}', summary: {summary}" # Shortened
            )
            return kv_pb2.GetResponse(value=value_str.encode("utf-8"))
        except Exception as e:
            logger.error(
                f"🐍 S> 🛎️📡❌ Get: Error retrieving key '{request.key}': {e}",
                extra={"error": str(e)},
            )
            await context.abort(grpc.StatusCode.INTERNAL, str(e))

    async def _log_request_details(
        self, context: grpc.aio.ServicerContext
    ) -> None:  # Already annotated by user
        """Log request details (peer and auth context) for debugging."""
        try:
            logger.debug(f"🐍 S> 🛎️🧰🔍 Utils: Request from peer: {context.peer()}")
            for k, v in context.auth_context().items():
                logger.debug(f"🐍 S> 🛎️🧰🔍 Utils: Auth Context {k}: {v}")
        except Exception as e:
            logger.error(
                f"🐍 S> 🛎️🧰❌ Utils: Error logging request details: {e}",
                extra={"error": str(e)},
            )


# ------------------------------------------------------------------------------
# Server entry point
# ------------------------------------------------------------------------------
async def serve() -> None:  # Already annotated
    logger.info("🐍 S> 🛎️🚀 Starting KV plugin server...")

    # Create an instance of KVHandler.
    kv_handler: KVHandler = KVHandler()  # Annotated

    # Self-Test: Put and then Get with key "status" and value "pyvider server listening"
    dummy_context: DummyContext = DummyContext()  # Annotated
    try:
        test_key: str = "status"  # Annotated
        test_value: str = "pyvider server listening"  # Annotated
        logger.info(
            f"🐍 S> Self-Test: Put key '{test_key}', value '{test_value}'" # Shortened
        )

        await kv_handler.Put(
            kv_pb2.PutRequest(key=test_key, value=test_value.encode("utf-8")),
            dummy_context,  # type: ignore[arg-type] # Keeping ignore for dummy context
        )

        logger.info("🐍 S> 🛎️🧪 Self-Test: Put executed successfully.")
        logger.info(f"🐍 S> 🛎️🧪 Self-Test: Executing Get for key '{test_key}'")

        response: kv_pb2.GetResponse = await kv_handler.Get(  # Annotated
            kv_pb2.GetRequest(key=test_key),
            dummy_context,  # type: ignore[arg-type]
        )

        retrieved: str = response.value.decode("utf-8")  # Annotated

        logger.info(f"🐍 S> 🛎️🧪 Self-Test: Get returned: {retrieved}")

    except Exception as e:
        logger.error(
            f"🐍 S> 🛎️🧪 Self-Test: Error during self-test: {e}", extra={"error": str(e)}
        )

    try:
        # Create and configure the RPCPluginServer with KVProtocol.
        logger.debug("🐍 S> 🛎️🚀✅ Server: Server started successfully")

        server: RPCPluginServer = plugin_server(
            protocol=cast(TypesRPCPluginProtocol, KVProtocol()),
            handler=kv_handler,
        )

        await server.serve()
        logger.info("🐍 S> 🛎️🚀✅ Server: Server started successfully")

        try:
            await server._serving_future
        except asyncio.CancelledError:
            logger.info("🐍 S> 🛎️🛑 Received shutdown signal")
        finally:
            await server.stop()
            logger.info("🐍 S> 🛎️🛑 Server: Server stopped")

    except Exception as e:
        logger.error(f"🐍 S> 🛎️❗ Fatal error: {e}", extra={"error": str(e)})
        raise


if __name__ == "__main__":
    logger.info("🐍 S> -------------------------------------------------")
    logger.info(f"🐍 S> {os.environ.get('PLUGIN_CLIENT_CERT')}")
    logger.info("🐍 S> -------------------------------------------------")
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        logger.info("🐍 S> 🛎️🛑 Server: Server stopped by user")
    except Exception as e:
        logger.error(f"🐍 S> 🛎️❗ Server: Server failed: {e}", extra={"error": str(e)})
        raise
