# examples/kvproto/py_rpc/proto/kv_protocol.py

from typing import Any  # Added Tuple

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # Corrected import
from pyvider.telemetry import logger

from . import kv_pb2_grpc


class KVProtocol(RPCPluginProtocol):
    """Protocol implementation for KV service."""

    async def get_grpc_descriptors(self) -> tuple[Any, str]:  # Changed tuple to Tuple
        """Get the gRPC service descriptors."""
        return kv_pb2_grpc, "KV"

    def get_method_type(self, method_name: str) -> str:  # Added
        # Assuming Put and Get are unary_unary for this KV service
        if method_name in (
            "Put",
            "Get",
        ):  # Method name might be /package.Service/Method
            return "unary_unary"
        logger.warning(f"Unknown method {method_name} in KVProtocol, defaulting.")
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:  # Added types
        logger.debug("🔌📡🚀 KVProtocol.add_to_server: Registering KV service")

        if not hasattr(handler, "Get") or not callable(handler.Get):
            logger.error("🔌📡❌ KVProtocol handler missing required 'Get' method")
            raise ValueError("Invalid KV handler: missing 'Get' method")

        if not hasattr(handler, "Put") or not callable(handler.Put):
            logger.error("🔌📡❌ KVProtocol handler missing required 'Put' method")
            raise ValueError("Invalid KV handler: missing 'Put' method")

        # Register the KV service implementation
        kv_pb2_grpc.add_KVServicer_to_server(handler, server)
