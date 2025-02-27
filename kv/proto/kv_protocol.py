# tests/kv/kv_protocol.py

from typing import Any

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.protocol import RPCPluginProtocol

from pyvider.rpcplugin.types import (
    ServerT,
    HandlerT,
)

from tests.kv.proto import kv_pb2_grpc


class KVProtocol(RPCPluginProtocol):
    """Protocol implementation for KV service."""

    def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Get the gRPC service descriptors."""
        return kv_pb2_grpc, "KV"

    async def add_to_server(self, handler: HandlerT, server: ServerT) -> None:
        """
        Add the KV service to a gRPC server.

        Args:
            handler: The KV service handler implementation
            server: The async gRPC server instance
        """
        try:
            logger.debug(f"🔍🚀✅ Adding KV service to server with handler: {handler}")
            kv_pb2_grpc.add_KVServicer_to_server(handler, server)
        except Exception as e:
            logger.error(f"🔍❌ Failed to add KV service to server: {e}")
            raise
