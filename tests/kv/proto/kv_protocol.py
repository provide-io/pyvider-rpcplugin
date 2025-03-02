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


    async def add_to_server(self, handler, server) -> None:
        logger.debug("🔌📡🚀 KVProtocol.add_to_server: Registering KV service")
        
        if not hasattr(handler, 'Get') or not callable(handler.Get):
            logger.error("🔌📡❌ KVProtocol handler missing required 'Get' method")
            raise ValueError("Invalid KV handler: missing 'Get' method")
            
        if not hasattr(handler, 'Put') or not callable(handler.Put):
            logger.error("🔌📡❌ KVProtocol handler missing required 'Put' method")
            raise ValueError("Invalid KV handler: missing 'Put' method")
            
        # Register the KV service implementation
        kv_pb2_grpc.add_KVServicer_to_server(handler, server)
