"""
Base Definitions for RPC Plugin Protocols.

This module provides the abstract base class `RPCPluginProtocol`
which defines the interface for protocol implementations used within
the Pyvider RPC Plugin system.
"""

from abc import ABC, abstractmethod
from typing import Any


class RPCPluginProtocol[ServerT, HandlerT](ABC):  # pragma: no cover
    """
    Abstract base class for defining RPC protocols.
    ServerT: Type of gRPC server
    HandlerT: Type of handler implementation
    """

    @abstractmethod
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Returns the protobuf descriptor set and service name."""
        pass

    @abstractmethod
    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        """
        Adds the protocol implementation to the gRPC server.

        Args:
            server: The gRPC async server instance.
            handler: The handler implementing the RPC methods for this protocol.
        """
        pass


# 🐍🏗️🔌
