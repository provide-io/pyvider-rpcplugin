# pyvider/rpcplugin/protocol.py

from abc import ABC, abstractmethod
from typing import Any, Generic

from pyvider.rpcplugin.types import (
    HandlerT,
    ServerT,
)


class RPCPluginProtocol(ABC, Generic[ServerT, HandlerT]):
    """
    Abstract base class for defining RPC protocols.
    ServerT: Type of gRPC server
    HandlerT: Type of handler implementation
    """

    @abstractmethod
    def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Returns the protobuf descriptor set and service name."""
        pass

    @abstractmethod
    def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        """
        Adds the protocol implementation to the gRPC server.
        Args:
            server: The gRPC async server instance
            handler: The handler implementing the RPC methods
        """
        pass
