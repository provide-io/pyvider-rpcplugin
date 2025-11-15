"""
Type Definitions for Pyvider RPC Plugin Client.

This module contains type aliases, TypeVars, and Protocols used throughout
the RPC plugin client components, aiding in static analysis and code clarity.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, TypeVar

if TYPE_CHECKING:
    from .base import RPCPluginClient
    from .connection import ClientConnection

import grpc

# Generic TypeVars
ClientT = TypeVar(
    "ClientT", bound="RPCPluginClient"
)  # Represents an RPCPluginClient instance type
ConnectionT = TypeVar(
    "ConnectionT", bound="ClientConnection"
)  # Represents a ClientConnection instance type

# Type Aliases for gRPC Clients
type GrpcChannelType = (
    grpc.aio.Channel | grpc.Channel
)  # Represents gRPC channel types (async or sync)
type RpcConfigType = dict[
    str, Any
]  # Represents the structure for RPC configuration dictionaries

# gRPC Credentials Type (used for TLS setup)
type GrpcCredentialsType = (
    grpc.ChannelCredentials | None
)  # Represents gRPC channel credentials, possibly None


# Protocol for Clients that support secure transport & handshake
class SecureRpcClientT(Protocol):
    """Protocol for an RPC client supporting secure transport and handshake."""

    async def _perform_handshake(self) -> None: ...
    async def _setup_tls(
        self,
    ) -> None: ...
    async def _create_grpc_channel(self) -> None: ...
    async def close(self) -> None: ...


# 🐍🏗️🔌
