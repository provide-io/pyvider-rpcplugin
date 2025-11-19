#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""Type Definitions for Pyvider RPC Plugin Client.

This module contains type aliases, TypeVars, and Protocols used throughout
the RPC plugin client components, aiding in static analysis and code clarity."""

from __future__ import annotations

from typing import (
    TYPE_CHECKING,
    Any,
    Protocol,
    TypeVar,
)

import grpc

if TYPE_CHECKING:
    from pyvider.rpcplugin.transport import UnixTransport

# Generic TypeVars
ClientT = TypeVar("ClientT")
SecureRpcClientT = TypeVar("SecureRpcClientT", bound="SecureRpcClient")

# gRPC related types
GrpcChannelType = grpc.aio.Channel
GrpcCredentialsType = grpc.ChannelCredentials

# Configuration dictionary type
RpcConfigType = dict[str, Any]


# Transport types
TransportType = "UnixTransport"


# Protocol for RPC client
class RpcClient(Protocol):
    """
    Protocol defining the interface for a secure RPC client.
    """

    grpc_channel: GrpcChannelType | None
    target_endpoint: str | None
    client_cert: str | None
    client_key_pem: str | None

    async def _perform_handshake(self) -> None: ...
    async def _setup_tls(
        self,
    ) -> None: ...
    async def _create_grpc_channel(self) -> None: ...
    async def close(self) -> None: ...

# 📞🔌🔚
