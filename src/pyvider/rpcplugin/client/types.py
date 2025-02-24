# pyvider/rpcplugin/client/types.py

from typing import Any, Protocol, TypeVar

import grpc

# Generic TypeVars
ClientT = TypeVar("ClientT", bound="RPCPluginClient")
ConnectionT = TypeVar("ConnectionT", bound="ClientConnection")

# Type Aliases for gRPC Clients
type GrpcChannelType = grpc.aio.Channel | grpc.Channel
type RpcConfigType = dict[str, Any]

# gRPC Credentials Type (used for TLS setup)
type GrpcCredentialsType = grpc.ChannelCredentials | None


# Protocol for Clients that support secure transport & handshake
class SecureRpcClientT(Protocol):
    """Protocol for an RPC client supporting secure transport and handshake"""

    async def _perform_handshake(self) -> None: ...
    async def _setup_tls(self) -> None: ...
    async def _create_grpc_channel(self) -> None: ...
    async def close(self) -> None: ...
