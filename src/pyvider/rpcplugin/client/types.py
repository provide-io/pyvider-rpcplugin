#
# pyvider/rpcplugin/client/types.py
#

from typing import Any, Protocol, TypeVar, Union # Added Union

import grpc

# Generic TypeVars
ClientT = TypeVar("ClientT", bound="RPCPluginClient")
ConnectionT = TypeVar("ConnectionT", bound="ClientConnection")

# Type Aliases for gRPC Clients
GrpcChannelType = Union[grpc.aio.Channel, grpc.Channel]
RpcConfigType = dict[str, Any] # Removed 'type' keyword

# gRPC Credentials Type (used for TLS setup)
GrpcCredentialsType = Union[grpc.ChannelCredentials, None] # Removed 'type' and used Union


# Protocol for Clients that support secure transport & handshake
class SecureRpcClientT(Protocol):
    """Protocol for an RPC client supporting secure transport and handshake"""

    async def _perform_handshake(self) -> None: ...
    async def _setup_tls(self) -> None: ...
    async def _create_grpc_channel(self) -> None: ...
    async def close(self) -> None: ...

# 🐍🏗️🔌
