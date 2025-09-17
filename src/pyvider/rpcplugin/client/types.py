#
# pyvider/rpcplugin/client/types.py
#
"""
Type Definitions for Pyvider RPC Plugin Client.

This module contains type aliases, TypeVars, and Protocols used throughout
the RPC plugin client components, aiding in static analysis and code clarity.
"""

from __future__ import annotations

import asyncio
import subprocess
from typing import TYPE_CHECKING, Any, Protocol, TypeAlias, TypeVar

if TYPE_CHECKING:
    from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
    from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
    from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
    from pyvider.rpcplugin.transport.types import TransportType

import grpc

# Generic TypeVars
ClientT = TypeVar("ClientT")  # Represents an RPCPluginClient instance type

# Type Aliases for gRPC Clients
GrpcChannelType: TypeAlias = (
    grpc.aio.Channel | grpc.Channel
)  # Represents gRPC channel types (async or sync)
RpcConfigType: TypeAlias = dict[
    str, Any
]  # Represents the structure for RPC configuration dictionaries

# gRPC Credentials Type (used for TLS setup)
GrpcCredentialsType: TypeAlias = (
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


# Protocol for mixin classes to define expected attributes from RPCPluginClient
class ClientProtocol(Protocol):
    """Protocol defining the interface expected by mixin classes."""

    # Logger instance
    logger: Any

    # Process management
    _process: subprocess.Popen | None
    command: list[str]
    config: dict[str, Any] | None

    # Transport and connection
    _transport: TransportType | None
    _transport_name: str | None
    _address: str | None
    _protocol_version: int | None
    _server_cert: str | None
    grpc_channel: grpc.aio.Channel | None
    target_endpoint: str | None

    # Client state and status
    is_started: bool

    # Client certificates
    client_cert: str | None
    client_key_pem: str | None

    # Handshake events
    _handshake_complete_event: asyncio.Event
    _handshake_failed_event: asyncio.Event

    # gRPC stubs and stub storage
    _stdio_stub: GRPCStdioStub | None
    _broker_stub: GRPCBrokerStub | None
    _controller_stub: GRPCControllerStub | None
    _stubs: dict[str, Any]

    # Background tasks
    _stdio_task: asyncio.Task[None] | None
    _broker_task: asyncio.Task[None] | None

    # Methods expected by mixins
    async def _create_grpc_channel(self) -> None: ...
    async def _read_stdio_logs(self) -> None: ...
    async def _launch_process(self) -> None: ...
    async def _relay_stderr_background(self) -> None: ...
    def _cleanup_process(self) -> None: ...
    def _rebuild_x509_pem(self, cert_data: str) -> str: ...
    def _init_stubs(self) -> None: ...
    async def _perform_handshake(self) -> None: ...
    async def _setup_client_certificates(self) -> None: ...
    async def _read_raw_handshake_line_from_stdout(self) -> str: ...
    async def _connect_and_handshake_with_retry(self) -> None: ...


# 🐍🏗️🔌



# 🐍🔌📄🪄
