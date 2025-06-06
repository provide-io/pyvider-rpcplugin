"""
Pyvider RPC Plugin Protocol Package.

This package defines the base RPC plugin protocol interface and re-exports
key components from the gRPC generated protocol code (services, servicers,
and registration functions) for use by clients and servers.
"""

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import (
    GRPCBroker,
    GRPCBrokerServicer,
    add_GRPCBrokerServicer_to_server,
)
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import (
    GRPCController,
    GRPCControllerServicer,
    add_GRPCControllerServicer_to_server,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import (
    GRPCStdio,
    GRPCStdioServicer,
    add_GRPCStdioServicer_to_server,
)

__all__ = [
    "RPCPluginProtocol",
    "register_protocol_service",
    "GRPCBroker",
    "GRPCBrokerServicer",
    "add_GRPCBrokerServicer_to_server",  # Corrected typo
    "GRPCController",
    "GRPCControllerServicer",
    "add_GRPCControllerServicer_to_server", # Corrected typo
    # "StreamStdio", # Removed as it's not an imported symbol
    "add_GRPCStdioServicer_to_server",
    "add_GRPCBrokerServicer_to_server", # Ensure this is not a duplicate if already corrected above (it is)
    "add_GRPCControllerServicer_to_server", # Ensure this is not a duplicate (it is)
    "GRPCStdio",
    "GRPCStdioServicer",
    "GRPCBrokerService",
]

# Consolidate __all__ to remove duplicates from corrections
__all__ = list(sorted(set(__all__)))


# 🐍🏗️🔌
