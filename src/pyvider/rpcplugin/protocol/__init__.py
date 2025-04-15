#
# pyvider/rpcplugin/protocol/__init__.py
#

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
    "add_GRPCBrokerServicer_to_serve",
    "GRPCController",
    "GRPCControllerServicer",
    "add_GRPCControllerServicer_to_serve",
    "StreamStdio",
    "add_GRPCStdioServicer_to_server",
    "add_GRPCBrokerServicer_to_server",
    "add_GRPCControllerServicer_to_server",
    "GRPCStdio",
    "GRPCStdioServicer",
    "GRPCBrokerService",
]

# 🐍🏗️🔌
