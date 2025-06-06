"""
Pyvider RPC Plugin Package.

This package exports the main classes and exceptions for the Pyvider RPC Plugin system,
making them available for direct import from `pyvider.rpcplugin`.
"""

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.config import RPCPluginConfig, rpcplugin_config
from pyvider.rpcplugin.exception import (
    HandshakeError,
    ProtocolError,
    RPCPluginError,
    SecurityError,
    TransportError,
)
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer

__all__ = [
    "RPCPluginConfig",
    "rpcplugin_config",
    "RPCPluginProtocol",
    "RPCPluginClient",
    "RPCPluginServer",
    "RPCPluginError",
    "HandshakeError",
    "ProtocolError",
    "TransportError",
    "SecurityError",
]

# 🐍🏗️🔌
