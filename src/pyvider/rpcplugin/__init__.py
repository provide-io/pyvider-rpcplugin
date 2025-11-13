"""
Pyvider RPC Plugin Package.

This package exports the main classes and exceptions for the Pyvider RPC Plugin system,
making them available for direct import from `pyvider.rpcplugin`.
"""

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    configure,
    rpcplugin_config,
)
from pyvider.rpcplugin.exception import (
    CertificateError,
    ConfigError,
    HandshakeError,
    ProtocolError,
    RPCPluginError,
    SecurityError,
    TransportError,
)
from pyvider.rpcplugin.factories import (
    create_basic_protocol,
    plugin_client,
    plugin_protocol,
    plugin_server,
)
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer

__all__ = [
    # Core Classes
    "RPCPluginClient",
    "RPCPluginServer",
    "RPCPluginProtocol",
    # Factory Functions
    "plugin_client",
    "plugin_server",
    "plugin_protocol",
    "create_basic_protocol",
    # Configuration
    "RPCPluginConfig",
    "rpcplugin_config",
    "configure",
    # Exceptions
    "RPCPluginError",
    "ConfigError",
    "HandshakeError",
    "ProtocolError",
    "TransportError",
    "SecurityError",
    "CertificateError",
]

# 🐍🏗️🔌
