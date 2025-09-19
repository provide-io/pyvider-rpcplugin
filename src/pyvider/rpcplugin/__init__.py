#
# pyvider/rpcplugin/__init__.py
#
"""
Pyvider RPC Plugin Package.

This package exports the main classes and exceptions for the Pyvider RPC Plugin system,
making them available for direct import from `pyvider.rpcplugin`.
"""

from pyvider.rpcplugin._version import __version__
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    configure,
    rpcplugin_config,
)
from pyvider.rpcplugin.exception import (
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
    "ConfigError",
    "HandshakeError",
    "ProtocolError",
    "RPCPluginClient",
    "RPCPluginConfig",
    "RPCPluginError",
    "RPCPluginProtocol",
    "RPCPluginServer",
    "SecurityError",
    "TransportError",
    "__version__",
    "configure",
    "create_basic_protocol",
    "plugin_client",
    "plugin_protocol",
    "plugin_server",
    "rpcplugin_config",
]

# 🐍🏗️🔌


# 🐍🔌🚀🪄
