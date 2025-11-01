#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Pyvider RPC Plugin Package.

This package exports the main classes and exceptions for the Pyvider RPC Plugin system,
making them available for direct import from `pyvider.rpcplugin`."""

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


def __getattr__(name: str) -> str:
    """Support lazy loading of __version__.

    This reduces initial import overhead by deferring version loading
    until first access.

    Args:
        name: Attribute name to lazy-load

    Returns:
        The attribute value

    Raises:
        AttributeError: If the attribute is not found
    """
    if name == "__version__":
        from provide.foundation.utils.versioning import get_version

        return get_version("pyvider-rpcplugin", caller_file=__file__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# 🔌📞🔚
