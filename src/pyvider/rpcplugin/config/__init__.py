"""Configuration management for Pyvider RPC Plugin.

This module provides a Foundation-based configuration system for the Pyvider RPC Plugin framework.
Uses provide.foundation for modern async configuration loading, multi-source support, and validation.

Usage:
    # Get a configuration value
    from pyvider.rpcplugin.config import rpcplugin_config
    cookie_value = rpcplugin_config.plugin_magic_cookie_value

    # Use helper methods
    transports = rpcplugin_config.server_transports()
    timeout = rpcplugin_config.handshake_timeout()

    # Use the simplified configuration helper
    from pyvider.rpcplugin.config import configure
    configure(
        magic_cookie="my-plugin-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],
        handshake_timeout=15.0,
    )
"""

from __future__ import annotations

from pyvider.rpcplugin.config.configure import configure
from pyvider.rpcplugin.config.runtime import RPCPluginConfig, rpcplugin_config

# Export commonly used items for backward compatibility
__all__ = [
    "RPCPluginConfig",
    "configure",
    "rpcplugin_config",
]
