#
# pyvider/rpcplugin/config/configure.py
#
"""
Configuration helper functions for the RPC Plugin framework.

This module provides convenience functions for configuring the RPC plugin system.
"""

from __future__ import annotations

from typing import Any

from provide.foundation.logger import logger

from pyvider.rpcplugin.exception import ConfigError


def configure(
    magic_cookie: str | None = None,
    protocol_version: int | None = None,
    transports: list[str] | None = None,
    auto_mtls: bool | None = None,
    handshake_timeout: float | None = None,
    **kwargs: Any,
) -> None:
    """
    Configure the RPC plugin system with common settings.

    This is a convenience function for setting up the most commonly
    used configuration options.

    Args:
        magic_cookie: Magic cookie value for handshake authentication
        protocol_version: Preferred protocol version
        transports: List of supported transports
        auto_mtls: Enable automatic mTLS certificate generation
        handshake_timeout: Timeout for handshake operations in seconds
        **kwargs: Additional configuration parameters
    """
    try:
        # Import here to avoid circular imports
        from pyvider.rpcplugin.config import rpcplugin_config

        if magic_cookie is not None:
            rpcplugin_config.plugin_magic_cookie_value = magic_cookie

        if protocol_version is not None:
            rpcplugin_config.plugin_core_version = protocol_version
            rpcplugin_config.plugin_protocol_versions = [protocol_version]

        if transports is not None:
            rpcplugin_config.plugin_server_transports = transports
            rpcplugin_config.plugin_client_transports = transports

        if auto_mtls is not None:
            rpcplugin_config.plugin_auto_mtls = auto_mtls

        if handshake_timeout is not None:
            rpcplugin_config.plugin_handshake_timeout = handshake_timeout

        # Apply any additional keyword arguments
        for key, value in kwargs.items():
            # Check if the field exists with plugin_ prefix
            plugin_key = f"plugin_{key}"
            if hasattr(rpcplugin_config, plugin_key):
                setattr(rpcplugin_config, plugin_key, value)
            elif hasattr(rpcplugin_config, key):
                setattr(rpcplugin_config, key, value)
            else:
                logger.warning(f"Unknown configuration parameter: {key}")

    except Exception as e:
        raise ConfigError(f"Failed to configure RPC plugin: {e}") from e
