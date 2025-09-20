"""Configuration helper functions for RPC plugin."""

from __future__ import annotations

from typing import Any

from provide.foundation import logger

from pyvider.rpcplugin.config.runtime import rpcplugin_config


def configure(
    handshake_timeout: float | None = None,
    magic_cookie: str | None = None,
    protocol_version: int | None = None,
    transports: list[str] | None = None,
    **kwargs: Any,
) -> None:
    """Configure the global RPC plugin settings.

    Args:
        handshake_timeout: Timeout for handshake operations
        magic_cookie: Magic cookie value for plugin validation
        protocol_version: Protocol version to use
        transports: List of supported transports
        **kwargs: Additional configuration parameters

    Note:
        This function modifies the global configuration instance.
        For field names, you can use either the full name (e.g., 'plugin_show_emoji_matrix')
        or the short name (e.g., 'show_emoji_matrix'). The function will automatically
        check for the prefixed version first.
    """
    # Set specific known parameters
    if handshake_timeout is not None:
        rpcplugin_config.plugin_handshake_timeout = handshake_timeout
    if magic_cookie is not None:
        rpcplugin_config.plugin_magic_cookie_value = magic_cookie
    if protocol_version is not None:
        rpcplugin_config.plugin_protocol_version = protocol_version
    if transports is not None:
        rpcplugin_config.plugin_server_transports = transports

    # Apply any additional keyword arguments
    for key, value in kwargs.items():
        # First try with plugin_ prefix
        plugin_key = f"plugin_{key}"
        if hasattr(rpcplugin_config, plugin_key):
            setattr(rpcplugin_config, plugin_key, value)
        elif hasattr(rpcplugin_config, key):
            setattr(rpcplugin_config, key, value)
        else:
            logger.warning("Unknown configuration parameter", parameter=key)