"""Validation functions for RPC plugin configuration."""

from __future__ import annotations

from pyvider.rpcplugin.defaults import DEFAULT_SUPPORTED_PROTOCOL_VERSIONS, DEFAULT_SERVER_TRANSPORTS
from pyvider.rpcplugin.exception import ConfigError


def _validate_protocol_versions_list(value: list[int]) -> list[int]:
    """Validate protocol versions list contains only supported versions."""
    if not value:
        raise ConfigError("Protocol versions list cannot be empty")
    for version in value:
        if version not in DEFAULT_SUPPORTED_PROTOCOL_VERSIONS:
            raise ConfigError(f"Unsupported protocol version: {version}")
    return value


def _validate_transports_list(value: list[str]) -> list[str]:
    """Validate transports list contains only supported transport types."""
    if not value:
        raise ConfigError("Transports list cannot be empty")
    for transport in value:
        if transport not in DEFAULT_SERVER_TRANSPORTS:
            raise ConfigError(f"Unsupported transport: {transport}")
    return value