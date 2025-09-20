"""Validation functions for RPC plugin configuration."""

from __future__ import annotations

from provide.foundation.errors.config import ValidationError

from pyvider.rpcplugin.defaults import DEFAULT_SUPPORTED_PROTOCOL_VERSIONS


def _validate_protocol_versions_list(value: list[int]) -> list[int]:
    """Validate that all protocol versions in the list are supported."""
    for version in value:
        if version not in DEFAULT_SUPPORTED_PROTOCOL_VERSIONS:
            raise ValidationError(f"Protocol version must be between 1 and 7, got {version}")
    return value


def _validate_transports_list(value: list[str]) -> list[str]:
    """Validate that all transports in the list are supported."""
    valid_transports = ["unix", "tcp"]
    for transport in value:
        if transport not in valid_transports:
            raise ValidationError(f"Invalid transport '{transport}'. Must be one of: {valid_transports}")
    return value