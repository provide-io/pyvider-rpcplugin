#
# pyvider/rpcplugin/config/validators.py
#
"""
Validation functions for RPC Plugin configuration values.

This module provides validators for configuration fields that require
custom validation logic beyond simple type checking.
"""

from __future__ import annotations

from provide.foundation.config import parse_list
from provide.foundation.errors import ValidationError

from pyvider.rpcplugin.defaults import DEFAULT_SUPPORTED_PROTOCOL_VERSIONS, DEFAULT_SUPPORTED_TRANSPORTS


def validate_protocol_versions_list(value: str | list[int]) -> list[int]:
    """Validate that all protocol versions in the list are supported.

    Args:
        value: Either a comma-separated string or a list of integers

    Returns:
        List of validated protocol version integers

    Raises:
        ValidationError: If any protocol version is not supported
    """
    if isinstance(value, str):
        # Parse comma-separated string
        str_list = parse_list(value)
        try:
            int_list = [int(x) for x in str_list if x.strip()]
        except ValueError as e:
            raise ValidationError(f"Invalid protocol version format: {e}") from e
    elif isinstance(value, list):
        int_list = value
    else:
        raise ValidationError(f"Protocol versions must be a list or comma-separated string, got {type(value)}")

    for version in int_list:
        if version not in DEFAULT_SUPPORTED_PROTOCOL_VERSIONS:
            raise ValidationError(f"Protocol version must be between 1 and 7, got {version}")
    return int_list


def validate_transport_list(value: str | list[str]) -> list[str]:
    """Validate that all transports in the list are supported.

    Args:
        value: Either a comma-separated string or a list of strings

    Returns:
        List of validated transport strings

    Raises:
        ValidationError: If any transport is not supported
    """
    if isinstance(value, str):
        # Parse comma-separated string
        str_list = parse_list(value)
    elif isinstance(value, list):
        str_list = value
    else:
        raise ValidationError(f"Transports must be a list or comma-separated string, got {type(value)}")

    for transport in str_list:
        if transport not in DEFAULT_SUPPORTED_TRANSPORTS:
            raise ValidationError(
                f"Invalid transport '{transport}'. Must be one of: {DEFAULT_SUPPORTED_TRANSPORTS}"
            )
    return str_list
