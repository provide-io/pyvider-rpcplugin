#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""Validation functions for RPC Plugin configuration values.

This module provides validators for configuration fields that require
custom validation logic beyond simple type checking."""

from provide_foundation.config import (
    env_field,
    parse_list,
    ValidationError,
)

from pyvider.rpcplugin.config.defaults import (
    DEFAULT_PLUGIN_CORE_VERSION,
    DEFAULT_PLUGIN_PROTOCOL_VERSIONS,
    DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
    DEFAULT_SUPPORTED_TRANSPORTS,
)


def validate_protocol_version(value: str | list[int]) -> list[int]:
    """Validate protocol versions against the supported list.

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


def parse_log_level(value: str) -> str:
    """Validate log level."""
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if value.upper() in valid_levels:
        return value.upper()
    raise ValidationError(f"Invalid log level: {value}. Must be one of {valid_levels}")


# Define fields with validators
PLUGIN_PROTOCOL_VERSIONS_FIELD = env_field(
    default=DEFAULT_PLUGIN_PROTOCOL_VERSIONS,
    parser=validate_protocol_version,
    env_var="PLUGIN_PROTOCOL_VERSIONS",
)

PLUGIN_PROTOCOL_VERSION_FIELD = env_field(
    default=DEFAULT_PLUGIN_CORE_VERSION,
    parser=int,
    env_var="PLUGIN_PROTOCOL_VERSION",
)

SUPPORTED_PROTOCOL_VERSIONS_FIELD = env_field(
    default=DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
    parser=validate_protocol_version,
    env_var="SUPPORTED_PROTOCOL_VERSIONS",
)

PLUGIN_SERVER_TRANSPORTS_FIELD = env_field(
    default=DEFAULT_SUPPORTED_TRANSPORTS,
    parser=validate_transport_list,
    env_var="PLUGIN_SERVER_TRANSPORTS",
)

PLUGIN_CLIENT_TRANSPORTS_FIELD = env_field(
    default=DEFAULT_SUPPORTED_TRANSPORTS,
    parser=validate_transport_list,
    env_var="PLUGIN_CLIENT_TRANSPORTS",
)

PLUGIN_SUPPORTED_TRANSPORTS_FIELD = env_field(
    default=DEFAULT_SUPPORTED_TRANSPORTS,
    parser=validate_transport_list,
    env_var="PLUGIN_SUPPORTED_TRANSPORTS",
)
# 📞🔌🔚
