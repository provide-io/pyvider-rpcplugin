#
# pyvider/rpcplugin/handshake/__init__.py
#
"""RPC Plugin handshake functionality.

This package provides handshake configuration, validation, building, parsing,
and negotiation capabilities for the RPC plugin system.
"""

# Core handshake functionality
from .core import (
    _SENTINEL_INSTANCE,
    HandshakeConfig,
    _SentinelEnum,
    _SentinelType,
    build_handshake_response,
    is_valid_handshake_parts,
    parse_handshake_response,
    validate_magic_cookie,
)

# Transport and protocol negotiation
from .negotiation import (
    create_stderr_relay,
    negotiate_protocol_version,
    negotiate_transport,
    read_handshake_response,
)

__all__ = [
    "_SENTINEL_INSTANCE",
    "HandshakeConfig",
    "_SentinelEnum",
    "_SentinelType",
    "build_handshake_response",
    "create_stderr_relay",
    "is_valid_handshake_parts",
    "negotiate_protocol_version",
    "negotiate_transport",
    "parse_handshake_response",
    "read_handshake_response",
    "validate_magic_cookie",
]
