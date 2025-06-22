#
# src/pyvider/rpcplugin/exception.py
#

"""
Custom Exception Types for Pyvider RPC Plugin.

This module defines a hierarchy of custom exceptions used throughout the
Pyvider RPC Plugin system. These exceptions provide more specific error
information than standard Python exceptions, aiding in debugging and error
handling.

The base exception is `RPCPluginError`, from which all other plugin-specific
exceptions inherit. This allows for broad catching of plugin-related errors
while still enabling fine-grained handling of specific error conditions.
"""

from typing import Any


class RPCPluginError(Exception):
    """
    Base exception for all Pyvider RPC plugin errors.

    This class serves as the root of the exception hierarchy for the plugin system.
    It can be subclassed to create more specific error types.

    Attributes:
        message: A human-readable error message.
        hint: An optional hint for resolving the error.
        code: An optional error code associated with the error.
    """

    def __init__(
        self,
        message: str,
        hint: str | None = None,
        code: int | str | None = None,
        *args: Any,
    ) -> None:
        super().__init__(message, *args)
        self.message = message
        self.hint = hint
        self.code = code

    def __str__(self) -> str:
        parts = [self.message]
        if self.code is not None:
            parts.append(f"[Code: {self.code}]")
        if self.hint:
            parts.append(f"(Hint: {self.hint})")
        return " ".join(parts)


class ConfigError(RPCPluginError):
    """Errors related to plugin configuration issues."""


class HandshakeError(RPCPluginError):
    """Errors occurring during the plugin handshake process."""


class ProtocolError(RPCPluginError):
    """Errors related to violations of the plugin protocol."""


class TransportError(RPCPluginError):
    """Errors related to network transport or communication issues."""


class SecurityError(RPCPluginError):
    """Base class for security-related errors within the plugin system."""


class CertificateError(SecurityError):
    """
    Errors related to security certificates, private keys, or other credential
    validation and management issues.
    """


# 🐍🏗️🔌
