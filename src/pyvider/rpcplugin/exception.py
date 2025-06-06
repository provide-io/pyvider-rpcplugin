"""
Custom Exceptions for Pyvider RPC Plugin System.

This module defines a hierarchy of custom exceptions used throughout the
Pyvider RPC Plugin system to indicate various error conditions related to
configuration, handshake, protocol, transport, and security.
"""


class RPCPluginError(Exception):
    """Base class for all RPC plugin-specific errors."""
    def __init__(self, message: str, code: int | None = None, hint: str | None = None) -> None:
        """
        Initialize RPCPluginError.

        Args:
            message: The error message.
            code: An optional error code.
            hint: An optional hint for resolving the error.
        """
        super().__init__(message)
        self.code = code
        self.hint = hint

    def __str__(self) -> str:
        """Return a string representation of the error, including the hint if available."""
        base_message = super().__str__()
        if self.hint:
            return f"{base_message} (Hint: {self.hint})"
        return base_message


class ConfigError(RPCPluginError):
    """Configuration-related errors."""


class HandshakeError(RPCPluginError):
    """Errors during the handshake."""


class ProtocolError(RPCPluginError):
    """Errors related to protocol negotiation or incompatibility."""


class TransportError(RPCPluginError):
    """Errors with the transport layer (TCP or Unix sockets)."""


class SecurityError(RPCPluginError):
    """Errors related to security (mTLS, certificate verification)."""


class CertificateError(SecurityError):
    """Credential configuration and validation errors."""


class CredentialsError(SecurityError):
    """Credential configuration and validation errors."""

# 🐍🏗️🔌
