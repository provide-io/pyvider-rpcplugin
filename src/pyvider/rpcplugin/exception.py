"""
Custom Exceptions for Pyvider RPC Plugin System.

This module defines a hierarchy of custom exceptions used throughout the
Pyvider RPC Plugin system to indicate various error conditions related to
configuration, handshake, protocol, transport, and security.
"""


class RPCPluginError(Exception):
    """Base class for all RPC plugin-specific errors."""

    def __init__(
        self, message: str, code: int | None = None, hint: str | None = None
    ) -> None:
        """
        Initialize RPCPluginError.

        Args:
            message: The error message.
            code: An optional error code.
            hint: An optional hint for resolving the error.
        """
        super().__init__(message)
        self.message = message  # Add this line
        self.code = code
        self.hint = hint

    def __str__(self) -> str:
        MAX_MSG_LEN = 256  # Max length for the base message part
        MAX_HINT_LEN = 128 # Max length for the hint part

        base_message = super().__str__()
        if len(base_message) > MAX_MSG_LEN:
            base_message = base_message[:MAX_MSG_LEN] + "..."

        output_message = f"[{self.__class__.__name__}] {base_message}"

        if self.code is not None:
            output_message += f" (Code: {self.code})"

        if self.hint:
            hint_str = self.hint
            if len(hint_str) > MAX_HINT_LEN:
                hint_str = hint_str[:MAX_HINT_LEN] + "..."
            output_message += f" (Hint: {hint_str})"
        return output_message


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
    """Errors related to security certificates, private keys, or other credential validation and management issues."""


# 🐍🏗️🔌
