#
# pyvider/rpcplugin/exception.py
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

from provide.foundation.errors import (
    FoundationError,
)


class RPCPluginError(FoundationError):
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
        **kwargs: Any,
    ) -> None:
        # Store original attributes for backward compatibility
        self.message = message
        self.hint = hint
        # Note: self.code will be set by FoundationError's __init__ to ensure it's always a string

        # Add hint and code to foundation context if provided
        if hint:
            kwargs.setdefault("context", {})["hint"] = hint
        if code is not None:
            kwargs.setdefault("context", {})["error_code"] = code

        # Pass the message and code to FoundationError
        # Convert int codes to strings as required by FoundationError
        super().__init__(message, *args, code=str(code) if code is not None else None, **kwargs)

    def __str__(self) -> str:
        """Format error message with prefix, code, and hint for backward compatibility."""
        prefix = f"[{self.__class__.__name__}]"

        # Get the base message from parent (which is just the message we passed)
        base_message = self.message

        # Ensure message is prefixed only if it's not already
        effective_message = base_message
        if not base_message.startswith("[") or not base_message.lower().startswith(prefix.lower()):
            effective_message = f"{prefix} {base_message}"

        parts = [effective_message]
        # Only add code if it was explicitly provided by the user
        if self.code is not None:
            parts.append(f"[Code: {self.code}]")
        if self.hint:
            parts.append(f"(Hint: {self.hint})")

        return " ".join(parts)

    def _default_code(self) -> str:
        """Provide default error code for foundation integration."""
        return "RPC_PLUGIN_ERROR"


class ConfigError(RPCPluginError):
    """Errors related to plugin configuration issues."""

    def _default_code(self) -> str:
        return "RPC_CONFIG_ERROR"


class HandshakeError(RPCPluginError):
    """Errors occurring during the plugin handshake process."""

    def _default_code(self) -> str:
        return "RPC_HANDSHAKE_ERROR"


class ProtocolError(RPCPluginError):
    """Errors related to violations of the plugin protocol."""

    def _default_code(self) -> str:
        return "RPC_PROTOCOL_ERROR"


class TransportError(RPCPluginError):
    """Errors related to network transport or communication issues."""

    def _default_code(self) -> str:
        return "RPC_TRANSPORT_ERROR"


class SecurityError(RPCPluginError):
    """Base class for security-related errors within the plugin system."""

    def _default_code(self) -> str:
        return "RPC_SECURITY_ERROR"


# 🐍🏗️🔌


# 🐍🔌⚠️🪄
