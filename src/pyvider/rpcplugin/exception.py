#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""Custom Exception Types for Pyvider RPC Plugin.

This module defines a hierarchy of custom exceptions used throughout the
Pyvider RPC Plugin system. These exceptions provide more specific error
information than standard Python exceptions, aiding in debugging and error
handling.

The base exception is `RPCPluginError`, from which all other plugin-specific
exceptions inherit. This allows for broad catching of plugin-related errors
while still enabling fine-grained handling of specific error conditions."""

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
    """
    Configuration-related errors in the RPC plugin system.

    Raised when there are issues with plugin configuration, including:
    - Invalid configuration values
    - Missing required configuration
    - Type mismatches in configuration
    - Environment variable parsing errors
    - Configuration validation failures

    Example:
        ```python
        from pyvider.rpcplugin.exception import ConfigError

        # Raise when required config is missing
        if not config.get("plugin_magic_cookie_value"):
            raise ConfigError(
                "Magic cookie value is required",
                hint="Set PLUGIN_MAGIC_COOKIE_VALUE environment variable",
                code="CONFIG_MISSING_COOKIE"
            )

        # Raise when config value is invalid
        if port < 0 or port > 65535:
            raise ConfigError(
                f"Invalid port number: {port}",
                hint="Port must be between 0 and 65535",
                code="CONFIG_INVALID_PORT"
            )
        ```
    """

    def _default_code(self) -> str:
        return "RPC_CONFIG_ERROR"


class HandshakeError(RPCPluginError):
    """
    Handshake protocol errors during plugin initialization.

    Raised when the handshake protocol fails, including:
    - Magic cookie validation failures
    - Protocol version negotiation failures
    - Transport negotiation failures
    - Certificate exchange errors
    - Timeout during handshake
    - Malformed handshake data

    Example:
        ```python
        from pyvider.rpcplugin.exception import HandshakeError

        # Raise when magic cookie doesn't match
        if received_cookie != expected_cookie:
            raise HandshakeError(
                "Magic cookie mismatch",
                hint="Ensure client and server use the same PLUGIN_MAGIC_COOKIE_VALUE",
                code="HANDSHAKE_COOKIE_MISMATCH"
            )

        # Raise when no compatible protocol version
        if not compatible_versions:
            raise HandshakeError(
                f"No compatible protocol versions: client={client_versions}, server={server_versions}",
                hint="Update client or server to support compatible protocol versions",
                code="HANDSHAKE_VERSION_MISMATCH"
            )
        ```
    """

    def _default_code(self) -> str:
        return "RPC_HANDSHAKE_ERROR"


class ProtocolError(RPCPluginError):
    """
    Protocol violation errors in RPC communication.

    Raised when the plugin protocol is violated, including:
    - Invalid message format
    - Unexpected message types
    - Protocol state violations
    - Missing required protocol fields
    - Incompatible protocol operations

    Example:
        ```python
        from pyvider.rpcplugin.exception import ProtocolError

        # Raise when message format is invalid
        if not hasattr(message, 'required_field'):
            raise ProtocolError(
                "Protocol message missing required field",
                hint="Ensure message conforms to protocol specification",
                code="PROTOCOL_INVALID_MESSAGE"
            )

        # Raise when protocol state is violated
        if not self.handshake_complete:
            raise ProtocolError(
                "Cannot send data before handshake completion",
                hint="Wait for handshake to complete before sending messages",
                code="PROTOCOL_STATE_ERROR"
            )
        ```
    """

    def _default_code(self) -> str:
        return "RPC_PROTOCOL_ERROR"


class TransportError(RPCPluginError):
    """
    Transport layer errors in plugin communication.

    Raised when transport-level issues occur, including:
    - Connection failures
    - Socket errors
    - Network timeouts
    - Invalid endpoints
    - Transport initialization failures
    - I/O errors during communication

    Example:
        ```python
        from pyvider.rpcplugin.exception import TransportError

        # Raise when connection fails
        try:
            await transport.connect(endpoint)
        except ConnectionRefusedError as e:
            raise TransportError(
                f"Failed to connect to {endpoint}",
                hint="Ensure the server is running and the endpoint is correct",
                code="TRANSPORT_CONNECTION_REFUSED"
            ) from e

        # Raise when endpoint format is invalid
        if not is_valid_endpoint(endpoint):
            raise TransportError(
                f"Invalid endpoint format: {endpoint}",
                hint="Use 'host:port' for TCP or 'unix:/path' for Unix sockets",
                code="TRANSPORT_INVALID_ENDPOINT"
            )
        ```
    """

    def _default_code(self) -> str:
        return "RPC_TRANSPORT_ERROR"


class SecurityError(RPCPluginError):
    """
    Security-related errors in the plugin system.

    Raised when security issues are detected, including:
    - Certificate validation failures
    - TLS/mTLS errors
    - Authentication failures
    - Authorization violations
    - Insecure configuration attempts
    - Certificate generation failures

    Example:
        ```python
        from pyvider.rpcplugin.exception import SecurityError

        # Raise when certificate validation fails
        if not validate_certificate(cert):
            raise SecurityError(
                "Certificate validation failed",
                hint="Check certificate expiration and CA trust chain",
                code="SECURITY_CERT_INVALID"
            )

        # Raise when insecure operation is attempted
        if config.plugin_insecure and config.plugin_auto_mtls:
            raise SecurityError(
                "Cannot enable both insecure mode and mTLS",
                hint="Choose either secure (mTLS) or insecure mode, not both",
                code="SECURITY_CONFIG_CONFLICT"
            )
        ```
    """

    def _default_code(self) -> str:
        return "RPC_SECURITY_ERROR"


# 📞🔌🔚
