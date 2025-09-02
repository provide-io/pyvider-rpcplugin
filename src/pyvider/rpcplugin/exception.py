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
    AuthenticationError,
    ConfigurationError,
    FoundationError,
    NetworkError,
    ValidationError,
)


class RPCPluginError(FoundationError):
    """
    Base exception for all Pyvider RPC plugin errors.

    This class serves as the root of the exception hierarchy for the plugin system.
    It can be subclassed to create more specific error types.
    """

    def _default_code(self) -> str:
        """Provide default error code for foundation integration."""
        return "RPC_PLUGIN_ERROR"


class ConfigError(ConfigurationError):
    """Errors related to plugin configuration issues."""
    
    def _default_code(self) -> str:
        return "RPC_CONFIG_ERROR"


class HandshakeError(NetworkError):
    """Errors occurring during the plugin handshake process."""
    
    def _default_code(self) -> str:
        return "RPC_HANDSHAKE_ERROR"


class ProtocolError(ValidationError):
    """Errors related to violations of the plugin protocol."""
    
    def _default_code(self) -> str:
        return "RPC_PROTOCOL_ERROR"


class TransportError(NetworkError):
    """Errors related to network transport or communication issues."""
    
    def _default_code(self) -> str:
        return "RPC_TRANSPORT_ERROR"


class SecurityError(AuthenticationError):
    """Base class for security-related errors within the plugin system."""
    
    def _default_code(self) -> str:
        return "RPC_SECURITY_ERROR"


class CertificateError(SecurityError):
    """
    Errors related to security certificates, private keys, or other credential
    validation and management issues.
    """
    
    def _default_code(self) -> str:
        return "RPC_CERTIFICATE_ERROR"


# 🐍🏗️🔌



# 🐍🔌⚠️🪄
