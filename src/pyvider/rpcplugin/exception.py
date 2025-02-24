
# pyvider/rpcplugin/exception.py

from typing import Optional

class RPCPluginError(Exception):
    def __init__(self, message: str, code: int = None, hint: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.hint = hint

    def __str__(self):
        return f"{super().__str__()}" # to implement another day. {self.hint}"

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
