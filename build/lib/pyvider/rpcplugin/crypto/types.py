"""
Type Definitions for Pyvider RPC Plugin Cryptography.

This module defines common type aliases and protocols used across the
cryptography-related components of the Pyvider RPC Plugin system.
"""

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate as X509Certificate

# Key Types
type PrivateKeyType = (
    rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
)  # Union of possible private key types
type PublicKeyType = (
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey
)  # Union of possible public key types
type KeyPairType = tuple[
    PublicKeyType, PrivateKeyType
]  # A tuple representing a public/private key pair

# Certificate Types
type CertificateType = (
    X509Certificate  # Alias for the cryptography library's Certificate type
)
type PEMType = str  # Represents a PEM-encoded string


class CertificateProtocolT(Protocol):
    """Protocol for certificate operations, defining a common interface."""

    def verify_trust(self, other: "CertificateProtocolT") -> bool: ...
    @property
    def is_valid(self) -> bool: ...
    @property
    def public_key(self) -> PublicKeyType: ...


# 🐍🏗️🔌
