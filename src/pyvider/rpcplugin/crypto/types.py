#
# pyvider/rpcplugin/crypto/types.py
#
"""
Type Definitions for Pyvider RPC Plugin Cryptography.

This module defines common type aliases and protocols used across the
cryptography-related components of the Pyvider RPC Plugin system.
"""

from typing import Protocol, TypeAlias

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate as X509Certificate

# Key Types
PrivateKeyType: TypeAlias = (
    rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
)  # Union of possible private key types
PublicKeyType: TypeAlias = (
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey
)  # Union of possible public key types
KeyPairType: TypeAlias = tuple[
    PublicKeyType, PrivateKeyType
]  # A tuple representing a public/private key pair

# Certificate Types
CertificateType: TypeAlias = (
    X509Certificate  # Alias for the cryptography library's Certificate type
)
PEMType: TypeAlias = str  # Represents a PEM-encoded string


class CertificateProtocolT(Protocol):
    """Protocol for certificate operations, defining a common interface."""

    def verify_trust(self, other: "CertificateProtocolT") -> bool: ...
    @property
    def is_valid(self) -> bool: ...
    @property
    def public_key(self) -> PublicKeyType: ...


# 🐍🏗️🔌



# 🐍🔌📄🪄
