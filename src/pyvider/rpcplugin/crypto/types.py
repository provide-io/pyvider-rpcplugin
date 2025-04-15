#
# pyvider/rpcplugin/crypto/types.py
#

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate as X509Certificate

# Key Types
type PrivateKeyType = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
type PublicKeyType = rsa.RSAPublicKey | ec.EllipticCurvePublicKey
type KeyPairType = tuple[PublicKeyType, PrivateKeyType]

# Certificate Types
type CertificateType = X509Certificate
type PEMType = str


class CertificateProtocolT(Protocol):
    """Protocol for certificate operations."""

    def verify_trust(self, other: "CertificateProtocolT") -> bool: ...
    @property
    def is_valid(self) -> bool: ...
    @property
    def public_key(self) -> PublicKeyType: ...

# 🐍🏗️🔌
