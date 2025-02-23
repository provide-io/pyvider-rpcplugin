
# pyvider/rpcplugin/crypto/types.py

from typing import Protocol, TypeAlias

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate as X509Certificate

# Key Types
PrivateKeyType: TypeAlias = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
PublicKeyType: TypeAlias = rsa.RSAPublicKey | ec.EllipticCurvePublicKey
KeyPairType: TypeAlias = tuple[PublicKeyType, PrivateKeyType]

# Certificate Types
CertificateType: TypeAlias = X509Certificate
PEMType: TypeAlias = str

class CertificateProtocolT(Protocol):
    """Protocol for certificate operations."""
    def verify_trust(self, other: 'CertificateProtocolT') -> bool: ...
    @property
    def is_valid(self) -> bool: ...
    @property
    def public_key(self) -> PublicKeyType: ...
