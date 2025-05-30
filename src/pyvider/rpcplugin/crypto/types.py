#
# pyvider/rpcplugin/crypto/types.py
#

from typing import Protocol, Union

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import Certificate as X509Certificate

# Key Types
PrivateKeyType = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
PublicKeyType = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
KeyPairType = tuple[PublicKeyType, PrivateKeyType]

# Certificate Types
CertificateType = X509Certificate
PEMType = str


class CertificateProtocolT(Protocol):
    """Protocol for certificate operations."""

    def verify_trust(self, other: "CertificateProtocolT") -> bool: ...
    @property
    def is_valid(self) -> bool: ...
    @property
    def public_key(self) -> PublicKeyType: ...

# 🐍🏗️🔌
