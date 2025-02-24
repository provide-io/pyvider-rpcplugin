
# pyvider/rpcplugin/tests/test_certificate_crypto.py

import pytest
import pytest_asyncio

import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from pyvider.rpcplugin.crypto.certificate import Certificate

from pyvider.rpcplugin.tests.fixtures import *

from pyvider.rpcplugin.crypto import (
    KEY_TYPE_RSA,
    KEY_TYPE_ECDSA,
    DEFAULT_RSA_KEY_SIZE,
    DEFAULT_ECDSA_CURVE,
    KEY_GENERATORS,
    KeyPairType,
    generate_ec_keypair,
)

@pytest.mark.asyncio
async def test_certificate_public_key(client_cert):
    """Ensure certificate public key is valid."""
    assert client_cert.public_key, "Public key should not be None"
    assert isinstance(client_cert.public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))

@pytest.mark.asyncio
async def test_certificate_verification(client_cert, server_cert):
    """Ensure certificate can verify another certificate."""
    assert client_cert.verify_trust(server_cert) is False, "Self-verification should fail"


