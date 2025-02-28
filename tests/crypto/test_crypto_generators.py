# pyvider/rpcplugin/tests/crypto/test_crypto_generators.py

import pytest

from unittest import mock

import time

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.crypto.certificate import Certificate

from pyvider.rpcplugin.crypto import (
    KEY_TYPE_RSA,
    KEY_TYPE_ECDSA,
    DEFAULT_RSA_KEY_SIZE,
    DEFAULT_ECDSA_CURVE,
    KEY_GENERATORS,
    KeyPairType,
    generate_rsa_keypair,
    generate_ec_keypair,
    generate_keypair,
)


@pytest.mark.asyncio
async def test_generate_keypair_returns_keypair():
    """Ensure generate_keypair() returns correct type"""
    rsa_key = generate_keypair(KEY_TYPE_RSA)
    ec_key = generate_keypair(KEY_TYPE_ECDSA)

    # Check concrete types instead of generics
    assert isinstance(rsa_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
    assert isinstance(ec_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))

@pytest.mark.asyncio
async def test_generate_keypair_returns_keypair_1():
    """Ensure generate_keypair() always returns a KeyPairType instance."""
    rsa_key = generate_keypair(KEY_TYPE_RSA)
    ec_key = generate_keypair(KEY_TYPE_ECDSA)
    assert isinstance(rsa_key, KeyPairType), "RSA key should be a KeyPairType instance"
    assert isinstance(ec_key, KeyPairType), "EC key should be a KeyPairType instance"

@pytest.mark.asyncio
async def test_generate_keypair_invalid_type():
    """Ensure an error is raised when an invalid key type is provided."""
    with pytest.raises(ValueError, match="Unsupported key type"):
        generate_keypair("invalid_type")

@pytest.mark.asyncio
async def test_generate_rsa_keypair():
    """Test RSA keypair generation with a valid size."""
    key = generate_rsa_keypair(2048)
    assert key.key_size == 2048

@pytest.mark.asyncio
async def test_generate_rsa_keypair_backend_failure():
    """Ensure RSA key generation fails if the cryptography backend encounters an issue."""
    with mock.patch(
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
        side_effect=Exception("Backend failure"),
    ):
        with pytest.raises(Exception, match="Backend failure"):
            generate_rsa_keypair(2048)

@pytest.mark.asyncio
async def test_generate_invalid_rsa_key_size():
    """Test RSA key generation fails with an invalid key size."""
    with pytest.raises(ValueError, match="Unsupported RSA key size"):
        generate_keypair(key_type=KEY_TYPE_RSA, key_size=1024)

@pytest.mark.asyncio
async def test_generate_ec_keypair():
    """Test ECDSA keypair generation with a valid curve."""
    key = generate_keypair(key_type=KEY_TYPE_ECDSA, curve_name="secp256r1")
    assert key.curve.name == "secp256r1"

@pytest.mark.asyncio
async def test_generate_ec_keypair_invalid_curve():
    """Cover error path in generate_ec_keypair"""
    with pytest.raises(AttributeError):
        generate_ec_keypair("invalid_curve")

@pytest.mark.asyncio
async def test_generate_ec_keypair_backend_failure():
    """Ensure EC key generation fails if the cryptography backend encounters an issue."""
    with mock.patch(
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
        side_effect=Exception("Backend failure"),
    ):
        with pytest.raises(Exception, match="Backend failure"):
            generate_ec_keypair("secp256r1")

@pytest.mark.asyncio
async def test_generate_invalid_ec_curve():
    """Test ECDSA key generation fails with an invalid curve name."""
    with pytest.raises(ValueError, match="Unsupported EC curve"):
        generate_keypair(key_type=KEY_TYPE_ECDSA, curve_name="invalid_curve")

@pytest.mark.asyncio
async def test_generate_unsupported_key_type():
    """Test unsupported key type raises an error."""
    with pytest.raises(ValueError, match="Unsupported key type"):
        generate_keypair(key_type="unsupported_type")

@pytest.mark.asyncio
async def test_key_generation_performance():
    start_time = time.time()
    cert = Certificate(generate_keypair=True, key_type=KEY_TYPE_RSA, key_size=2048)
    generation_time = time.time() - start_time
    assert generation_time < 1.0  # Should complete within 1 second

### 🐍🏗🧪️
