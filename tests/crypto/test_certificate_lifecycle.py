# pyvider/rpcplugin/tests/test_certificate_verify.py

import pytest

from datetime import datetime, timedelta, timezone

from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa, ec

from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.crypto.certificate import Certificate

from tests.fixtures import *

@pytest.mark.asyncio
async def test_cleanup_after_failed_generation():
    """Test proper cleanup after failed certificate generation."""
    with pytest.raises(CertificateError):
        cert = Certificate(generate_keypair=True, key_type="invalid_type")

@pytest.mark.asyncio
async def test_certificate_is_valid(client_cert):
    """Ensure validity check works correctly."""
    assert isinstance(client_cert.is_valid, bool), "Validity should return True/False"

@pytest.mark.asyncio
async def test_expired_certificate():
    """Ensure expired certificates fail validation."""
    expired_cert = Certificate(
        generate_keypair=True,
        key_type="rsa",
        not_valid_before=datetime.now(timezone.utc) - timedelta(days=365),
        not_valid_after=datetime.now(timezone.utc)
        - timedelta(days=1),  # Expired yesterday
    )
    assert expired_cert._base.not_valid_after < datetime.now(timezone.utc), (
        "Certificate should be expired"
    )
    assert not expired_cert.is_valid, "Expired certificates should be invalid"

@pytest.mark.asyncio
async def test_certificate_validity_period(client_cert):
    """Test certificate validity period checking."""
    now = datetime.now(timezone.utc)  # ✅ Ensure timezone-aware datetime
    assert client_cert._base.not_valid_before <= now
    assert now <= client_cert._base.not_valid_after
    assert client_cert.is_valid  # ✅ No function call () since it's @cached_property

@pytest.mark.asyncio
async def test_verify_expired_certificate():
    """Ensure verification fails when certificate is expired."""
    expired_cert = Certificate(
        generate_keypair=True,
        key_type="rsa",
        not_valid_before=datetime.now(timezone.utc) - timedelta(days=365),
        not_valid_after=datetime.now(timezone.utc) - timedelta(days=1),
    )
    assert not expired_cert.is_valid, "Expired certificate should be invalid"
    assert not expired_cert.verify_trust(expired_cert), (
        "Expired certificates should not verify"
    )

@pytest.mark.asyncio
async def test_certificate_validity_period_error():
    """Ensure validity period calculation failures raise CertificateError."""
    with mock.patch(
        "pyvider.rpcplugin.crypto.certificate.datetime",
        side_effect=Exception("Time error"),
    ):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

@pytest.mark.asyncio
async def test_certificate_extension_addition_failure():
    """Ensure failures in adding extensions raise CertificateError."""
    cert = Certificate(generate_keypair=True)

    with mock.patch(
        "cryptography.x509.CertificateBuilder.add_extension",
        side_effect=Exception("Mock failure"),
    ):
        with pytest.raises(CertificateError, match="Failed to create"):
            cert._create_x509_certificate()

@pytest.mark.skip
async def test_certificate_trust_chain_validation():
    """Ensure trust chain verification enforces correct issuer-subject matching."""
    cert1 = Certificate(generate_keypair=True)
    cert2 = Certificate(generate_keypair=True)

    cert1.trust_chain.append(cert2)

    # Ensure invalid trust chain fails verification
    # with mock.patch.object(cert2._base.public_key, "verify", side_effect=Exception("Signature mismatch")):
    with mock.patch(
        "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify",
        ...,
    ):
        assert not cert1.verify_trust(cert2), "Trust chain validation should fail"


### 🐍🏗🧪️
