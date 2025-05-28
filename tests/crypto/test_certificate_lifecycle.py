# pyvider/rpcplugin/tests/test_certificate_verify.py

import pytest

from datetime import datetime, timedelta, timezone

from unittest import mock


from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.crypto.certificate import Certificate

from tests.fixtures import *

@pytest.mark.asyncio
async def test_cleanup_after_failed_generation() -> None:
    """Test proper cleanup after failed certificate generation."""
    with pytest.raises(CertificateError):
        Certificate(generate_keypair=True, key_type="invalid_type")

@pytest.mark.asyncio
async def test_certificate_is_valid(client_cert) -> None:
    """Ensure validity check works correctly."""
    assert isinstance(client_cert.is_valid, bool), "Validity should return True/False"

@pytest.mark.asyncio
async def test_expired_certificate() -> None:
    """Ensure expired certificates fail validation."""
    expired_cert = Certificate(
        generate_keypair=True,
        key_type="rsa",
        validity_days=-1  # Set to expire yesterday relative to its creation 'now'
    )
    
    # Ensure the certificate's not_valid_after is indeed in the past
    # compared to the current real time.
    # datetime.now(timezone.utc) inside the test will be slightly after 
    # the datetime.now(timezone.utc) used inside Certificate's __attrs_post_init__.
    current_real_now = datetime.now(timezone.utc)
    assert expired_cert._base.not_valid_after < current_real_now, \
        f"Certificate expiry date {expired_cert._base.not_valid_after} should be before current time {current_real_now}"
    
    assert not expired_cert.is_valid, "Expired certificates should be invalid"

@pytest.mark.asyncio
async def test_certificate_validity_period(client_cert) -> None:
    """Test certificate validity period checking."""
    now = datetime.now(timezone.utc)  # ✅ Ensure timezone-aware datetime
    assert client_cert._base.not_valid_before <= now
    assert now <= client_cert._base.not_valid_after
    assert client_cert.is_valid  # ✅ No function call () since it's @cached_property

@pytest.mark.asyncio
async def test_verify_expired_certificate() -> None:
    """Ensure verification fails when certificate is expired."""
    expired_cert = Certificate(
        generate_keypair=True,
        key_type="rsa",
        validity_days=-1  # Set to make it expired
    )
    assert not expired_cert.is_valid, "Expired certificate should be invalid"
    assert not expired_cert.verify_trust(expired_cert), (
        "Expired certificates should not verify"
    )

@pytest.mark.asyncio
async def test_certificate_validity_period_error() -> None:
    """Ensure validity period calculation failures raise CertificateError."""
    with mock.patch(
        "pyvider.rpcplugin.crypto.certificate.datetime",
        side_effect=Exception("Time error"),
    ):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

@pytest.mark.asyncio
async def test_certificate_extension_addition_failure() -> None:
    """Ensure failures in adding extensions raise CertificateError."""
    cert = Certificate(generate_keypair=True)

    with mock.patch(
        "cryptography.x509.CertificateBuilder.add_extension",
        side_effect=Exception("Mock failure"),
    ):
        with pytest.raises(CertificateError, match="Failed to create"):
            cert._create_x509_certificate()

@pytest.mark.asyncio
async def test_certificate_trust_chain_validation() -> None:
    """Ensure trust chain verification enforces correct issuer-subject matching."""
    cert1 = Certificate(generate_keypair=True)
    cert2 = Certificate(generate_keypair=True)

    cert1.trust_chain.append(cert2)

    # Ensure invalid trust chain fails verification
    with mock.patch(
        "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify",
        side_effect=Exception("Signature failure")
    ):
        assert not cert1.verify_trust(cert2), "Trust chain validation should fail"

### 🐍🏗🧪️
