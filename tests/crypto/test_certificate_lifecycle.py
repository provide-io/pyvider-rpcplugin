# pyvider/rpcplugin/tests/test_certificate_verify.py

import pytest

from datetime import datetime, timezone

from unittest import mock


from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.crypto.certificate import Certificate

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.crypto import client_cert


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
        validity_days=-1,  # Set to expire yesterday relative to its creation 'now'
    )

    # Ensure the certificate's not_valid_after is indeed in the past
    # compared to the current real time.
    # datetime.now(timezone.utc) inside the test will be slightly after
    # the datetime.now(timezone.utc) used inside Certificate's __attrs_post_init__.
    current_real_now = datetime.now(timezone.utc)
    assert expired_cert._base.not_valid_after < current_real_now, (
        f"Certificate expiry date {expired_cert._base.not_valid_after} should be before current time {current_real_now}"
    )

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
        validity_days=-1,  # Set to make it expired
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
async def test_certificate_trust_chain_validation() -> (
    None
):  # Name can remain, or be more specific
    """Ensure trust chain verification correctly fails on a mocked signature mismatch."""
    # Ensure 'mock' is imported from unittest (already imported at file level)
    # from unittest import mock

    relying_party_cert = Certificate(
        generate_keypair=True, common_name="RelyingPartyCert", key_type="ecdsa"
    )
    ca_cert = Certificate(
        generate_keypair=True, common_name="TestCACert", key_type="ecdsa"
    )

    relying_party_cert.trust_chain = [ca_cert]  # relying_party_cert trusts ca_cert

    end_entity_cert = Certificate(
        generate_keypair=True, common_name="EndEntityToVerify", key_type="ecdsa"
    )

    # Mock end_entity_cert's issuer to be ca_cert's subject so that the
    # issuer check within _validate_signature passes, forcing a signature attempt.
    # REMOVED: with mock.patch.object(end_entity_cert._cert, 'issuer', ca_cert._cert.subject):

    # The mock for EllipticCurvePublicKey.verify can remain. If the issuer check *were* to pass
    # (which it won't for these two unrelated certs as end_entity_cert is self-signed with a different subject),
    # this mock would ensure failure.
    # With unrelated certs, _validate_signature will return False due to issuer mismatch
    # *before* the EllipticCurvePublicKey.verify line is reached.
    with mock.patch(
        "cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify",
        side_effect=Exception("Simulated Signature Failure"),
    ):
        # relying_party_cert.verify_trust(end_entity_cert) will call:
        # _validate_signature(signed_cert=end_entity_cert, signing_cert=ca_cert)
        # Inside _validate_signature, since end_entity_cert.issuer (self-signed) != ca_cert.subject,
        # it will return False.
        # Thus, verify_trust will return False.
        assert not relying_party_cert.verify_trust(end_entity_cert), (
            "Verification of an unrelated certificate (or one with a bad signature if issuers matched) should fail."
        )


### 🐍🏗🧪️
