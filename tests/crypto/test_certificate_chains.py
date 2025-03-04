# pyvider/rpcplugin/tests/crypto/test_certificate_chains.py

import pytest

from unittest import mock

from datetime import datetime, timezone

from cryptography import x509

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import CertificateError


from tests.fixtures import *

@pytest.mark.asyncio
async def test_certificate_chain_validation(client_cert, server_cert) -> None:
    """Test validation of a certificate chain."""
    # Add server cert to client's trust chain
    client_cert.trust_chain.append(server_cert)

    # Should validate against the certificate in its trust chain
    assert client_cert.verify_trust(server_cert)

@pytest.mark.asyncio
async def test_certificate_chain_validation_no_trust(client_cert, server_cert) -> None:
    """Test validation behavior when certificates are not in trust chain."""
    # First ensure trust chain is empty
    client_cert.trust_chain = []
    server_cert.trust_chain = []

    # Without a trust chain, certificates should not validate
    # regardless of whether they are self-signed
    result = client_cert.verify_trust(server_cert)
    assert not result, "Certificates without trust chain should not validate"

@pytest.mark.asyncio
@pytest.mark.parametrize("cert_fixture", ["client_cert", "server_cert"])
async def test_certificate_basic_properties(cert_fixture, request) -> None:
    """Test basic certificate properties."""
    cert = request.getfixturevalue(cert_fixture)

    # Test required properties
    assert cert.subject
    assert cert.issuer
    assert isinstance(cert.is_ca, bool)
    assert cert.public_key
    assert isinstance(cert.public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))

@pytest.mark.asyncio
async def test_certificate_self_signed_validation(client_cert) -> None:
    """Test self-signed certificate validation."""
    # Clear trust chain first
    client_cert.trust_chain = []

    # A self-signed certificate should be in its own trust chain to validate
    if client_cert.subject == client_cert.issuer:
        client_cert.trust_chain.append(client_cert)
        assert client_cert.verify_trust(client_cert), (
            "Self-signed certificate should validate against itself when in trust chain"
        )
    else:
        pytest.skip("Certificate is not self-signed")

@pytest.mark.asyncio
async def test_certificate_extensions(client_cert) -> None:
    """Test certificate extensions are present and valid."""
    x509_cert = client_cert._cert

    # Test basic constraints
    bc = x509_cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert bc.value.ca in [True, False]

    # Test key usage if present
    try:
        ku = x509_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        assert hasattr(ku.value, "digital_signature")
    except x509.ExtensionNotFound:
        pytest.skip("Key usage extension not present")

    # Test subject alternative names if present
    try:
        san = x509_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert all(
            isinstance(name, (x509.DNSName, x509.IPAddress)) for name in san.value
        )
    except x509.ExtensionNotFound:
        pytest.skip("SAN extension not present")

@pytest.mark.asyncio
async def test_certificate_validity_period(client_cert) -> None:
    """Test certificate validity period checking."""
    now = datetime.now(timezone.utc)
    assert client_cert._cert.not_valid_before_utc <= now
    assert now <= client_cert._cert.not_valid_after_utc
    assert client_cert.is_valid

@pytest.mark.asyncio
async def test_certificate_unique_serial(client_cert, server_cert) -> None:
    """Test certificates have unique serial numbers."""
    assert client_cert._cert.serial_number != server_cert._cert.serial_number

@pytest.mark.asyncio
async def test_generate_certificate_invalid_type() -> None:
    """Test error handling for invalid key type."""
    with pytest.raises(CertificateError):
        Certificate(generate_keypair=True, key_type="invalid_type")

@pytest.mark.asyncio
async def test_certificate_repr() -> None:
    """Ensure repr() includes subject, issuer, and validity."""
    cert = Certificate(generate_keypair=True)
    cert_repr = repr(cert)
    assert "subject=" in cert_repr
    assert "issuer=" in cert_repr
    assert "valid=" in cert_repr
    assert "ca=" in cert_repr

@pytest.mark.asyncio
async def test_certificate_hash(client_cert) -> None:
    """Test certificate hash generation."""
    cert_hash = hash(client_cert)
    assert isinstance(cert_hash, int)
    # Same certificate should generate same hash
    assert hash(client_cert) == cert_hash

@pytest.mark.asyncio
async def test_certificate_invalid_trust_chain_signature() -> None:
    """Ensure certificate trust chain fails on signature mismatch."""
    cert1 = Certificate(generate_keypair=True)
    cert2 = Certificate(generate_keypair=True)

    cert1.trust_chain.append(cert2)

    with mock.patch.object(
        cert2._cert.public_key, "signature", side_effect=Exception("Signature failure")
    ):
        assert not cert1.verify_trust(cert2), (
            "Verification should fail due to invalid signature"
        )


#    # Force a signature failure
#    with mock.patch.object(
#        cert2._cert, "signature", new=cert1._cert.signature + b"corrupt"
#    ):
#        assert not cert1.verify_trust(cert2), "Verification should fail due to invalid signature"

### 🐍🏗🧪️
