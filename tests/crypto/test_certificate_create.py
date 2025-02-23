
# pyvider/rpcplugin/tests/crypto/test_certificate_create.py

import pytest

from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.crypto.certificate import (
    Certificate,
    CertificateBase,
    CertificateConfig,
)



# 3. Certificate Creation Error Tests
def test_create_x509_cert_subject_error():
    """Test error in subject/issuer name creation."""
    with mock.patch('cryptography.x509.Name', side_effect=Exception("Name error")):
        with pytest.raises(CertificateError, match="Failed to generate"):
            Certificate(generate_keypair=True)

def test_create_x509_cert_serial_error():
    """Test error in serial number generation."""
    with mock.patch('os.urandom', side_effect=Exception("urandom failed")):
        with pytest.raises(CertificateError, match="Failed to generate"):
            Certificate(generate_keypair=True)

def test_create_x509_cert_validity_error():
    """Test error in validity period calculation."""
    # Mock datetime.timezone to raise an exception
    with mock.patch('pyvider.rpcplugin.crypto.certificate.timezone',
                   side_effect=Exception("Time error")):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

def test_create_x509_cert_builder_error():
    """Test error in certificate builder."""
    with mock.patch('cryptography.x509.CertificateBuilder.subject_name', 
                   side_effect=Exception("Builder error")):
        with pytest.raises(CertificateError, match="Failed to create X.509 certificate"):
            Certificate(generate_keypair=True)

def test_create_x509_cert_extension_error():
    """Test error in adding certificate extensions."""
    with mock.patch('cryptography.x509.CertificateBuilder.add_extension', 
                   side_effect=Exception("Extension error")):
        with pytest.raises(CertificateError, match="Failed to"):
            Certificate(generate_keypair=True)

def test_create_invalid_key_type():
    """Ensure unsupported key types raise ValueError."""
    config = CertificateConfig(
        common_name="test",
        organization="test",
        key_type=123  # Invalid type, not a KeyType Enum
    )
    with pytest.raises(CertificateError, match="Unsupported key type"):
        CertificateBase.create(config)

def test_certificate_extension_failure():
    """Ensure extension addition failures raise CertificateError."""
    cert = Certificate(generate_keypair=True)

    with mock.patch("cryptography.x509.CertificateBuilder.add_extension", side_effect=Exception("Mock failure")):
        with pytest.raises(CertificateError, match="Failed to create"):
            cert._create_x509_certificate()

def test_create_x509_cert_validity_error():
    """Test error in validity period calculation."""
    with mock.patch('pyvider.rpcplugin.crypto.certificate.datetime', side_effect=Exception("Time error")):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

def test_create_x509_cert_extension_error():
    """Test error in adding certificate extensions."""
    cert = Certificate(generate_keypair=True)

    with mock.patch("cryptography.x509.CertificateBuilder.add_extension", side_effect=Exception("Mock failure")):
        with pytest.raises(CertificateError, match="Failed to create"):
            cert._create_x509_certificate()
