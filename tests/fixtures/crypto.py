# tests/fixtures/crypto.py

from pathlib import Path  # Moved to top

import pytest

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.telemetry import logger


@pytest.fixture(scope="module")
def dev_root_ca() -> Certificate:
    """Generates a self-signed CA certificate for testing mTLS setups."""
    ca = Certificate.create_ca(
        common_name="Test Fixture Root CA",
        organization_name="Pyvider Test Fixtures",
        validity_days=7,  # Longer validity for a module-scoped CA
    )
    logger.info(f"Generated Test Fixture Root CA: {ca.cert[:30]}...")
    return ca


@pytest.fixture(scope="module")
def client_cert(dev_root_ca: Certificate) -> Certificate:
    """
    Loads the client certificate from environment or generates a default one
    signed by dev_root_ca.
    """
    from pyvider.rpcplugin.config import rpcplugin_config

    cert_env_val = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
    key_env_val = rpcplugin_config.get("PLUGIN_CLIENT_KEY")

    cert_is_pem_like = cert_env_val and cert_env_val.strip().startswith(
        "-----BEGIN CERTIFICATE-----"
    )
    key_is_pem_like = key_env_val and key_env_val.strip().startswith("-----BEGIN ")

    cert_to_use = cert_env_val if cert_is_pem_like else None
    key_to_use = key_env_val if key_is_pem_like else None

    if not cert_to_use or not key_to_use:
        logger.info(
            "PLUGIN_CLIENT_CERT or PLUGIN_CLIENT_KEY not found/PEM-like in env, "
            "generating default client cert for tests."
        )
        default_client_cert_obj = Certificate.create_signed_certificate(
            ca_certificate=dev_root_ca,
            common_name="TestDefaultClientCert",
            organization_name="Pyvider Test Fixtures",
            alt_names=["localhost", "client.example.test"],
            validity_days=1,
            is_client_cert=True,
        )
        cert_to_use = default_client_cert_obj.cert
        key_to_use = default_client_cert_obj.key
        logger.info(f"Generated default CLIENT_CERT: {cert_to_use[:30]}...")
    else:
        logger.info(f"Using CLIENT_CERT from env: {cert_to_use[:30]}...")

    if key_to_use is None:  # Should not happen if generated, but as a safeguard
        raise ValueError("Client key ended up being None, which is unexpected.")

    return Certificate(cert_pem_or_uri=cert_to_use, key_pem_or_uri=key_to_use)


@pytest.fixture(scope="module")
def server_cert(dev_root_ca: Certificate) -> Certificate:
    """
    Loads the server certificate from environment or generates one signed by
    dev_root_ca.
    """
    from pyvider.rpcplugin.config import rpcplugin_config

    cert_env_val = rpcplugin_config.get("PLUGIN_SERVER_CERT")
    key_env_val = rpcplugin_config.get("PLUGIN_SERVER_KEY")

    cert_is_pem_like = cert_env_val and cert_env_val.strip().startswith(
        "-----BEGIN CERTIFICATE-----"
    )
    key_is_pem_like = key_env_val and key_env_val.strip().startswith("-----BEGIN ")

    cert_to_use = cert_env_val if cert_is_pem_like else None
    key_to_use = key_env_val if key_is_pem_like else None

    if not cert_to_use or not key_to_use:
        logger.info(
            "PLUGIN_SERVER_CERT or PLUGIN_SERVER_KEY not found/PEM-like in env, "
            "generating default server cert for tests."
        )
        default_server_cert_obj = Certificate.create_signed_certificate(
            ca_certificate=dev_root_ca,
            common_name="TestDefaultServerCert",
            organization_name="Pyvider Test Fixtures",
            alt_names=["localhost", "server.example.test", "127.0.0.1"],
            validity_days=1,
            is_client_cert=False,
        )
        cert_to_use = default_server_cert_obj.cert
        key_to_use = default_server_cert_obj.key
        logger.info(f"Generated default SERVER_CERT: {cert_to_use[:30]}...")
    else:
        logger.info(f"Using SERVER_CERT from env: {cert_to_use[:30]}...")

    if key_to_use is None:  # Safeguard
        raise ValueError("Server key ended up being None, which is unexpected.")

    return Certificate(cert_pem_or_uri=cert_to_use, key_pem_or_uri=key_to_use)


@pytest.fixture(scope="module")
def valid_key_pem(client_cert: Certificate) -> str | None:
    """Get a valid key PEM from the client cert fixture."""
    return client_cert.key


@pytest.fixture
def valid_cert_pem(client_cert: Certificate) -> str:
    """Get a valid certificate PEM from the client cert fixture."""
    return client_cert.cert


@pytest.fixture
def invalid_key_pem() -> str:
    """Returns an invalid PEM string (not a valid key)."""
    return "INVALID KEY DATA"


@pytest.fixture
def invalid_cert_pem() -> str:
    """Returns an invalid PEM string (not a valid certificate)."""
    return "INVALID CERTIFICATE DATA"


@pytest.fixture
def malformed_cert_pem() -> str:
    """Returns a PEM-like string with incorrect headers."""
    return "-----BEGIN CERT-----\nMALFORMED DATA\n-----END CERT-----"


@pytest.fixture
def empty_cert() -> str:
    """Returns an empty certificate string."""
    return ""


@pytest.fixture
def temporary_cert_file(tmp_path: Path, client_cert: Certificate) -> str:
    """Creates a temporary file containing the client certificate."""
    cert_file = tmp_path / "client_cert.pem"
    cert_file.write_text(client_cert.cert)
    return f"file://{cert_file}"


@pytest.fixture
def temporary_key_file(tmp_path: Path, client_cert: Certificate) -> str:
    """Creates a temporary file containing the client private key."""
    key_file = tmp_path / "client_key.pem"
    if client_cert.key:  # Ensure key is not None before writing
        key_file.write_text(client_cert.key)
    else:
        # Handle case where key might be None
        key_file.write_text("")  # Or raise an error if key is essential
        logger.warning(
            "Client certificate fixture had no key, temporary key file is empty."
        )
    return f"file://{key_file}"


@pytest.fixture(scope="module")
def external_dev_ca_pem() -> str:
    """
    Provides a known-good, externally generated self-signed CA certificate PEM
    string.
    """
    # This is a sample ECDSA P-256 CA certificate.
    # Issuer: CN=External Test CA, O=MyOrg
    # Subject: CN=External Test CA, O=MyOrg
    # Basic Constraints: CA:TRUE
    # Key Usage: Certificate Sign, CRL Sign
    return """-----BEGIN CERTIFICATE-----
MIIB4TCCAYegAwIBAgIJAPZ9vcVfR8AdMAoGCCqGSM49BAMCMFExCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FuIEZyYW5jaXNjbzEOMAwGA1UE
CgwFTXlPcmcxEzARBgNVBAMMCkV4dGVybmFsIENBMB4XDTI0MDgwMjEwNTgwMVoX
DTM0MDczMDEwNTgwMVowUTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYD
VQQHDAhTYW5EaWVnbzEOMAwGA1UECgwFTXlPcmcxEzARBgNVBAMMCkV4dGVybmFs
IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgyF5Y8upm+M3ZzO8P4n7q2sS+L4c
mhl5XGg3vIOwFf7lG8XZCgJ6Xy4t1t8oD3zY0m9X8H8Z4YhY7K6b7c8Y7Xv6Y9fV
Q8M7Jg9nJ0x5c1N40zQwZzKjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBTGX00Gq7b09y/0C9eK0XgJp0mY7DAKBggqhkjOPQQD
AgNJADBGAiEAx1xH/b83/u5t7r29a/THZnFjQ7pvT2N0L4hG4BgGgXACIQD02W2+
MHB78ZWM+JOgikYj99qD6nLp0nkMyGmkSC7RYg==
-----END CERTIFICATE-----
"""


### 🐍🏗🧪️
