# tests/fixtures/crypto.py

import pytest


from pyvider.telemetry import logger
from pyvider.rpcplugin.crypto.certificate import Certificate


@pytest.fixture(scope="module")
def client_cert():
    """Loads the server certificate from the environment variable."""
    from pyvider.rpcplugin.config import rpcplugin_config

    cert_pem_from_env = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
    key_pem_from_env = rpcplugin_config.get("PLUGIN_CLIENT_KEY")

    if cert_pem_from_env and key_pem_from_env:
        logger.info(f"Loading client certificate from environment variables.")
        logger.info(f"Loaded CLIENT_CERT: {cert_pem_from_env[:30]}...")
        logger.info(f"Loaded CLIENT_KEY: {key_pem_from_env[:30]}...")
        return Certificate(cert_pem_or_uri=cert_pem_from_env, key_pem_or_uri=key_pem_from_env)
    else:
        logger.info("Environment variables for client certificate not found. Generating new client certificate for fixture.")
        cert_obj = Certificate(generate_keypair=True, common_name="fixture_client_cert")
        logger.info(f"Generated fixture CLIENT_CERT: {cert_obj.cert[:30]}...")
        return cert_obj


@pytest.fixture(scope="module")
def server_cert():
    """Loads the server certificate from the environment variable or generates one."""
    from pyvider.rpcplugin.config import rpcplugin_config

    cert_pem_from_env = rpcplugin_config.get("PLUGIN_SERVER_CERT")
    key_pem_from_env = rpcplugin_config.get("PLUGIN_SERVER_KEY")

    if cert_pem_from_env and key_pem_from_env:
        logger.info(f"Loading server certificate from environment variables.")
        logger.info(f"Loaded SERVER_CERT: {cert_pem_from_env[:30]}...")
        logger.info(f"Loaded SERVER_KEY: {key_pem_from_env[:30]}...")
        return Certificate(cert_pem_or_uri=cert_pem_from_env, key_pem_or_uri=key_pem_from_env)
    else:
        logger.info("Environment variables for server certificate not found. Generating new server certificate for fixture.")
        cert_obj = Certificate(generate_keypair=True, common_name="fixture_server_cert")
        logger.info(f"Generated fixture SERVER_CERT: {cert_obj.cert[:30]}...")
        return cert_obj


@pytest.fixture(scope="module")
def valid_key_pem(client_cert):
    """Get a valid key PEM from the client cert fixture."""
    return client_cert.key


@pytest.fixture
def valid_cert_pem(client_cert):
    """Get a valid certificate PEM from the client cert fixture."""
    return client_cert.cert


@pytest.fixture
def invalid_key_pem() -> str:
    """Returns an invalid PEM certificate."""
    return "INVALID KEY DATA"


@pytest.fixture
def invalid_cert_pem() -> str:
    """Returns an invalid PEM certificate."""
    return "INVALID CERTIFICATE DATA"


@pytest.fixture
def malformed_cert_pem() -> str:
    """Returns a PEM certificate with incorrect headers."""
    return "-----BEGIN CERT-----\nMALFORMED DATA\n-----END CERT-----"


@pytest.fixture
def empty_cert() -> str:
    """Returns an empty certificate string."""
    return ""


@pytest.fixture
def temporary_cert_file(tmp_path, client_cert) -> str:
    """Creates a temporary file containing the client certificate."""
    cert_file = tmp_path / "client_cert.pem"
    cert_file.write_text(client_cert.cert)
    return f"file://{cert_file}"


@pytest.fixture
def temporary_key_file(tmp_path, client_cert) -> str:
    """Creates a temporary file containing the client private key."""
    key_file = tmp_path / "client_key.pem"
    key_file.write_text(client_cert.key)  # Write valid PEM key
    return f"file://{key_file}"


@pytest.fixture(scope="module")
def dev_root_ca() -> Certificate:
    """Generates a self-signed CA certificate for testing mTLS setups."""
    ca_cert = Certificate(
        common_name="Test Development CA", # Differentiate from other default certs
        generate_keypair=True,
        key_type="ecdsa" # Default is "ecdsa", explicit for clarity
        # No need for basic_constraints_ca or key_usage_extensions here,
        # as the Certificate class currently makes all generated certs CAs by default.
    )
    logger.info(f"Generated Development Root CA (common_name='Test Development CA'): {ca_cert.cert[:30]}...")
    return ca_cert


@pytest.fixture(scope="module")
def external_dev_ca_pem() -> str:
    """Provides a known-good, externally generated self-signed CA certificate PEM string."""
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
