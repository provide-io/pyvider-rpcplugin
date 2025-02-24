
# pyvider/rpcplugin/tests/test_certificate_mtls.py

import os
import pytest
import pytest_asyncio

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import CertificateError

from pyvider.rpcplugin.tests.fixtures import *

@pytest.mark.asyncio
async def test_load_client_certificate(client_cert):
    """Ensure the client certificate loads correctly."""
    assert client_cert.subject, "Client certificate subject should not be empty"
    assert client_cert.issuer, "Client certificate issuer should not be empty"
@pytest.mark.asyncio
async def test_load_server_certificate(server_cert):
    """Ensure the server certificate loads correctly."""
    assert server_cert.subject, "Server certificate subject should not be empty"
    assert server_cert.issuer, "Server certificate issuer should not be empty"

@pytest.mark.asyncio
async def test_mutual_tls_verification(client_cert, server_cert):
    """Ensure the client and server certificates can be used for mutual TLS."""
    assert client_cert.public_key, "Client certificate should have a valid public key"
    assert server_cert.public_key, "Server certificate should have a valid public key"
    assert client_cert.issuer == server_cert.subject or server_cert.issuer == client_cert.subject, (
        "mTLS requires mutual recognition between certificates"
    )
