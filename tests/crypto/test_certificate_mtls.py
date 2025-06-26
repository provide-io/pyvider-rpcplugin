# pyvider/rpcplugin/tests/test_certificate_mtls.py

import pytest


# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.crypto import client_cert, server_cert


@pytest.mark.asyncio
async def test_load_client_certificate(client_cert) -> None:
    """Ensure the client certificate loads correctly."""
    assert client_cert.subject, "Client certificate subject should not be empty"
    assert client_cert.issuer, "Client certificate issuer should not be empty"


@pytest.mark.asyncio
async def test_load_server_certificate(server_cert) -> None:
    """Ensure the server certificate loads correctly."""
    assert server_cert.subject, "Server certificate subject should not be empty"
    assert server_cert.issuer, "Server certificate issuer should not be empty"
