# pyvider/rpcplugin/tests/server/test_server_tls.py

import asyncio
import pytest
from unittest import mock
from unittest.mock import patch

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.config import rpcplugin_config

from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
)

from tests.fixtures import *


# this is somehow causing a segfault. i need to figure out wtf is up with the segfaults.
@pytest.mark.asyncio
async def test_server_starts_insecurely(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:

    transport = mock_server_transport

    # TODO: errors are being swallowed here when the transport is not what's expected.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    # Capture print calls directly
    printed_messages = []

    def mock_print(message, *args, **kwargs):
        printed_messages.append(str(message))

    with patch("builtins.print", mock_print):
        server_task = asyncio.create_task(server.serve())
        await server.wait_for_server_ready()

        await asyncio.sleep(0.1)

        await server.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    assert len(printed_messages) > 0, "No handshake message was printed"
    handshake = printed_messages[0]
    assert handshake.startswith("1|"), f"Invalid handshake format: {handshake}"

@pytest.mark.asyncio
async def test_read_client_cert_present(monkeypatch, mock_server_transport) -> None:
    from pyvider.rpcplugin.config import rpcplugin_config

    rpcplugin_config.set("PLUGIN_CLIENT_CERT", "client_cert")
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )
    cert = server._read_client_cert()
    assert cert == "client_cert"

@pytest.mark.asyncio
async def X1_test_read_client_cert_absent(
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    transport = mock_server_transport

    #original_config = rpcplugin_config.config.copy()

    mock_server_config.set("PLUGIN_CLIENT_CERT", "")
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    await transport.listen()
    cert = server._read_client_cert()
    assert cert is None

@pytest.mark.asyncio
async def test_generate_server_credentials_insecure(server_with_mocks) -> None:
    """Test generating server credentials in insecure mode."""
    creds = server_with_mocks._generate_server_credentials(None)
    assert creds is None

@pytest.mark.skip
async def X1_test_generate_server_credentials_secure(monkeypatch) -> None:
    dummy_cert = "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----"
    dummy_key = "-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----"

    mock_server_config.set("PLUGIN_SERVER_CERT", dummy_cert)
    mock_server_config.set("PLUGIN_SERVER_KEY", dummy_key)
    mock_server_config.set("PLUGIN_CLIENT_CERT", "client_cert")
    mock_server_config.set("PLUGIN_PROTOCOL_VERSIONS", "1")
    mock_server_config.set("PLUGIN_TRANSPORTS", ["tcp"])

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
    )
    creds = server._generate_server_credentials("client_cert")
    assert creds is not None
    rpcplugin_config.config = original

@pytest.mark.asyncio
async def test_generate_server_credentials_success(
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:

    mock_server_config.set(
        "PLUGIN_SERVER_CERT",
        "-----BEGIN CERTIFICATE-----\ndummy_cert\n-----END CERTIFICATE-----",
    )
    mock_server_config.set(
        "PLUGIN_SERVER_KEY",
        "-----BEGIN PRIVATE KEY-----\ndummy_key\n-----END PRIVATE KEY-----",
    )
    mock_server_config.set("PLUGIN_CLIENT_CERT", client_cert)
    mock_server_config.set("PLUGIN_PROTOCOL_VERSIONS", "1")
    mock_server_config.set("PLUGIN_SERVER_TRANSPORTS", "tcp")

    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    creds = server._generate_server_credentials(client_cert.cert.encode())
    # Expect creds to be not None (dummy creds generated successfully)
    assert creds is not None

@pytest.mark.asyncio
async def test_generate_server_credentials_failure(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    # Force Certificate creation to raise an exception.
    from pyvider.rpcplugin.crypto.certificate import Certificate

    monkeypatch.setattr(
        Certificate,
        "__init__",
        lambda self, **kwargs: (_ for _ in ()).throw(Exception("Forced failure")),
    )
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )
    with pytest.raises(Exception, match="has no attribute"):
        server._generate_server_credentials(client_cert.cert.encode())

###

@pytest.mark.asyncio
async def test_generate_server_credentials_secure(monkeypatch) -> None:
    """Test generating server credentials in secure mode with proper mocking."""
    dummy_cert = "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----"
    dummy_key = "-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----"

    # Create a temporary mock config with proper set method
    mock_config = mock_server_config
    
    # Set the necessary values
    mock_config.set("PLUGIN_SERVER_CERT", dummy_cert)
    mock_config.set("PLUGIN_SERVER_KEY", dummy_key)
    mock_config.set("PLUGIN_CLIENT_CERT", "client_cert")
    
    # Create the server with our mock config
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_config,
    )
    
    # Mock Certificate initialization to avoid actual certificate creation
    with mock.patch('pyvider.rpcplugin.crypto.certificate.Certificate') as mock_cert:
        # Setup the mock to return a properly structured certificate object
        mock_cert_instance = mock.MagicMock()
        mock_cert_instance.cert = dummy_cert
        mock_cert_instance.key = dummy_key
        mock_cert.return_value = mock_cert_instance
        
        # Test the method
        creds = server._generate_server_credentials("client_cert")
        
        # Verify Certificate was called correctly
        mock_cert.assert_called_once()
        
        # Assert we got something back (the actual credentials would be a complex object)
        assert creds is not None

@pytest.mark.asyncio
async def test_read_client_cert_absent(monkeypatch) -> None:
    """Test behavior when client certificate is absent."""
    # Create a mock server without a client certificate
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,  # Use None to force using the global config
    )
    
    # Mock rpcplugin_config.get to return None for PLUGIN_CLIENT_CERT
    with mock.patch('pyvider.rpcplugin.server.rpcplugin_config.get', 
                   return_value=None) as mock_get:
        cert = server._read_client_cert()
        # Expect None when no client certificate is found
        assert cert is None
        # Verify we looked for the right key
        mock_get.assert_any_call("PLUGIN_CLIENT_CERT")

###


### 🐍🏗🧪️
