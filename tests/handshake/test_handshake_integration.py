# tests/handshake/test_handshake_integration.py

import asyncio
import io
import sys
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import grpc # <--- ADD THIS IMPORT

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.handshake import (
    build_handshake_response,
    parse_handshake_response,
)
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)


class MockProtocol:
    """Create an actual protocol implementation for server tests."""

    async def add_to_server(self, handler, server):
        """Mock implementation of add_to_server."""
        pass

    def get_grpc_descriptors(self):
        """Mock implementation of get_grpc_descriptors."""
        return None, "MockService"


@pytest.fixture
def mock_protocol():
    """Create a mock protocol for server tests."""
    return MockProtocol()


@pytest.fixture
def mock_handler():
    """Create a mock handler for server tests."""
    handler = MagicMock()
    return handler


@pytest.fixture
def setup_environment(monkeypatch):
    """Set up environment variables for handshake tests."""
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE", "test_cookie_value")
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_VALUE", "test_cookie_value")
    monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "1,2,3,4,5,6,7")
    monkeypatch.setenv("PLUGIN_SERVER_TRANSPORTS", "tcp,unix")

    # Clear config to force reload from environment
    rpcplugin_config._instance = None


@pytest.mark.asyncio
async def test_build_handshake_response_unix(monkeypatch):
    """Test building handshake response with Unix transport."""
    transport = UnixSocketTransport()
    transport.listen = AsyncMock(return_value="/tmp/test.sock")
    transport.endpoint = "/tmp/test.sock"

    response = await build_handshake_response(
        plugin_version=6, transport_name="unix", transport=transport, server_cert=None
    )

    # Verify expected format
    parts = response.split("|")
    assert len(parts) == 6
    assert parts[0] == "1"  # Core version
    assert parts[1] == "6"  # Plugin version
    assert parts[2] == "unix"  # Transport name
    assert parts[3] == "/tmp/test.sock"  # Endpoint
    assert parts[4] == "grpc"  # Protocol
    assert parts[5] == ""  # No certificate

    # Clean up
    await transport.close()


@pytest.mark.asyncio
async def test_build_handshake_response_with_certificate():
    """Test building handshake response with a certificate."""
    transport = TCPSocketTransport()

    # Create a simple certificate
    cert = Certificate(generate_keypair=True)

    response = await build_handshake_response(
        plugin_version=7,
        transport_name="tcp",
        transport=transport,
        server_cert=cert,
        port=12345,
    )

    # Verify expected format
    parts = response.split("|")
    assert len(parts) == 6
    assert parts[0] == "1"  # Core version
    assert parts[1] == "7"  # Plugin version
    assert parts[2] == "tcp"  # Transport name
    assert parts[3] == "127.0.0.1:12345"  # Endpoint
    assert parts[4] == "grpc"  # Protocol
    assert parts[5] != ""  # Certificate data

    # Clean up
    await transport.close()


@pytest.mark.asyncio
async def test_full_handshake_cycle():
    """Test a complete handshake cycle with building and parsing."""
    transport = TCPSocketTransport()

    # Build the response
    response = await build_handshake_response(
        plugin_version=6,
        transport_name="tcp",
        transport=transport,
        server_cert=None,
        port=8080,
    )

    # Parse the response
    core_version, plugin_version, network, address, protocol, cert = (
        parse_handshake_response(response)
    )

    # Verify parsed values match
    assert core_version == 1
    assert plugin_version == 6
    assert network == "tcp"
    assert address == "127.0.0.1:8080"
    assert protocol == "grpc"
    assert cert is None

    # Clean up
    await transport.close()


@pytest.mark.asyncio
async def test_server_handshake_integration(
    setup_environment, rpc_plugin_server_manager, mocker, mock_protocol, mock_handler
):
    """Test integration of handshake with the server using rpc_plugin_server_manager."""

    # Configuration for the server via rpc_plugin_server_manager
    # Ensure PLUGIN_AUTO_MTLS is false for this test's original intent.
    # The setup_environment fixture already sets magic cookie and other relevant env vars
    # which rpc_plugin_config (used by the server manager) will pick up.
    config_overrides = {
        "PLUGIN_AUTO_MTLS": "false", # Explicitly ensure mTLS is off
        "PLUGIN_SERVER_CERT": None,
        "PLUGIN_SERVER_KEY": None,
        # Other configs like magic cookie key/value are set by setup_environment
        # and will be used by the server created by rpc_plugin_server_manager.
    }

    # Patch sys.stdout to capture handshake output
    with patch("sys.stdout.buffer.write") as mock_write, \
         patch("sys.stdout.buffer.flush"), \
         patch("pyvider.rpcplugin.server.GRPCServer") as mock_grpc_server: # Keep GRPCServer mock if it's for deeper control

        # Setup mocks for internal GRPCServer behavior if needed by the test logic
        # that rpc_plugin_server_manager doesn't abstract away.
        # For this test, the core is that server.serve() is called and it prints to stdout.
        mock_internal_grpc_server = MagicMock(spec=grpc.aio.Server) # Use spec for type safety
        mock_internal_grpc_server.add_insecure_port.return_value = 8080 # Example port
        mock_internal_grpc_server.start = AsyncMock()
        mock_internal_grpc_server.stop = AsyncMock()
        mock_internal_grpc_server.wait_closed = AsyncMock()
        mock_grpc_server.return_value = mock_internal_grpc_server


        # Use the rpc_plugin_server_manager to create and start the server.
        # The manager handles transport creation (defaulting to unix).
        # It also runs server.serve() in a background task and waits for readiness.
        # The 'protocol' and 'handler' will be the default mocks from fixtures,
        # which is what the original test used.
        server, endpoint = await rpc_plugin_server_manager(
            config_overrides=config_overrides,
            protocol=mock_protocol, # Pass the fixture explicitly
            handler=mock_handler,   # Pass the fixture explicitly
            transport_type="unix",   # Explicitly use unix as in original test logic
            auto_start=True # The manager will start it and wait for ready
        )

        # server.serve() is already running in a background task managed by rpc_plugin_server_manager.
        # The manager also ensures server.stop() is called on cleanup.

        # Verify handshake output was written to stdout
        # This assertion needs to happen *after* rpc_plugin_server_manager has started the server
        # and server.serve() has printed the handshake. The auto_start=True and waiting for
        # readiness within the manager should ensure this.
        assert mock_write.called

        # Get the handshake data
        handshake_data = mock_write.call_args[0][0].decode("utf-8").strip()
        assert "|" in handshake_data

        # Parse the handshake
        parts = handshake_data.split("|")
        assert len(parts) == 6
        assert parts[0] == "1"  # Core version
        assert int(parts[1]) in range(1, 8)  # Protocol version, check against configured/negotiated
        assert parts[2] == "unix" # Since we requested unix
        assert parts[3] == endpoint # Endpoint from the manager should match
        assert parts[4] == "grpc"  # Protocol
        # No cert expected as PLUGIN_AUTO_MTLS is false
        assert not parts[5] if len(parts) > 5 and parts[5] else True


@pytest.mark.asyncio
async def test_certificate_handling_in_handshake():
    """Test proper certificate handling in handshake."""
    # Generate a test certificate
    cert = Certificate(generate_keypair=True)

    # Build handshake with certificate
    transport = TCPSocketTransport()
    response = await build_handshake_response(
        plugin_version=7,
        transport_name="tcp",
        transport=transport,
        server_cert=cert,
        port=8080,
    )

    # Parse the response
    core_version, plugin_version, network, address, protocol, parsed_cert = (
        parse_handshake_response(response)
    )

    # Verify certificate was properly handled
    assert parsed_cert is not None

    # The parsed cert should be a base64-encoded string without PEM headers
    # and should match what we'd get from the original certificate
    cert_lines = cert.cert.strip().split("\n")
    expected_cert_base = "".join(cert_lines[1:-1]).rstrip("=")

    # The cert might have padding added during parsing
    assert parsed_cert.rstrip("=") == expected_cert_base

    # Clean up
    await transport.close()


### 🐍🏗🧪️
