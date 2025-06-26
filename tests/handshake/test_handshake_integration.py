# tests/handshake/test_handshake_integration.py

import asyncio
import io
import sys
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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


# Helper contexts to capture stdout/stderr
@contextmanager
def capture_stdout():
    """Context manager to capture stdout."""
    original_stdout = sys.stdout
    buffer = io.StringIO()
    sys.stdout = buffer
    try:
        yield buffer
    finally:
        sys.stdout = original_stdout


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
    setup_environment, mock_protocol, mock_handler, managed_unix_socket_path, mocker
):
    """Test integration of handshake with the server."""

    # Ensure the server runs in insecure mode for this test's original intent
    # (checking handshake output, not TLS setup).
    def mock_config_get(key, default=None):
        if key == "PLUGIN_AUTO_MTLS":
            return False
        if key == "PLUGIN_SERVER_CERT":
            return None
        if key == "PLUGIN_SERVER_KEY":
            return None
        # Values set by setup_environment fixture
        if key == "PLUGIN_MAGIC_COOKIE_KEY":
            return "PLUGIN_MAGIC_COOKIE" # As set by setup_environment
        if key == "PLUGIN_MAGIC_COOKIE_VALUE":
            return "test_cookie_value" # As set by setup_environment

        # For other keys, return their actual values from the global config
        # This ensures values set by setup_environment are respected.
        return rpcplugin_config.config.get(key, default)

    mocker.patch.object(rpcplugin_config, "get", side_effect=mock_config_get)

    # Patch sys.stdout to capture handshake output
    with (
        patch("sys.stdout.buffer.write") as mock_write,
        patch("sys.stdout.buffer.flush"),
        patch("pyvider.rpcplugin.server.GRPCServer") as mock_grpc_server,
    ):
        # Setup mocks
        mock_server = MagicMock()
        mock_server.add_insecure_port.return_value = 8080
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_server.wait_closed = AsyncMock()
        mock_grpc_server.return_value = mock_server

        # Create server with Unix transport
        socket_path = managed_unix_socket_path
        transport = UnixSocketTransport(path=socket_path)

        server = RPCPluginServer(
            protocol=mock_protocol, handler=mock_handler, transport=transport
        )

        # Start the server in a task that we'll cancel
        server_task = asyncio.create_task(server.serve())

        try:
            # Wait for the server to be ready
            await asyncio.wait_for(server._serving_event.wait(), timeout=5)

            # Verify handshake output was written to stdout
            assert mock_write.called

            # Get the handshake data
            handshake_data = mock_write.call_args[0][0].decode("utf-8").strip()
            assert "|" in handshake_data

            # Parse the handshake
            parts = handshake_data.split("|")
            assert len(parts) == 6
            assert parts[0] == "1"  # Core version
            assert int(parts[1]) in range(1, 8)  # Protocol version
            assert parts[2] in ["unix", "tcp"]  # Transport
            assert parts[4] == "grpc"  # Protocol

        finally:
            # Clean up
            server_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await server_task
            await server.stop()


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
