# pyvider/rpcplugin/tests/transport/tcp/test_transport_tcp_connect.py

import asyncio
import socket # Added import

import pytest

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import TCPSocketTransport

from unittest.mock import MagicMock, AsyncMock # Added AsyncMock


@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_unreachable_address() -> None:
    unreachable = "192.0.2.254:80"
    transport = TCPSocketTransport(host=unreachable)

    with pytest.raises(TransportError):
        await asyncio.wait_for(transport.listen(), timeout=3.0)


@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_invalid_endpoint() -> None:
    """
    Test connecting to an invalid endpoint with TCPSocketTransport.
    """
    transport = TCPSocketTransport()
    await transport.listen()

    # Use a valid format but an unlikely to be used port
    with pytest.raises(TransportError):
        # Include a timeout to prevent indefinite hanging
        await asyncio.wait_for(transport.connect("127.0.0.1:65530"), timeout=6.0)


@pytest.mark.asyncio
async def test_tcp_socket_transport_default_host() -> None:
    """
    Test that TCPSocketTransport uses the default host when none is provided.
    """
    transport = TCPSocketTransport()
    assert transport.host == "127.0.0.1"


@pytest.mark.asyncio
async def test_listen_already_running_no_endpoint():
    """Test listen() when _running is True but endpoint is None."""
    transport = TCPSocketTransport()
    transport._running = True
    transport.endpoint = None
    with pytest.raises(
        TransportError,
        match="TCP transport is already configured with an endpoint but it's None.",
    ):
        await transport.listen()


@pytest.mark.asyncio
async def test_listen_specific_port():
    """Test listen() when a specific port is provided."""
    specific_port = 55555
    # Ensure port is likely free, or test might be flaky
    # For robustness, could try to bind to it first to check
    transport = TCPSocketTransport(host="127.0.0.1", port=specific_port)
    endpoint = await transport.listen()
    assert endpoint == f"127.0.0.1:{specific_port}"
    assert transport.port == specific_port
    # Clean up by closing, though listen doesn't hold the port open itself anymore
    await transport.close()


@pytest.mark.asyncio
async def test_listen_ephemeral_port_os_error(mocker):
    """Test listen() when OS fails to bind an ephemeral port."""
    transport = TCPSocketTransport(host="127.0.0.1", port=0)

    # Mock socket operations to simulate failure in finding an ephemeral port
    mock_socket_instance = MagicMock()
    mock_socket_instance.bind = MagicMock(side_effect=OSError("All ports in use"))
    mock_socket_instance.close = MagicMock()

    # When socket.socket() is called, return our mock instance
    mocker.patch("socket.socket", return_value=mock_socket_instance)

    with pytest.raises(TransportError, match="Failed to find an ephemeral port"):
        await transport.listen()


@pytest.mark.asyncio
async def test_connect_malformed_endpoint_extra_parts():
    """Test connect() with a malformed endpoint (too many colons)."""
    transport = TCPSocketTransport()
    with pytest.raises(
        TransportError, match="Invalid TCP endpoint format: host:port:123"
    ):
        await transport.connect("host:port:123")


@pytest.mark.asyncio
async def test_connect_unresolvable_hostname():
    """Test connect() to an unresolvable hostname."""
    transport = TCPSocketTransport()
    hostname = "unlikely-to-resolve-hostname-for-pyvider-testing.local"
    with pytest.raises(
        TransportError, match=f"Address resolution failed for {hostname}:12345"
    ):
        await transport.connect(f"{hostname}:12345")


@pytest.mark.asyncio
async def test_connect_successful():
    """Test successful connect() to a dummy asyncio server."""
    server_host = "127.0.0.1"
    server_port = 0  # Let OS pick a port for the dummy server

    async def handle_echo(reader, writer):
        writer.close()

    server = await asyncio.start_server(handle_echo, server_host, server_port)
    actual_port = server.sockets[0].getsockname()[1]

    transport = TCPSocketTransport()
    try:
        await transport.connect(f"{server_host}:{actual_port}")
        assert transport._reader is not None
        assert transport._writer is not None
        assert transport.endpoint == f"{server_host}:{actual_port}"
    finally:
        await transport.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_connect_generic_exception_open_connection(mocker):
    """Test connect() when asyncio.open_connection raises a generic Exception."""
    transport = TCPSocketTransport()
    # Mock asyncio.open_connection to raise a generic RuntimeError
    mocker.patch(
        "asyncio.open_connection",
        side_effect=RuntimeError("Simulated open_connection error"),
    )

    with pytest.raises(
        TransportError,
        match="Failed to connect to TCP endpoint 127.0.0.1:12345: Simulated open_connection error",
    ):
        await transport.connect("127.0.0.1:12345")


@pytest.mark.asyncio
async def test_listen_already_running_and_endpoint_set(mocker):
    transport = TCPSocketTransport(host="127.0.0.1", port=12345)
    transport._running = True
    transport.endpoint = "127.0.0.1:12345"

    # Mock the lock to avoid actual locking in this specific test path
    mocker.patch.object(transport, '_lock', AsyncMock(spec=asyncio.Lock))

    # Spy on socket creation to ensure it's not called
    socket_spy = mocker.spy(socket, "socket")

    # Call listen again
    endpoint = await transport.listen()
    assert endpoint == "127.0.0.1:12345"
    socket_spy.assert_not_called() # Ensure no new socket was created
    await transport.close() # Clean up transport

### 🐍🏗🧪️
