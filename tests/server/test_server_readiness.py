import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

# Dummy protocol and handler for server instantiation
class DummyHandler:
    pass

class DummyProtocol(RPCPluginProtocol[MagicMock, DummyHandler]): # Use MagicMock for ServerT
    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, "dummy_service_name"

    async def add_to_server(self, server: MagicMock, handler: DummyHandler) -> None:
        pass

@pytest.mark.asyncio
async def test_wait_for_server_ready_unix_path_not_exists(mocker):
    mock_protocol = DummyProtocol()
    mock_handler = DummyHandler()

    # Setup mock UnixSocketTransport
    mock_unix_transport = AsyncMock(spec=UnixSocketTransport)
    mock_unix_transport.endpoint = "/tmp/test_unix.sock"
    mock_unix_transport.path = "/tmp/test_unix.sock" # Ensure path attribute is set

    server = RPCPluginServer(protocol=mock_protocol, handler=mock_handler, transport=mock_unix_transport)
    server._transport = mock_unix_transport # Explicitly assign to _transport as well

    # Simulate that the server's main serving event is set
    server._serving_event.set()

    # Mock os.path.exists to return False for the specific path
    mocker.patch("os.path.exists", return_value=False)

    with pytest.raises(TransportError, match=r"Unix socket file /tmp/test_unix.sock does not exist."):
        await server.wait_for_server_ready(timeout=0.1)

@pytest.mark.asyncio
async def test_wait_for_server_ready_tcp_port_none(mocker):
    mock_protocol = DummyProtocol()
    mock_handler = DummyHandler()

    mock_tcp_transport = AsyncMock(spec=TCPSocketTransport)
    mock_tcp_transport.endpoint = "127.0.0.1:12345" # Endpoint is set
    mock_tcp_transport.host = "127.0.0.1"
    # server._port will be None initially

    server = RPCPluginServer(protocol=mock_protocol, handler=mock_handler, transport=mock_tcp_transport)
    server._transport = mock_tcp_transport
    server._port = None # Explicitly ensure _port is None for this test case

    server._serving_event.set()

    with pytest.raises(TransportError, match="TCP port not available for readiness check."):
        await server.wait_for_server_ready(timeout=0.1)

@pytest.mark.asyncio
async def test_wait_for_server_ready_tcp_connect_fails(mocker):
    mock_protocol = DummyProtocol()
    mock_handler = DummyHandler()

    mock_tcp_transport = AsyncMock(spec=TCPSocketTransport)
    mock_tcp_transport.endpoint = "127.0.0.1:12345"
    mock_tcp_transport.host = "127.0.0.1"

    server = RPCPluginServer(protocol=mock_protocol, handler=mock_handler, transport=mock_tcp_transport)
    server._transport = mock_tcp_transport
    server._port = 12345 # Port is set
    server._serving_event.set()

    # Mock socket.socket().connect() to raise OSError
    mock_socket_instance = MagicMock()
    mock_socket_instance.connect = MagicMock(side_effect=OSError("Connection failed"))
    mock_socket_instance.close = MagicMock() # Ensure close is mockable
    mocker.patch("socket.socket", return_value=mock_socket_instance)

    with pytest.raises(TransportError, match="Server readiness check failed: Connection failed"):
        await server.wait_for_server_ready(timeout=0.1)
