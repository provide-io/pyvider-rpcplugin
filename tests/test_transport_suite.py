# tests/transport/test_transport_suite.py
#!/usr/bin/env python3
# tests/test_transport_suite.py

import asyncio
import os
import socket
import tempfile
from typing import Tuple, AsyncGenerator

import pytest
import pytest_asyncio

from pyvider.telemetry import logger
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.types import TransportT

# tests/transport/test_transport_suite.py - Replace SocketStateMonitor class entirely

class SocketStateMonitor:
    """Utility for monitoring socket state."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._active = False
        self._connections = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def path(self) -> str:
        return self._path

    @property
    def connections(self) -> int:
        return self._connections

    async def check_state(self) -> bool:
        """Check current socket state with retries."""
        for attempt in range(3):  # Retry up to 3 times
            async with self._lock:
                try:
                    if not os.path.exists(self._path):
                        self._active = False
                        return False

                    # Check if it's a valid socket file
                    try:
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect(self._path)
                        self._active = True
                        self._connections += 1
                        sock.close()
                        return True
                    except (ConnectionRefusedError, FileNotFoundError):
                        # Socket exists but nothing listening
                        if attempt < 2:  # Only sleep if we have more retries
                            await asyncio.sleep(0.2)  # Wait for socket to be ready
                            continue
                        self._active = False
                        return False
                    except OSError:
                        self._active = False
                        return False
                    finally:
                        try:
                            sock.close()
                        except (NameError, UnboundLocalError):
                            pass
                except Exception as e:
                    logger.error(f"Socket state check error: {e}")

            # Sleep between retries
            if attempt < 2:
                await asyncio.sleep(0.2)

        self._active = False
        return False

    async def wait_for_active(self, timeout: float = 3.0) -> bool:
        """Wait for socket to become active with regular checks."""
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if await self.check_state():
                return True
            await asyncio.sleep(0.1)
        return False

    async def cleanup(self) -> None:
        """Attempt to remove the socket file."""
        async with self._lock:
            if os.path.exists(self._path):
                try:
                    os.unlink(self._path)
                    logger.info(f"Cleaned up socket: {self._path}")
                except OSError as e:
                    logger.error(f"Error cleaning up socket {self._path}: {e}")


@pytest_asyncio.fixture(params=["tcp", "unix"])
async def transport_factory(request) -> AsyncGenerator[Tuple[str, TransportT], None]:
    """Fixture to provide transport factories for TCP and Unix sockets."""
    if request.param == "tcp":
        yield "tcp", TCPSocketTransport
    elif request.param == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        monitor = SocketStateMonitor(socket_path)
        yield "unix", lambda **kwargs: UnixSocketTransport(path=socket_path, **kwargs)
        await monitor.cleanup()
    else:
        raise ValueError(f"Unknown transport type: {request.param}")


@pytest_asyncio.fixture
async def server_transport(transport_factory, unused_tcp_port) -> TransportT:
    """Fixture to create a server transport instance."""
    transport_type, factory = transport_factory
    if transport_type == "tcp":
        return await factory(host="127.0.0.1", port=unused_tcp_port)
    elif transport_type == "unix":
        # Use a new temporary file for each test to avoid conflicts
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        transport = factory(path=socket_path)
        yield transport
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    else:
        raise ValueError(f"Unknown transport type: {transport_type}")


@pytest_asyncio.fixture
async def client_transport(transport_factory, unused_tcp_port) -> TransportT:
    """Fixture to create a client transport instance."""
    transport_type, factory = transport_factory
    if transport_type == "tcp":
        return factory(host="127.0.0.1", port=unused_tcp_port)
    elif transport_type == "unix":
        # Client transport for Unix socket doesn't need to create the file
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        yield factory(path=socket_path)
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    else:
        raise ValueError(f"Unknown transport type: {transport_type}")


@pytest_asyncio.fixture
async def protocol() -> RPCPluginProtocol:
    """Fixture to create an RPCPluginProtocol instance."""
    return RPCPluginProtocol()


@pytest_asyncio.fixture
async def server(server_transport, protocol) -> RPCPluginServer:
    """Fixture to create an RPCPluginServer instance."""
    server = RPCPluginServer(transport=server_transport, protocol=protocol)
    yield server
    await server.close()


@pytest_asyncio.fixture
async def client(client_transport, protocol) -> RPCPluginProtocol:
    """Fixture to create an RPCPluginProtocol instance for the client."""
    await client_transport.connect()
    yield protocol
    await client_transport.close()


@pytest.mark.asyncio
async def test_server_with_transport(server, server_transport):
    """Test that the server starts and can be closed with different transports."""
    assert not server.is_serving()
    await server.serve()
    assert server.is_serving()
    await server.close()
    assert not server.is_serving()


@pytest.mark.asyncio
async def test_unix_socket_error_handling(transport_factory):
    """Test Unix socket error handling for connection refused."""
    transport_type, factory = transport_factory
    if transport_type == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        transport = factory(path=socket_path)
        with pytest.raises(TransportError):
            await transport.connect()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    else:
        pytest.skip("Test only applicable to Unix sockets")


@pytest.mark.asyncio
@pytest.mark.parametrize("num_connections", [1, 2, 3, 4])
async def test_unix_socket_concurrent_connections(transport_factory, num_connections):
    """Test concurrent connections to a Unix socket server."""
    transport_type, factory = transport_factory
    if transport_type == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        monitor = SocketStateMonitor(socket_path)
        server_transport = factory(path=socket_path)
        server_protocol = RPCPluginProtocol()
        server = RPCPluginServer(transport=server_transport, protocol=server_protocol)
        await server.serve()
        assert await monitor.wait_for_active(timeout=1.0)

        client_transports = [factory(path=socket_path) for _ in range(num_connections)]
        clients = [RPCPluginProtocol() for _ in range(num_connections)]
        connect_tasks = [client_transports[i].connect() for i in range(num_connections)]
        await asyncio.gather(*connect_tasks)
        assert monitor.connections >= num_connections

        disconnect_tasks = [client_transports[i].close() for i in range(num_connections)]
        await asyncio.gather(*disconnect_tasks)
        await server.close()
        await monitor.cleanup()
    else:
        pytest.skip("Test only applicable to Unix sockets")


@pytest.mark.asyncio
@pytest.mark.parametrize("test_case", [1, 2])
async def test_unix_socket_server_integration(transport_factory, test_case):
    """Test basic server integration with Unix sockets."""
    transport_type, factory = transport_factory
    if transport_type == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        monitor = SocketStateMonitor(socket_path)
        server_transport = factory(path=socket_path)
        server_protocol = RPCPluginProtocol()
        server = RPCPluginServer(transport=server_transport, protocol=server_protocol)
        await server.serve()
        assert await monitor.wait_for_active(timeout=1.0)

        client_transport = factory(path=socket_path)
        client_protocol = RPCPluginProtocol()
        await client_transport.connect()

        if test_case == 1:
            # Send and receive a simple message (implementation details might vary)
            pass
        elif test_case == 2:
            # Simulate a more complex interaction
            pass

        await client_transport.close()
        await server.close()
        await monitor.cleanup()
    else:
        pytest.skip("Test only applicable to Unix sockets")


@pytest.mark.asyncio
async def test_unix_socket_lifecycle_1(transport_factory):
    """Test Unix socket server lifecycle."""
    transport_type, factory = transport_factory
    if transport_type == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            socket_path = tmp_file.name
        monitor = SocketStateMonitor(socket_path)
        server_transport = factory(path=socket_path)
        server_protocol = RPCPluginProtocol()
        server = RPCPluginServer(transport=server_transport, protocol=server_protocol)
        await server.serve()
        assert await monitor.wait_for_active(timeout=1.0)
        await server.close()
        assert not await monitor.check_state()
        await monitor.cleanup()
    else:
        pytest.skip("Test only applicable to Unix sockets")
