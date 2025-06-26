#
#
# tests/test_transport_suite.py
#

import asyncio
import os
import socket
import stat  # Added
import tempfile
from pathlib import Path
import uuid

import pytest
import pytest_asyncio

from pyvider.telemetry import logger
from pyvider.rpcplugin.exception import TransportError

from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.base import (
    RPCPluginTransport as BaseTransportT,
)  # For factory return type

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.config import rpcplugin_config  # Added for config manipulation

from tests.fixtures.mocks import (
    MockProtocol,
    MockHandler,
)  # Assumes SocketStateMonitor, MockProtocol, MockHandler are here

# managed_transport context manager seems unused by current tests, can be reviewed later.


@pytest.fixture
def unused_tcp_port() -> int:
    """Find an unused TCP port."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def temp_sock_dir():
    """Create a temporary directory for Unix sockets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest_asyncio.fixture(scope="function")
async def transport_factory(request, tmp_path: Path):
    """Factory fixture for creating isolated transport instances."""
    created_transports = []

    async def create(transport_type: str, **kwargs) -> BaseTransportT:
        transport: BaseTransportT
        if transport_type == "unix":
            kwargs.pop("port", None)
            socket_path_from_kwargs = kwargs.pop("path", None)
            if socket_path_from_kwargs:
                socket_path_to_use = Path(socket_path_from_kwargs)
            else:
                short_name = f"pyv_tf_{uuid.uuid4().hex[:6]}.sock"
                socket_path_to_use = Path(tempfile.gettempdir()) / short_name
                if os.path.exists(socket_path_to_use):
                    try:
                        os.unlink(socket_path_to_use)
                    except OSError as e:
                        logger.warning(
                            f"transport_factory: Could not unlink pre-existing socket {socket_path_to_use}: {e}"
                        )
            transport = UnixSocketTransport(path=str(socket_path_to_use), **kwargs)
        else:  # TCP
            if "port" not in kwargs:
                kwargs.setdefault("port", 0)
            transport = TCPSocketTransport(**kwargs)

        created_transports.append(transport)
        return transport

    yield create

    for transport_instance in created_transports:
        try:
            await transport_instance.close()
            if (
                isinstance(transport_instance, UnixSocketTransport)
                and transport_instance.path
            ):
                if os.path.exists(transport_instance.path):
                    try:
                        os.chmod(transport_instance.path, 0o777)
                        os.unlink(transport_instance.path)
                    except OSError as e:
                        logger.warning(
                            f"transport_factory: Error unlinking socket {transport_instance.path}: {e}"
                        )
        except Exception as e:
            logger.error(
                f"Error during transport_factory cleanup of {transport_instance}: {e}"
            )


@pytest_asyncio.fixture
async def mock_protocol() -> MockProtocol:
    return MockProtocol()


@pytest_asyncio.fixture
async def mock_handler() -> MockHandler:
    return MockHandler()


@pytest_asyncio.fixture
async def server_factory(mock_protocol, mock_handler):
    servers = []

    async def create(transport: BaseTransportT, **kwargs) -> RPCPluginServer:
        assert transport is not None, "Transport must be provided to server factory"
        server = RPCPluginServer(
            protocol=mock_protocol,
            handler=mock_handler,
            transport=transport,
            **kwargs,  # type: ignore
        )
        servers.append(server)
        return server

    yield create
    for server in servers:
        try:
            await server.stop()
        except Exception as e:
            logger.error(f"Error stopping server: {e}")


@pytest_asyncio.fixture
async def connected_pair_factory(transport_factory, unused_tcp_port):
    pairs = []

    async def create(
        transport_type: str, tcp_port_for_server: int | None = None
    ) -> tuple[BaseTransportT, BaseTransportT]:
        server_kwargs: dict[str, Any] = ( # Type hint for server_kwargs
            {"port": tcp_port_for_server}
            if transport_type == "tcp" and tcp_port_for_server is not None
            else {}
        )
        client_kwargs: dict[str, Any] = {} # Type hint for client_kwargs

        server_transport = await transport_factory(transport_type, **server_kwargs)

        endpoint = await server_transport.listen()
        await asyncio.sleep(0.05)

        if transport_type == "tcp":
            client_kwargs.pop("port", None)
            client_transport = await transport_factory(transport_type, **client_kwargs)
        else:  # Unix
            client_transport = await transport_factory(transport_type, **client_kwargs)

        # If server is TCP and listen() picked a dynamic port, client needs to connect to that actual port.
        # The `endpoint` returned by `listen()` is the correct one to use.
        await client_transport.connect(endpoint)

        pair = (server_transport, client_transport)
        pairs.append(pair)
        return pair

    yield create
    for server, client in pairs:
        try:
            await client.close()
        except Exception:
            pass
        try:
            await server.close()
        except Exception:
            pass


################################################################################
# Consolidated tests
################################################################################


@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_server_lifecycle_and_connectivity(
    transport_type, transport_factory, server_factory, unused_tcp_port, mocker, monkeypatch # Added monkeypatch
):
    # Set the expected magic cookie in the environment for the server to validate
    monkeypatch.setenv(rpcplugin_config.get("PLUGIN_MAGIC_COOKIE_KEY"), rpcplugin_config.get("PLUGIN_MAGIC_COOKIE_VALUE"))

    # Configure for an insecure setup for both tcp and unix variants
    def mock_config_get_insecure(key, default=None):
        if key == "PLUGIN_AUTO_MTLS":
            return False
        if key == "PLUGIN_SERVER_CERT":
            return None
        return rpcplugin_config.config.get(key, default)

    mocker.patch.object(rpcplugin_config, "get", side_effect=mock_config_get_insecure)

    # Ensure the magic cookie environment variable is set for direct server instantiation
    cookie_key = rpcplugin_config.magic_cookie_key()
    cookie_value = rpcplugin_config.magic_cookie_value()
    monkeypatch.setenv(cookie_key, cookie_value)

    server_transport_kwargs = (
        {"port": unused_tcp_port} if transport_type == "tcp" else {}
    )
    server_transport = await transport_factory(
        transport_type, **server_transport_kwargs
    )

    rpc_server = await server_factory(transport=server_transport)

    original_client_cert_config = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
    rpcplugin_config.set("PLUGIN_CLIENT_CERT", None)

    actual_server_endpoint = None

    server_task = asyncio.create_task(rpc_server.serve())
    try:
        await asyncio.sleep(0.1)
        await asyncio.wait_for(rpc_server.wait_for_server_ready(), timeout=7.0)
        logger.info(f"Server reported ready for {transport_type}.")

        assert rpc_server._transport is not None, "Server's transport not initialized"
        actual_server_endpoint = rpc_server._transport.endpoint
        assert actual_server_endpoint is not None, (
            "Server transport endpoint not set after ready"
        )

        if transport_type == "unix":
            assert os.path.exists(actual_server_endpoint), (
                "Unix socket file does not exist"
            )
            assert stat.S_ISSOCK(os.stat(actual_server_endpoint).st_mode), (
                "Unix path is not a socket"
            )
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(actual_server_endpoint)
            sock.close()
        else:  # tcp
            host, port_str = actual_server_endpoint.split(":")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, int(port_str)))
            sock.close()
        logger.info(
            f"Transport endpoint {actual_server_endpoint} confirmed active for {transport_type}."
        )

    except Exception as e:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        pytest.fail(
            f"Server readiness or connectivity check failed for {transport_type}: {e}"
        )
    finally:
        rpcplugin_config.set("PLUGIN_CLIENT_CERT", original_client_cert_config)

    await rpc_server.stop()
    try:
        await asyncio.wait_for(server_task, timeout=5.0)
    except asyncio.TimeoutError:
        pytest.fail(f"Server task did not complete after stop() for {transport_type}")
    logger.info(f"Server serve task completed for {transport_type}.")

    if actual_server_endpoint:
        if transport_type == "unix":
            await asyncio.sleep(0.1)
            assert not os.path.exists(actual_server_endpoint), (
                f"Unix socket file {actual_server_endpoint} still exists after shutdown"
            )
        else:  # tcp
            host, port_str = actual_server_endpoint.split(":")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            with pytest.raises((ConnectionRefusedError, OSError)):
                sock.connect((host, int(port_str)))
            sock.close()
    logger.info(f"Server shutdown confirmed for {transport_type}.")


@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_connection_refused_consolidated(
    transport_type, transport_factory, unused_tcp_port
):
    kwargs = {"port": unused_tcp_port} if transport_type == "tcp" else {}
    transport_config_for_client = await transport_factory(transport_type, **kwargs)

    endpoint_to_test: str | None
    if transport_type == "unix":
        assert isinstance(transport_config_for_client, UnixSocketTransport)
        endpoint_to_test = f"unix:{transport_config_for_client.path}"
    else:
        assert isinstance(transport_config_for_client, TCPSocketTransport)
        host = (
            transport_config_for_client.host
            if transport_config_for_client.host
            else "127.0.0.1"
        )
        port = transport_config_for_client.port
        if (
            port is None or port == 0
        ):  # If port is 0, factory might make it 0, then OS picks. For client to connect, it needs a real port.
            port = unused_tcp_port  # Fallback to ensure we have a port for constructing endpoint string
        endpoint_to_test = f"{host}:{port}"

    # For Unix, ensure the specific path does not exist for this test.
    if (
        transport_type == "unix"
        and transport_config_for_client.path
        and os.path.exists(transport_config_for_client.path)
    ):  # type: ignore
        os.unlink(transport_config_for_client.path)  # type: ignore

    await transport_config_for_client.close()

    client_kwargs = (
        {"port": unused_tcp_port} if transport_type == "tcp" else {}
    )  # Ensure client factory uses a different port if it were to listen
    client = await transport_factory(transport_type, **client_kwargs)
    try:
        with pytest.raises(TransportError):
            await client.connect(endpoint_to_test)
    finally:
        await client.close()


# long-running
@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_transport_error_scenarios_consolidated(
    transport_type, transport_factory, unused_tcp_port
):
    if transport_type == "tcp":
        invalid_transport_tcp = await transport_factory("tcp", port=unused_tcp_port)
        with pytest.raises(TransportError, match="Invalid TCP endpoint format"):
            await invalid_transport_tcp.connect("invalid:endpoint:format")
        await invalid_transport_tcp.close()

    connect_kwargs = {"port": unused_tcp_port} if transport_type == "tcp" else {}
    connect_transport = await transport_factory(transport_type, **connect_kwargs)
    try:
        if transport_type == "unix":
            non_existent_unix_path = (
                Path(tempfile.gettempdir()) / f"pyv_ne_{uuid.uuid4().hex[:6]}.sock"
            )
            if os.path.exists(non_existent_unix_path):
                os.unlink(non_existent_unix_path)
            with pytest.raises(
                TransportError,
                match="Socket .* does not exist|No such file or directory",
            ):
                await connect_transport.connect(str(non_existent_unix_path))
        else:  # tcp
            with pytest.raises(
                TransportError,
                match="timed out|timeout|Network is unreachable|Connection refused",
            ):
                await connect_transport.connect("240.0.0.1:12345")
    finally:
        await connect_transport.close()

    if transport_type == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"this is not a socket")
            tf.flush()
            non_socket_path = tf.name

        transport_nonsocket = await transport_factory("unix")
        try:
            with pytest.raises(TransportError, match="is not a socket"):
                await transport_nonsocket.connect(non_socket_path)
        finally:
            await transport_nonsocket.close()
            os.unlink(non_socket_path)

    # Test 4: Listen on already-in-use endpoint
    if (
        transport_type == "unix"
    ):  # This test is primarily valid for Unix with current listen() behavior
        server1_kwargs = {}
        server1 = await transport_factory(transport_type, **server1_kwargs)
        actual_endpoint = await server1.listen()

        server2_init_kwargs = {"path": actual_endpoint}
        server2 = await transport_factory(transport_type, **server2_init_kwargs)
        try:
            with pytest.raises(
                TransportError,
                match=r"already in use|Failed to create|Failed to bind|Socket .* is already running|Address already in use",
            ):
                await server2.listen()
        finally:
            await server1.close()
            await server2.close()
    elif transport_type == "tcp":
        logger.info(
            "Skipping 'Listen on already-in-use endpoint' for TCP as listen() behavior changed for gRPC."
        )
        # This test for TCP would require two RPCPluginServer instances attempting to use the same port.
        # TCPSocketTransport.listen() by itself no longer errors on "already in use"
        # because it doesn't try to acquire the port if it's only determining an endpoint string.
        pass


### 🐍🏗🧪️
