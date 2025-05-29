# tests/fixtures/server.py

import pytest
import pytest_asyncio

import asyncio


from pyvider.rpcplugin.server import RPCPluginServer




@pytest.fixture
def valid_server_env(monkeypatch) -> None:
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    monkeypatch.setenv(
        "PLUGIN_MAGIC_COOKIE",
        "hello",
    )
    monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "1,2,3,4,5,6,7")
    monkeypatch.setenv("PLUGIN_TRANSPORTS", "tcp")


@pytest_asyncio.fixture(scope="module")
async def server_instance(
    mock_server_config,
    mock_server_protocol,
    mock_server_handler,
    mock_server_transport,
    client_cert,
):
    from pyvider.rpcplugin.config import rpcplugin_config

    transport = mock_server_transport

    try:
        # Set environment variables
        rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
        rpcplugin_config.set(
            "PLUGIN_MAGIC_COOKIE",
            "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
        )
        rpcplugin_config.set("PLUGIN_PROTOCOL_VERSIONS", "6")
        rpcplugin_config.set("PLUGIN_TRANSPORTS", "unix")
        rpcplugin_config.get("PLUGIN_CLIENT_CERT")

        # Start the server with mock handler
        server = RPCPluginServer(
            protocol=mock_server_protocol,
            handler=mock_server_handler,
            config=mock_server_config,
            transport=mock_server_transport, # This transport's path is managed by managed_unix_socket_path
        )
        asyncio.create_task(server.serve())

        # Wait for server readiness
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=10)

        yield server
    finally:
        # Cleanup
        await server.stop()
        # Socket cleanup is now fully handled by the managed_unix_socket_path fixture
        # which is used by the unix_transport fixture, which mock_server_transport might be.
        # No need to check transport_name or os.path.exists here.


@pytest_asyncio.fixture(scope="function")
async def mock_async_tcp_server(mock_server_transport_tcp) -> None:
    transport = mock_server_transport_tcp
    endpoint = await transport.listen()

    host, port = endpoint.split(":")

    # Simulate a client connection
    reader, writer = await asyncio.open_connection(host, int(port))
    writer.write(b"test data")
    await writer.drain()

    # Keep connection open to simulate active connection
    await asyncio.sleep(1)
    if writer is not None:
        writer.close()

    await writer.wait_closed()

    # Test transport close
    await transport.close()

### 🐍🏗🧪️
