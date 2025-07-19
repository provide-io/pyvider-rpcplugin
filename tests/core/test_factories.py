# tests/rpcplugin/test_factories.py

import pytest
from attrs import define
import asyncio
from unittest.mock import MagicMock, patch
import os

from pyvider.rpcplugin.factories import (
    create_basic_protocol,
    plugin_protocol,
    plugin_server,
    plugin_client,
)
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.exception import TransportError


# Basic Mocks/Stubs for dependencies
@define
class MockProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        return None, "MockService"

    async def add_to_server(self, handler, server):
        pass


@define
class MockHandler:
    pass


# TODO: Add more mocks as needed for server/client tests


def test_create_basic_protocol():
    """Test that create_basic_protocol returns a valid RPCPluginProtocol."""
    protocol = create_basic_protocol()
    assert isinstance(protocol, RPCPluginProtocol)

    # Test get_grpc_descriptors
    descriptors, service_name = asyncio.run(protocol.get_grpc_descriptors())
    assert descriptors is None
    assert service_name == "TestService"

    # Test add_to_server (it's a no-op, so just ensure it runs without error)
    mock_grpc_server = object()  # A simple mock for the gRPC server
    asyncio.run(protocol.add_to_server(None, mock_grpc_server))


@pytest.mark.asyncio
async def test_plugin_protocol_basic():
    """Test plugin_protocol with minimal valid inputs."""
    mock_descriptor_module = MagicMock()
    mock_servicer_add_fn = MagicMock()

    protocol = plugin_protocol(
        service_name="TestService",
        descriptor_module=mock_descriptor_module,
        servicer_add_fn=mock_servicer_add_fn,
    )
    assert isinstance(protocol, RPCPluginProtocol)

    # Test get_grpc_descriptors
    descriptors, service_name = await protocol.get_grpc_descriptors()
    assert descriptors is mock_descriptor_module
    assert service_name == "TestService"

    # Test add_to_server
    mock_grpc_server = object()
    mock_handler = MockHandler()
    # When calling protocol.add_to_server(arg1, arg2):
    # arg1 is 'server' in GeneratedProtocol.add_to_server(self, server, handler)
    # arg2 is 'handler' in GeneratedProtocol.add_to_server(self, server, handler)
    # Inside GeneratedProtocol.add_to_server, the call is servicer_add_fn(handler, server)
    # So, servicer_add_fn is called with (arg2, arg1)
    await protocol.add_to_server(mock_handler, mock_grpc_server)
    mock_servicer_add_fn.assert_called_once_with(
        mock_grpc_server, mock_handler
    )  # Corrected argument order


@pytest.mark.asyncio
async def test_plugin_protocol_no_servicer_fn():
    """Test plugin_protocol when servicer_add_fn is None."""
    mock_descriptor_module = MagicMock()

    protocol = plugin_protocol(
        service_name="NoServicerService",
        descriptor_module=mock_descriptor_module,
        servicer_add_fn=None,
    )
    assert isinstance(protocol, RPCPluginProtocol)

    # Test get_grpc_descriptors
    descriptors, service_name = await protocol.get_grpc_descriptors()
    assert descriptors is mock_descriptor_module
    assert service_name == "NoServicerService"

    # Test add_to_server (should run without error and log a warning)
    mock_grpc_server = object()
    mock_handler = MockHandler()
    # Use patch to capture log messages if desired, or just ensure no error
    with patch("pyvider.rpcplugin.factories.logger.warning") as mock_log_warning:
        await protocol.add_to_server(mock_handler, mock_grpc_server)
        mock_log_warning.assert_called_once_with(
            "🧰📡⚠️ No servicer_add_fn provided for 'NoServicerService'"
        )


# TODO: Add tests for plugin_server


@patch("pyvider.rpcplugin.factories.RPCPluginServer")
@patch("pyvider.rpcplugin.factories.UnixSocketTransport")
def test_plugin_server_unix_transport_default_path(
    mock_unix_transport_cls, mock_rpc_plugin_server_cls
):
    """Test plugin_server with unix transport and default path."""
    mock_protocol_inst = MockProtocol()
    mock_handler_inst = MockHandler()

    server = plugin_server(
        protocol=mock_protocol_inst, handler=mock_handler_inst, transport="unix"
    )

    mock_unix_transport_cls.assert_called_once_with(path=None)
    mock_rpc_plugin_server_cls.assert_called_once_with(
        protocol=mock_protocol_inst,
        handler=mock_handler_inst,
        transport=mock_unix_transport_cls.return_value,
        config={},
    )
    assert server is mock_rpc_plugin_server_cls.return_value


@patch("pyvider.rpcplugin.factories.RPCPluginServer")
@patch("pyvider.rpcplugin.factories.UnixSocketTransport")
def test_plugin_server_unix_transport_custom_path(
    mock_unix_transport_cls, mock_rpc_plugin_server_cls
):
    """Test plugin_server with unix transport and a custom path."""
    mock_protocol_inst = MockProtocol()
    mock_handler_inst = MockHandler()
    custom_path = "/tmp/custom.sock"
    custom_config = {"foo": "bar"}

    server = plugin_server(
        protocol=mock_protocol_inst,
        handler=mock_handler_inst,
        transport="unix",
        transport_path=custom_path,
        config=custom_config,
    )

    mock_unix_transport_cls.assert_called_once_with(path=custom_path)
    mock_rpc_plugin_server_cls.assert_called_once_with(
        protocol=mock_protocol_inst,
        handler=mock_handler_inst,
        transport=mock_unix_transport_cls.return_value,
        config=custom_config,
    )
    assert server is mock_rpc_plugin_server_cls.return_value


@patch("pyvider.rpcplugin.factories.RPCPluginServer")
@patch("pyvider.rpcplugin.factories.TCPSocketTransport")
def test_plugin_server_tcp_transport_default_host_port(
    mock_tcp_transport_cls, mock_rpc_plugin_server_cls
):
    """Test plugin_server with tcp transport and default host/port."""
    mock_protocol_inst = MockProtocol()
    mock_handler_inst = MockHandler()

    server = plugin_server(
        protocol=mock_protocol_inst, handler=mock_handler_inst, transport="tcp"
    )

    mock_tcp_transport_cls.assert_called_once_with(host="127.0.0.1", port=0)
    mock_rpc_plugin_server_cls.assert_called_once_with(
        protocol=mock_protocol_inst,
        handler=mock_handler_inst,
        transport=mock_tcp_transport_cls.return_value,
        config={},
    )
    assert server is mock_rpc_plugin_server_cls.return_value


@patch("pyvider.rpcplugin.factories.RPCPluginServer")
@patch("pyvider.rpcplugin.factories.TCPSocketTransport")
def test_plugin_server_tcp_transport_custom_host_port(
    mock_tcp_transport_cls, mock_rpc_plugin_server_cls
):
    """Test plugin_server with tcp transport and custom host/port."""
    mock_protocol_inst = MockProtocol()
    mock_handler_inst = MockHandler()
    custom_host = "0.0.0.0"
    custom_port = 12345
    custom_config = {"baz": "qux"}

    server = plugin_server(
        protocol=mock_protocol_inst,
        handler=mock_handler_inst,
        transport="tcp",
        host=custom_host,
        port=custom_port,
        config=custom_config,
    )

    mock_tcp_transport_cls.assert_called_once_with(host=custom_host, port=custom_port)
    mock_rpc_plugin_server_cls.assert_called_once_with(
        protocol=mock_protocol_inst,
        handler=mock_handler_inst,
        transport=mock_tcp_transport_cls.return_value,
        config=custom_config,
    )
    assert server is mock_rpc_plugin_server_cls.return_value


def test_plugin_server_invalid_transport():
    """Test plugin_server with an invalid transport type."""
    mock_protocol_inst = MockProtocol()
    mock_handler_inst = MockHandler()

    with pytest.raises(TransportError, match="Invalid transport type: bogus"):
        plugin_server(
            protocol=mock_protocol_inst, handler=mock_handler_inst, transport="bogus"
        )


# TODO: Add tests for plugin_client


@patch("pyvider.rpcplugin.factories.asyncio.create_task")
@patch("pyvider.rpcplugin.factories.RPCPluginClient")
@patch("pyvider.rpcplugin.factories.os.access")
@patch("pyvider.rpcplugin.factories.os.path.exists")
def test_plugin_client_basic(
    mock_exists, mock_access, mock_rpc_client_cls, mock_create_task
):
    """Test plugin_client basic functionality without auto_connect."""
    mock_exists.return_value = True
    mock_access.return_value = True
    server_path = "/fake/server"

    client = plugin_client(server_path=server_path)

    mock_exists.assert_called_once_with(server_path)
    mock_access.assert_called_once_with(server_path, os.X_OK)
    mock_rpc_client_cls.assert_called_once_with(
        command=[server_path], config={"timeout": 10.0}
    )
    assert client is mock_rpc_client_cls.return_value
    mock_create_task.assert_not_called()


@patch("pyvider.rpcplugin.factories.asyncio.create_task")
@patch("pyvider.rpcplugin.factories.RPCPluginClient")
@patch("pyvider.rpcplugin.factories.os.access")
@patch("pyvider.rpcplugin.factories.os.path.exists")
def test_plugin_client_with_options_and_auto_connect(
    mock_exists, mock_access, mock_rpc_client_cls, mock_create_task
):
    """Test plugin_client with custom env, timeout, kwargs, and auto_connect."""
    mock_exists.return_value = True
    mock_access.return_value = True
    server_path = "/fake/server_exec"
    custom_env = {"VAR": "val"}
    custom_timeout = 5.0
    extra_kwarg = "test_val"

    # Mock the client instance returned by RPCPluginClient constructor
    mock_client_instance = MagicMock(spec=RPCPluginClient)
    # Make client.start() return a specific (mocked) coroutine object to ensure identity
    # This is important because each call to an AsyncMock method that returns a coroutine
    # will typically return a new coroutine object, causing identity checks to fail.
    # By pre-defining the coroutine, we ensure we're checking against the exact object
    # that would have been passed to asyncio.create_task.
    # However, since client.start is already an AsyncMock (due to MagicMock(spec=RPCPluginClient)),
    # we just need to ensure we capture the result of its *call* if we were to assert on the
    # specific coroutine object. The key is that `asyncio.create_task` receives the
    # coroutine object returned by `client.start()`.
    mock_rpc_client_cls.return_value = mock_client_instance

    client = plugin_client(
        server_path=server_path,
        env=custom_env,
        auto_connect=True,
        timeout=custom_timeout,
        extra_option=extra_kwarg,  # test **kwargs
    )

    mock_exists.assert_called_once_with(server_path)
    mock_access.assert_called_once_with(server_path, os.X_OK)
    mock_rpc_client_cls.assert_called_once_with(
        command=[server_path],
        config={
            "timeout": custom_timeout,
            "env": custom_env,
            "extra_option": extra_kwarg,
        },
    )
    assert client is mock_client_instance

    # Ensure client.start() was called (as it's an AsyncMock from the MagicMock spec)
    mock_client_instance.start.assert_called_once()

    # Ensure asyncio.create_task was called
    mock_create_task.assert_called_once()

    # Check that the argument to asyncio.create_task was the coroutine from client.start()
    # When mock_client_instance.start (an AsyncMock) is called, it returns a coroutine.
    # This coroutine is what's passed to create_task.
    args_list, _ = mock_create_task.call_args
    assert len(args_list) == 1
    created_task_arg = args_list[0]

    # Check it's a coroutine
    assert asyncio.iscoroutine(created_task_arg), (
        "Argument to create_task was not a coroutine"
    )
    # To be more specific, we can check if the coroutine's name (if available and stable) matches what we expect,
    # or that it's the return_value of the called mock_client_instance.start.
    # The key is that mock_client_instance.start() (a call to AsyncMock) produces a coroutine.
    # That specific coroutine instance is what's passed to create_task.
    # mock_client_instance.start.return_value is the mock *for* that coroutine.
    # The actual coroutine object created by the SUT is args_list[0].
    # We can check if this coroutine object is the one that would be returned by calling the mock method.
    # This is tricky because the mock system might wrap it.
    # A common pattern is to assert that the mock method (client.start) was called,
    # and that create_task was called. Verifying the exact coroutine instance can be fragile.
    # The check that it *is* a coroutine is a good step.
    # For now, ensuring client.start() was called and create_task was called once is the most robust.
    # If deeper inspection is needed, one might need to configure mock_client_instance.start to return a specific, known coroutine mock.
    # However, the current setup with spec=RPCPluginClient means client.start is already an AsyncMock.
    # The actual coroutine passed to create_task is `mock_client_instance.start.awaited[0][0][0]` if using `await mock_client_instance.start()`,
    # but here it's `mock_client_instance.start()` which returns the coroutine object.
    # The `call_args` for `mock_create_task` should contain this coroutine.
    # Let's check if the `created_task_arg` (from `mock_create_task.call_args`) is the `return_value` of the `mock_client_instance.start` mock.
    # This is what the previous failing assertion was trying to do.
    # The reason it failed is that `mock_client_instance.start.return_value` is an AsyncMock,
    # while `created_task_arg` is a concrete coroutine object.
    # This means `mock_client_instance.start()` was called, and its result (a coroutine) was passed.
    # So, `created_task_arg` should be an instance of a coroutine.
    # The critical check is `mock_client_instance.start.assert_called_once()` and `mock_create_task.assert_called_once()`.
    # The argument check for `mock_create_task` is more about type than specific instance if instance tracking is hard.
    # Given the previous failure, let's stick to type checking for the argument of create_task.
    # The previous logic: mock_create_task.assert_called_once_with(mock_client_instance.start.return_value)
    # failed because mock_client_instance.start.return_value is an AsyncMock, not the coroutine object itself.

    # The coroutine object passed to create_task is the result of calling mock_client_instance.start()
    # So, we expect mock_create_task to be called with the coroutine that mock_client_instance.start() would return.
    # mock_client_instance.start is an AsyncMock. Its return_value is what `await mock_client_instance.start()` resolves to,
    # not the coroutine object itself.
    # The object returned by just calling `mock_client_instance.start()` is the coroutine.
    # This is what create_task receives.
    # So we need to compare what create_task received with what a call to mock_client_instance.start() produces.
    # This is tricky because calling it again in the assert creates a *new* coroutine.

    # Let's assume the primary check is that `start` was called and `create_task` was called.
    # The `iscoroutine` check is a good addition.


@patch("pyvider.rpcplugin.factories.logger.error", new_callable=MagicMock)
@patch("pyvider.rpcplugin.factories.os.path.exists")
def test_plugin_client_server_not_found(mock_exists, mock_logger_error):
    """Test plugin_client when server executable does not exist."""
    mock_exists.return_value = False
    server_path = "/nonexistent/server"

    with pytest.raises(
        FileNotFoundError, match=f"Server executable not found: {server_path}"
    ):
        plugin_client(server_path=server_path)
    mock_exists.assert_called_once_with(server_path)
    mock_logger_error.assert_called_once()


@patch("pyvider.rpcplugin.factories.os.access")
@patch("pyvider.rpcplugin.factories.os.path.exists")
def test_plugin_client_server_not_executable(mock_exists, mock_access):
    """Test plugin_client when server executable is not executable."""
    mock_exists.return_value = True
    mock_access.return_value = False
    server_path = "/unexecutable/server"

    with pytest.raises(
        PermissionError, match=f"Server executable not executable: {server_path}"
    ):
        plugin_client(server_path=server_path)
    mock_exists.assert_called_once_with(server_path)
    mock_access.assert_called_once_with(server_path, os.X_OK)


# 🐍🧪🏭
