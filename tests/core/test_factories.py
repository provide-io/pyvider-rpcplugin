# tests/rpcplugin/test_factories.py

import pytest
from attrs import define
import asyncio # asyncio import re-added
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
    ProtocolClass = create_basic_protocol()
    protocol_instance = ProtocolClass(service_name_override="TestService") # Override for test
    assert isinstance(protocol_instance, RPCPluginProtocol)

    # Test get_grpc_descriptors
    descriptors, service_name = asyncio.run(protocol_instance.get_grpc_descriptors())
    assert descriptors is None
    assert service_name == "TestService"

    # Test add_to_server (it's a no-op, so just ensure it runs without error)
    mock_grpc_server = object()  # A simple mock for the gRPC server
    asyncio.run(protocol_instance.add_to_server(None, mock_grpc_server))


@pytest.mark.asyncio
async def test_plugin_protocol_basic_default():
    """Test plugin_protocol defaulting to BasicRPCPluginProtocol."""
    protocol_instance = plugin_protocol(service_name="MyBasicService")

    # Verify it's an instance of the type returned by create_basic_protocol
    # This is a bit indirect, but checks it's the default path.
    # BasicProtoClass = create_basic_protocol() # Call only once by checking type of protocol_instance
    assert type(protocol_instance).__name__ == "BasicRPCPluginProtocol"
    assert protocol_instance.service_name == "MyBasicService"

    # Test get_grpc_descriptors for BasicRPCPluginProtocol
    descriptors, service_name = await protocol_instance.get_grpc_descriptors()
    assert descriptors is None # BasicRPCPluginProtocol returns None for descriptors
    assert service_name == "MyBasicService"

    # Test add_to_server for BasicRPCPluginProtocol (it's a no-op)
    mock_grpc_server = object()
    mock_handler = MockHandler()
    await protocol_instance.add_to_server(mock_handler, mock_grpc_server)
    # No specific call to assert as it's a pass, just ensure no error.

@pytest.mark.asyncio
async def test_plugin_protocol_custom_class():
    """Test plugin_protocol with a custom protocol_class."""

    class CustomTestProtocol(RPCPluginProtocol):
        service_name = "CustomService"

        def __init__(self, custom_arg: str, service_name_override: str | None = None):
            super().__init__()
            self.custom_arg = custom_arg
            if service_name_override:
                 self.service_name = service_name_override # Allow override for testing

        async def get_grpc_descriptors(self):
            return "custom_descriptors", self.service_name

        async def add_to_server(self, handler, server):
            # Simulate adding to server, e.g., by calling a handler method
            if hasattr(handler, 'register'):
                handler.register(server, self.service_name)
            pass # For this test, just ensuring it's called is enough

        def get_method_type(self, method_name: str) -> str:
            return "custom_unary_unary"

    # Test providing a custom protocol class
    # Note: The factory now passes all kwargs to the protocol_class constructor
    # if protocol_class is provided.
    # The factory itself doesn't use handler_class for instantiation logic,
    # it's more of a placeholder or for potential future use.

    # Scenario 1: Custom class with its own args
    custom_protocol_instance = plugin_protocol(
        protocol_class=CustomTestProtocol,
        # service_name="IgnoredWhenClassHasOwn", # This will be ignored if CustomTestProtocol doesn't take service_name in __init__
        custom_arg="my_value" # Pass args for CustomTestProtocol
    )
    assert isinstance(custom_protocol_instance, CustomTestProtocol)
    assert custom_protocol_instance.custom_arg == "my_value"
    assert custom_protocol_instance.service_name == "CustomService" # Default from class

    desc, name = await custom_protocol_instance.get_grpc_descriptors()
    assert desc == "custom_descriptors"
    assert name == "CustomService"

    # Scenario 2: Custom class with service_name override (if __init__ supports it)
    custom_protocol_instance_override = plugin_protocol(
        protocol_class=CustomTestProtocol,
        service_name="OverriddenService", # This kwarg is passed to CustomTestProtocol
        custom_arg="another_value"
    )
    assert custom_protocol_instance_override.service_name == "OverriddenService"
    assert custom_protocol_instance_override.custom_arg == "another_value"


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

    with pytest.raises(ValueError, match="Unsupported transport type: bogus"): # Changed to ValueError
        plugin_server(
            protocol=mock_protocol_inst, handler=mock_handler_inst, transport="bogus"
        )


# TODO: Add tests for plugin_client


@patch("pyvider.rpcplugin.factories.RPCPluginClient")
def test_plugin_client_basic(mock_rpc_client_cls):
    """Test plugin_client basic functionality."""
    server_command = ["/fake/server"]
    client_config = {"some_config": "value"}

    client = plugin_client(command=server_command, config=client_config, auto_connect=False)

    mock_rpc_client_cls.assert_called_once_with(
        command=server_command, config=client_config
    )
    assert client is mock_rpc_client_cls.return_value


@patch("pyvider.rpcplugin.factories.RPCPluginClient")
def test_plugin_client_with_options_and_auto_connect_warning(
    mock_rpc_client_cls
):
    """Test plugin_client with auto_connect=True issues a warning."""
    server_command = ["/fake/server_exec"]
    custom_config = {"VAR": "val", "timeout": 5.0, "extra_option": "test_val"}

    mock_client_instance = MagicMock(spec=RPCPluginClient)
    mock_rpc_client_cls.return_value = mock_client_instance

    with patch("pyvider.rpcplugin.factories.logger.warning") as mock_logger_warning:
        client = plugin_client(
            command=server_command,
            config=custom_config,
            auto_connect=True # This should trigger the warning
        )

        mock_rpc_client_cls.assert_called_once_with(
            command=server_command,
            config=custom_config,
        )
        assert client is mock_client_instance
        mock_logger_warning.assert_called_once_with(
            "🏭 auto_connect=True in synchronous factory is misleading. "
            "Caller should handle async client.start()."
        )
        # client.start() should not be called by the factory itself anymore
        mock_client_instance.start.assert_not_called()


# The tests for server_not_found and server_not_executable are no longer relevant
# as the factory doesn't do path checking. These responsibilities are now with the caller
# or within the RPCPluginClient itself if it were to do such checks.
# For now, removing them as the factory's responsibility changed.

# 🐍🧪🏭
