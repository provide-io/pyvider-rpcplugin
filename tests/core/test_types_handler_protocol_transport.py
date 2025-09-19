# tests/core/test_types_handler_protocol_transport.py
"""Tests for handler, protocol, and transport type validation."""

from provide.testkit.mocking import MagicMock

from pyvider.rpcplugin import types as types_module_logger_ref
from pyvider.rpcplugin.types import (
    RPCPluginHandler,
    RPCPluginProtocol,
    RPCPluginTransport,
    is_valid_handler,
    is_valid_protocol,
    is_valid_transport,
)


# Test for is_valid_handler
def test_is_valid_handler_true(mocker: object) -> None:
    """Test is_valid_handler with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class ValidHandler(RPCPluginHandler):
        # No methods needed for this basic protocol check with isinstance
        pass

    handler_instance = ValidHandler()
    assert is_valid_handler(handler_instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginHandler protocol")


def test_is_valid_handler_false(mocker: object) -> None:
    """Test is_valid_handler with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    non_handler_instance = object()
    # For an empty @runtime_checkable protocol, isinstance(object(), Protocol) is True.
    assert is_valid_handler(non_handler_instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginHandler protocol")


# Test for is_valid_protocol
def test_is_valid_protocol_true(mocker: object) -> None:
    """Test is_valid_protocol with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class ValidProtocol(RPCPluginProtocol):
        async def get_grpc_descriptors(self):
            return (None, "service")

        async def add_to_server(self, handler, server) -> None:
            pass

        def get_method_type(self, method_name) -> str:
            return "unary_unary"

    protocol_instance = ValidProtocol()
    assert is_valid_protocol(protocol_instance) is True
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginProtocol protocol"
    )


def test_is_valid_protocol_false(mocker: object) -> None:
    """Test is_valid_protocol with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class InvalidProtocol:  # Missing methods
        pass

    protocol_instance = InvalidProtocol()
    assert is_valid_protocol(protocol_instance) is False
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginProtocol protocol"
    )


# Test for is_valid_transport
def test_is_valid_transport_true(mocker: object) -> None:
    """Test is_valid_transport with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class ValidTransport(RPCPluginTransport):
        endpoint: str | None = None

        async def listen(self) -> str:
            return "endpoint"

        async def connect(self, endpoint: str) -> None:
            pass

        async def close(self) -> None:
            pass

    transport_instance = ValidTransport()
    assert is_valid_transport(transport_instance) is True
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginTransport protocol"
    )


def test_is_valid_transport_false(mocker: object) -> None:
    """Test is_valid_transport with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    non_transport_instance = object()
    assert is_valid_transport(non_transport_instance) is False
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginTransport protocol"
    )
