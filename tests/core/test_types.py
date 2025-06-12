# tests/core/test_types.py

import pytest
from unittest.mock import MagicMock, patch

# Assuming RPCPluginHandler, RPCPluginProtocol, RPCPluginTransport are importable
# from the SUT (System Under Test - types.py)
from pyvider.rpcplugin.types import (
    RPCPluginHandler,
    RPCPluginProtocol,
    RPCPluginTransport,
    SerializableT, # Added import
    is_valid_handler,
    is_valid_protocol,
    is_valid_transport,
    is_valid_serializable, # Added import
)
# Import logger from the types module to patch it where it's used by the TypeGuards
from pyvider.rpcplugin import types as types_module_logger_ref


# Test for is_valid_handler
def test_is_valid_handler_true(mocker):
    """Test is_valid_handler with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class ValidHandler(RPCPluginHandler):
        # No methods needed for this basic protocol check with isinstance
        pass

    handler_instance = ValidHandler()
    assert is_valid_handler(handler_instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginHandler protocol")

def test_is_valid_handler_false(mocker):
    """Test is_valid_handler with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    non_handler_instance = object()
    # For an empty @runtime_checkable protocol, isinstance(object(), Protocol) is True.
    assert is_valid_handler(non_handler_instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginHandler protocol")

# Test for is_valid_protocol
def test_is_valid_protocol_true(mocker):
    """Test is_valid_protocol with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class ValidProtocol(RPCPluginProtocol):
        async def get_grpc_descriptors(self): return (None, "service")
        async def add_to_server(self, handler, server): pass
        def get_method_type(self, method_name): return "unary_unary"

    protocol_instance = ValidProtocol()
    assert is_valid_protocol(protocol_instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginProtocol protocol")

def test_is_valid_protocol_false(mocker):
    """Test is_valid_protocol with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidProtocol: # Missing methods
        pass

    protocol_instance = InvalidProtocol()
    assert is_valid_protocol(protocol_instance) is False
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginProtocol protocol")

# Test for is_valid_transport
def test_is_valid_transport_true(mocker):
    """Test is_valid_transport with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class ValidTransport(RPCPluginTransport):
        endpoint: str | None = None
        async def listen(self): return "endpoint"
        async def connect(self, endpoint): pass
        async def close(self): pass

    transport_instance = ValidTransport()
    assert is_valid_transport(transport_instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginTransport protocol")

def test_is_valid_transport_false(mocker):
    """Test is_valid_transport with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    non_transport_instance = object()
    assert is_valid_transport(non_transport_instance) is False
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements RPCPluginTransport protocol")


# Test for is_valid_serializable
def test_is_valid_serializable_true(mocker):
    """Test is_valid_serializable with an object that correctly implements the protocol."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class ValidSerializable(SerializableT):
        def to_dict(self):
            return {"data": "valid"}

        @classmethod
        def from_dict(cls, data):
            return cls()

    instance = ValidSerializable()
    assert is_valid_serializable(instance) is True
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements SerializableT protocol")

def test_is_valid_serializable_false_missing_methods(mocker):
    """Test is_valid_serializable with an object missing required methods."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidSerializableMissing:
        # Missing to_dict and from_dict
        pass

    instance = InvalidSerializableMissing()
    assert is_valid_serializable(instance) is False
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements SerializableT protocol")

def test_is_valid_serializable_false_incorrect_signature(mocker):
    """Test is_valid_serializable with an object having methods with incorrect signatures."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidSerializableSignature:
        def to_dict(self, extra_arg): # Incorrect signature
            return {"data": "invalid"}

        @classmethod
        def from_dict(cls, data, extra_arg): # Incorrect signature
            return cls()

    instance = InvalidSerializableSignature()
    assert is_valid_serializable(instance) is False
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements SerializableT protocol")
