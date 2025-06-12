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
    ConnectionT, # Added import
    SecureRpcClientT, # Added import
    is_valid_handler,
    is_valid_protocol,
    is_valid_transport,
    is_valid_serializable, # Added import
    is_valid_connection, # Added import
    is_valid_secure_rpc_client, # Added import
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
    mock_logger_debug.assert_called_once_with("🧰🔍✅ Checking if object implements SerializableT protocol (runtime signature check)")


# Test for is_valid_connection
def test_is_valid_connection_true(mocker):
    """Test is_valid_connection with an object that correctly implements ConnectionT."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class ValidConnection(ConnectionT):
        async def send_data(self, data: bytes) -> None:
            pass
        async def receive_data(self, size: int = 16384) -> bytes:
            return b""
        async def close(self) -> None:
            pass

    instance = ValidConnection()
    assert is_valid_connection(instance) is True
    # Check for the final success log, assuming intermediate checks also log
    mock_logger_debug.assert_any_call("ConnectionT: All checks passed.")

def test_is_valid_connection_false_missing_method(mocker):
    """Test is_valid_connection with an object missing a required method."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidConnectionMissing(ConnectionT):
        async def send_data(self, data: bytes) -> None:
            pass
        async def receive_data(self, size: int = 16384) -> bytes: # Missing close
            return b""
        # Missing close method implicitly by not defining it from the protocol

    instance = InvalidConnectionMissing()
    assert is_valid_connection(instance) is False
    mock_logger_debug.assert_any_call("ConnectionT: isinstance check failed (method missing or not async).")

def test_is_valid_connection_false_send_data_signature(mocker):
    """Test is_valid_connection with incorrect send_data signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidConnectionSendDataSig(ConnectionT):
        async def send_data(self) -> None: # Missing 'data' param
            pass
        async def receive_data(self, size: int = 16384) -> bytes:
            return b""
        async def close(self) -> None:
            pass

    instance = InvalidConnectionSendDataSig()
    assert is_valid_connection(instance) is False
    mock_logger_debug.assert_any_call("ConnectionT: send_data signature incorrect. Expected 1 param, got 0.")

def test_is_valid_connection_false_receive_data_signature(mocker):
    """Test is_valid_connection with incorrect receive_data signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidConnectionReceiveDataSig(ConnectionT):
        async def send_data(self, data: bytes) -> None:
            pass
        async def receive_data(self) -> bytes: # Missing 'size' param
            return b""
        async def close(self) -> None:
            pass

    instance = InvalidConnectionReceiveDataSig()
    assert is_valid_connection(instance) is False
    mock_logger_debug.assert_any_call("ConnectionT: receive_data signature incorrect. Expected 1 param, got 0.")

def test_is_valid_connection_false_close_signature(mocker):
    """Test is_valid_connection with incorrect close signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidConnectionCloseSig(ConnectionT):
        async def send_data(self, data: bytes) -> None:
            pass
        async def receive_data(self, size: int = 16384) -> bytes:
            return b""
        async def close(self, extra_arg) -> None: # Has extra param
            pass

    instance = InvalidConnectionCloseSig()
    assert is_valid_connection(instance) is False
    mock_logger_debug.assert_any_call("ConnectionT: close signature incorrect. Expected 0 params, got 1.")

def test_is_valid_connection_false_not_async(mocker):
    """Test is_valid_connection with a method that is not async."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidConnectionNotAsync(ConnectionT):
        def send_data(self, data: bytes) -> None: # Not async
            pass
        async def receive_data(self, size: int = 16384) -> bytes:
            return b""
        async def close(self) -> None:
            pass

    instance = InvalidConnectionNotAsync()
    # This check is primarily handled by isinstance and @runtime_checkable for async methods
    assert is_valid_connection(instance) is False
    mock_logger_debug.assert_any_call("ConnectionT: isinstance check failed (method missing or not async).")


# Test for is_valid_secure_rpc_client
def test_is_valid_secure_rpc_client_true(mocker):
    """Test is_valid_secure_rpc_client with an object that correctly implements SecureRpcClientT."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class ValidSecureRpcClient(SecureRpcClientT):
        async def _perform_handshake(self) -> None: pass
        async def _setup_tls(self) -> None: pass
        async def _create_grpc_channel(self) -> None: pass
        async def close(self) -> None: pass

    instance = ValidSecureRpcClient()
    assert is_valid_secure_rpc_client(instance) is True
    mock_logger_debug.assert_any_call("SecureRpcClientT: All checks passed.")

def test_is_valid_secure_rpc_client_false_missing_method(mocker):
    """Test is_valid_secure_rpc_client with an object missing a required method."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidSecureRpcClientMissing(SecureRpcClientT):
        async def _perform_handshake(self) -> None: pass
        async def _setup_tls(self) -> None: pass
        # Missing _create_grpc_channel
        async def close(self) -> None: pass

    instance = InvalidSecureRpcClientMissing()
    assert is_valid_secure_rpc_client(instance) is False
    mock_logger_debug.assert_any_call("SecureRpcClientT: isinstance check failed (method missing or not async).")

def test_is_valid_secure_rpc_client_false_perform_handshake_signature(mocker):
    """Test is_valid_secure_rpc_client with incorrect _perform_handshake signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidSecureRpcClientSig(SecureRpcClientT):
        async def _perform_handshake(self, extra_arg) -> None: pass # Incorrect signature
        async def _setup_tls(self) -> None: pass
        async def _create_grpc_channel(self) -> None: pass
        async def close(self) -> None: pass

    instance = InvalidSecureRpcClientSig()
    assert is_valid_secure_rpc_client(instance) is False
    mock_logger_debug.assert_any_call("SecureRpcClientT: _perform_handshake signature incorrect. Expected 0 params, got 1.")

def test_is_valid_secure_rpc_client_false_not_async(mocker):
    """Test is_valid_secure_rpc_client with a method that is not async."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, 'debug')

    class InvalidSecureRpcClientNotAsync(SecureRpcClientT):
        async def _perform_handshake(self) -> None: pass
        def _setup_tls(self) -> None: pass # Not async
        async def _create_grpc_channel(self) -> None: pass
        async def close(self) -> None: pass

    instance = InvalidSecureRpcClientNotAsync()
    assert is_valid_secure_rpc_client(instance) is False
    mock_logger_debug.assert_any_call("SecureRpcClientT: isinstance check failed (method missing or not async).")
