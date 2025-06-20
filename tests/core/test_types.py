# tests/core/test_types.py


# Assuming RPCPluginHandler, RPCPluginProtocol, RPCPluginTransport are importable
# from the SUT (System Under Test - types.py)
from pyvider.rpcplugin.types import (
    RPCPluginHandler,
    RPCPluginProtocol,
    RPCPluginTransport,
    is_valid_handler,
    is_valid_protocol,
    is_valid_transport,
    is_valid_serializable,  # Added import
    is_valid_connection,  # Added import
    is_valid_secure_rpc_client,  # Added import
)

# Import logger from the types module to patch it where it's used by the TypeGuards
from pyvider.rpcplugin import types as types_module_logger_ref


# Test for is_valid_handler
from unittest.mock import MagicMock


def test_is_valid_handler_true(mocker):
    """Test is_valid_handler with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class ValidHandler(RPCPluginHandler):
        # No methods needed for this basic protocol check with isinstance
        pass

    handler_instance = ValidHandler()
    assert is_valid_handler(handler_instance) is True
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginHandler protocol"
    )


def test_is_valid_handler_false(mocker):
    """Test is_valid_handler with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    non_handler_instance = object()
    # For an empty @runtime_checkable protocol, isinstance(object(), Protocol) is True.
    assert is_valid_handler(non_handler_instance) is True
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginHandler protocol"
    )


# Test for is_valid_protocol
def test_is_valid_protocol_true(mocker):
    """Test is_valid_protocol with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class ValidProtocol(RPCPluginProtocol):
        async def get_grpc_descriptors(self):
            return (None, "service")

        async def add_to_server(self, handler, server):
            pass

        def get_method_type(self, method_name):
            return "unary_unary"

    protocol_instance = ValidProtocol()
    assert is_valid_protocol(protocol_instance) is True
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginProtocol protocol"
    )


def test_is_valid_protocol_false(mocker):
    """Test is_valid_protocol with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidProtocol:  # Missing methods
        pass

    protocol_instance = InvalidProtocol()
    assert is_valid_protocol(protocol_instance) is False
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginProtocol protocol"
    )


# Test for is_valid_transport
def test_is_valid_transport_true(mocker):
    """Test is_valid_transport with an object that implements the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class ValidTransport(RPCPluginTransport):
        endpoint: str | None = None

        async def listen(self):
            return "endpoint"

        async def connect(self, endpoint):
            pass

        async def close(self):
            pass

    transport_instance = ValidTransport()
    assert is_valid_transport(transport_instance) is True
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginTransport protocol"
    )


def test_is_valid_transport_false(mocker):
    """Test is_valid_transport with an object that does not implement the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    non_transport_instance = object()
    assert is_valid_transport(non_transport_instance) is False
    mock_logger_debug.assert_called_once_with(
        "🧰🔍✅ Checking if object implements RPCPluginTransport protocol"
    )


# Test for is_valid_serializable
def test_is_valid_serializable_true(mocker):
    """Test is_valid_serializable with an object that correctly implements the protocol."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class ValidSerializable:  # Does NOT inherit SerializableT
        def to_dict(self) -> dict[str, object]:
            return {"data": "valid"}

        @classmethod
        def from_dict(cls, data: dict[str, object]) -> "ValidSerializable":
            instance = cls()
            return instance

    instance = ValidSerializable()
    assert is_valid_serializable(instance) is True
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SerializableT protocol (manual runtime checks)"
        ),
        mocker.call("SerializableT: All structural and signature checks passed."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_serializable_false_missing_methods(mocker):
    """Test is_valid_serializable with an object missing required methods."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidSerializableMissing:
        # Missing to_dict and from_dict
        pass

    instance = InvalidSerializableMissing()
    assert is_valid_serializable(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SerializableT protocol (manual runtime checks)"
        ),
        mocker.call("SerializableT: Method to_dict is missing."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_serializable_false_incorrect_signature(mocker):
    """Test is_valid_serializable with an object having methods with incorrect signatures."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidSerializableSignature:  # Does NOT inherit SerializableT
        def to_dict(self, extra_arg: int) -> dict[str, object]:
            return {"key": extra_arg}

        @classmethod
        def from_dict(
            cls, data: dict[str, object], extra_arg: int
        ) -> "InvalidSerializableSignature":
            return cls()

    instance = InvalidSerializableSignature()
    assert is_valid_serializable(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SerializableT protocol (manual runtime checks)"
        ),
        mocker.call(
            "SerializableT: to_dict signature incorrect. Expected 0 params, got 1."
        ),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


# Test for is_valid_connection
def test_is_valid_connection_true(mocker):
    """Test is_valid_connection with an object that correctly implements ConnectionT."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class ValidConnection:  # No longer inherits ConnectionT for manual check testing
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    instance = ValidConnection()
    assert is_valid_connection(instance) is True
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"
        ),
        mocker.call("ConnectionT: All structural and signature checks passed."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_connection_false_missing_method(mocker):
    """Test is_valid_connection with an object missing a required method."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidConnectionMissing:  # Does not inherit ConnectionT
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        # Missing close method

    instance = InvalidConnectionMissing()
    assert is_valid_connection(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"
        ),
        mocker.call("ConnectionT: Method close is missing."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_connection_false_send_data_signature(mocker):
    """Test is_valid_connection with incorrect send_data signature."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidConnectionSendDataSig:  # Does not inherit ConnectionT
        async def send_data(self) -> None:  # Missing 'data' param
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    instance = InvalidConnectionSendDataSig()
    assert is_valid_connection(instance) is False  # Main assertion

    # Verify key log messages were made
    mock_logger_debug.assert_any_call(
        "🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"
    )

    # Check for the specific failure log related to send_data signature
    # This makes sure the *reason* for returning False is the one we are testing
    specific_failure_log_made = False
    expected_specific_log = (
        "ConnectionT: send_data signature incorrect. Expected 1 param, got 0."
    )
    for call_item in mock_logger_debug.call_args_list:
        if call_item == mocker.call(expected_specific_log):
            specific_failure_log_made = True
            break
    assert specific_failure_log_made, (
        f"Expected log '{expected_specific_log}' not found in actual calls: {mock_logger_debug.call_args_list}"
    )

    assert mock_logger_debug.call_count >= 2


def test_is_valid_connection_false_receive_data_signature(mocker):
    """Test is_valid_connection with incorrect receive_data signature."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidConnectionReceiveDataSig:  # Does not inherit ConnectionT
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self) -> bytes:  # Missing 'size' param
            return b""

        async def close(self) -> None:
            pass

    instance = InvalidConnectionReceiveDataSig()
    assert is_valid_connection(instance) is False  # Main assertion

    mock_logger_debug.assert_any_call(
        "🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"
    )

    specific_failure_log_made = False
    expected_specific_log = (
        "ConnectionT: receive_data signature incorrect. Expected 1 param, got 0."
    )
    # Iterate through call_args_list to find the specific log
    for call_item in mock_logger_debug.call_args_list:
        if call_item == mocker.call(expected_specific_log):
            specific_failure_log_made = True
            break
    assert specific_failure_log_made, (
        f"Expected log '{expected_specific_log}' not found in actual calls: {mock_logger_debug.call_args_list}"
    )

    assert mock_logger_debug.call_count >= 2


def test_is_valid_connection_false_close_signature(mocker):
    """Test is_valid_connection with incorrect close signature."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidConnectionCloseSig:  # Does not inherit ConnectionT
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        async def close(self, extra_arg) -> None:  # Has extra param
            pass

    instance = InvalidConnectionCloseSig()
    assert is_valid_connection(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"
        ),
        mocker.call(
            "ConnectionT: close signature incorrect. Expected 0 params, got 1."
        ),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_connection_false_not_async(mocker):
    """Test is_valid_connection with a method that is not async."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidConnectionNotAsync:  # Does not inherit ConnectionT
        def send_data(self, data: bytes) -> None:  # Not async
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    instance = InvalidConnectionNotAsync()
    assert is_valid_connection(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"
        ),
        mocker.call("ConnectionT: Method send_data is not async as expected."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


# Test for is_valid_secure_rpc_client
def test_is_valid_secure_rpc_client_true(mocker):
    """Test is_valid_secure_rpc_client with an object that correctly implements SecureRpcClientT."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class ValidSecureRpcClient:  # Does not inherit SecureRpcClientT
        async def _perform_handshake(self) -> None:
            pass

        async def _setup_tls(self) -> None:
            pass

        async def _create_grpc_channel(self) -> None:
            pass

        async def close(self) -> None:
            pass

    instance = ValidSecureRpcClient()
    assert is_valid_secure_rpc_client(instance) is True
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"
        ),
        mocker.call("SecureRpcClientT: All structural and signature checks passed."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_secure_rpc_client_false_missing_method(mocker):
    """Test is_valid_secure_rpc_client with an object missing a required method."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidSecureRpcClientMissing:  # Does not inherit SecureRpcClientT
        async def _perform_handshake(self) -> None:
            pass

        async def _setup_tls(self) -> None:
            pass

        # Missing _create_grpc_channel
        async def close(self) -> None:
            pass

    instance = InvalidSecureRpcClientMissing()
    assert is_valid_secure_rpc_client(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"
        ),
        mocker.call("SecureRpcClientT: Method _create_grpc_channel is missing."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_secure_rpc_client_false_perform_handshake_signature(mocker):
    """Test is_valid_secure_rpc_client with incorrect _perform_handshake signature."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidSecureRpcClientSig:  # Does not inherit SecureRpcClientT
        async def _perform_handshake(self, extra_arg) -> None:
            pass  # Incorrect signature

        async def _setup_tls(self) -> None:
            pass

        async def _create_grpc_channel(self) -> None:
            pass

        async def close(self) -> None:
            pass

    instance = InvalidSecureRpcClientSig()
    assert is_valid_secure_rpc_client(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"
        ),
        mocker.call(
            "SecureRpcClientT: _perform_handshake signature incorrect. Expected 0 params, got 1."
        ),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_secure_rpc_client_false_not_async(mocker):
    """Test is_valid_secure_rpc_client with a method that is not async."""
    mock_logger_debug = mocker.patch.object(
        types_module_logger_ref.logger, "debug", new_callable=MagicMock
    )

    class InvalidSecureRpcClientNotAsync:  # Does not inherit SecureRpcClientT
        async def _perform_handshake(self) -> None:
            pass

        def _setup_tls(self) -> None:
            pass  # Not async

        async def _create_grpc_channel(self) -> None:
            pass

        async def close(self) -> None:
            pass

    instance = InvalidSecureRpcClientNotAsync()
    assert is_valid_secure_rpc_client(instance) is False
    expected_log_calls = [
        mocker.call(
            "🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"
        ),
        mocker.call("SecureRpcClientT: Method _setup_tls is not async as expected."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2
