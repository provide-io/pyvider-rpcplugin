# tests/core/test_types_connection_client.py
"""Tests for connection and secure RPC client type validation."""

import inspect

from provide.testkit.mocking import MagicMock, patch

from pyvider.rpcplugin import types as types_module_logger_ref
from pyvider.rpcplugin.types import is_valid_connection, is_valid_secure_rpc_client


# ConnectionT Not Callable
def test_is_valid_connection_method_not_callable(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class ConnSendNotCallable:
        send_data = 123

        async def receive_data(self, size=16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    assert is_valid_connection(ConnSendNotCallable()) is False
    mock_logger_debug.assert_any_call("ConnectionT: Attribute send_data is not callable.")

    mock_logger_debug.reset_mock()

    class ConnReceiveNotCallable:
        async def send_data(self, data) -> None:
            pass

        receive_data = 123

        async def close(self) -> None:
            pass

    assert is_valid_connection(ConnReceiveNotCallable()) is False
    mock_logger_debug.assert_any_call("ConnectionT: Attribute receive_data is not callable.")

    mock_logger_debug.reset_mock()

    class ConnCloseNotCallable:
        async def send_data(self, data) -> None:
            pass

        async def receive_data(self, size=16384) -> bytes:
            return b""

        close = 123

    assert is_valid_connection(ConnCloseNotCallable()) is False
    mock_logger_debug.assert_any_call("ConnectionT: Attribute close is not callable.")


# ConnectionT Inspect Signature Fails (example for one method)
def test_is_valid_connection_inspect_signature_fails(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class ConnTargetForInspectFail:
        async def send_data(self, data) -> None:
            pass

        async def receive_data(self, size=16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    original_inspect_signature = inspect.signature

    def inspect_side_effect_selective_conn(obj_to_inspect):
        if (
            hasattr(obj_to_inspect, "__qualname__")
            and "ConnTargetForInspectFail.send_data" in obj_to_inspect.__qualname__
        ):
            raise ValueError("Inspect fail for send_data!")
        return original_inspect_signature(obj_to_inspect)

    with patch("inspect.signature", side_effect=inspect_side_effect_selective_conn):
        assert is_valid_connection(ConnTargetForInspectFail()) is False
    mock_logger_debug.assert_any_call("ConnectionT: Could not inspect send_data signature.")


# SecureRpcClientT Not Callable
def test_is_valid_secure_rpc_client_method_not_callable(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class ClientPerformHandshakeNotCallable:
        _perform_handshake = 123

        async def _setup_tls(self) -> None:
            pass

        async def _create_grpc_channel(self) -> None:
            pass

        async def close(self) -> None:
            pass

    assert is_valid_secure_rpc_client(ClientPerformHandshakeNotCallable()) is False
    mock_logger_debug.assert_any_call("SecureRpcClientT: Attribute _perform_handshake is not callable.")
    # Similar tests can be added for _setup_tls, _create_grpc_channel, close


# SecureRpcClientT Inspect Signature Fails (example for one method)
def test_is_valid_secure_rpc_client_inspect_signature_fails(mocker: object) -> None:
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug")

    class ClientTargetForInspectFail:
        async def _perform_handshake(self) -> None:
            pass

        async def _setup_tls(self) -> None:
            pass

        async def _create_grpc_channel(self) -> None:
            pass

        async def close(self) -> None:
            pass

    original_inspect_signature = inspect.signature

    def inspect_side_effect_selective_secure_client(obj_to_inspect):
        if (
            hasattr(obj_to_inspect, "__qualname__")
            and "ClientTargetForInspectFail._perform_handshake" in obj_to_inspect.__qualname__
        ):
            raise ValueError("Inspect fail for _perform_handshake!")
        return original_inspect_signature(obj_to_inspect)

    with patch("inspect.signature", side_effect=inspect_side_effect_selective_secure_client):
        assert is_valid_secure_rpc_client(ClientTargetForInspectFail()) is False
    mock_logger_debug.assert_any_call("SecureRpcClientT: Could not inspect _perform_handshake signature.")


# Test for is_valid_connection
def test_is_valid_connection_true(mocker: object) -> None:
    """Test is_valid_connection with an object that correctly implements ConnectionT."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"),
        mocker.call("ConnectionT: All structural and signature checks passed."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_connection_false_missing_method(mocker: object) -> None:
    """Test is_valid_connection with an object missing a required method."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

    class InvalidConnectionMissing:  # Does not inherit ConnectionT
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        # Missing close method

    instance = InvalidConnectionMissing()
    assert is_valid_connection(instance) is False
    expected_log_calls = [
        mocker.call("🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"),
        mocker.call("ConnectionT: Method close is missing."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_connection_false_send_data_signature(mocker: object) -> None:
    """Test is_valid_connection with incorrect send_data signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
    expected_specific_log = "ConnectionT: send_data signature incorrect. Expected 1 param, got 0."
    for call_item in mock_logger_debug.call_args_list:
        if call_item == mocker.call(expected_specific_log):
            specific_failure_log_made = True
            break
    assert specific_failure_log_made, (
        f"Expected log '{expected_specific_log}' not found in actual calls: {mock_logger_debug.call_args_list}"
    )

    assert mock_logger_debug.call_count >= 2


def test_is_valid_connection_false_receive_data_signature(mocker: object) -> None:
    """Test is_valid_connection with incorrect receive_data signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
    expected_specific_log = "ConnectionT: receive_data signature incorrect. Expected 1 param, got 0."
    # Iterate through call_args_list to find the specific log
    for call_item in mock_logger_debug.call_args_list:
        if call_item == mocker.call(expected_specific_log):
            specific_failure_log_made = True
            break
    assert specific_failure_log_made, (
        f"Expected log '{expected_specific_log}' not found in actual calls: {mock_logger_debug.call_args_list}"
    )

    assert mock_logger_debug.call_count >= 2


def test_is_valid_connection_false_close_signature(mocker: object) -> None:
    """Test is_valid_connection with incorrect close signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"),
        mocker.call("ConnectionT: close signature incorrect. Expected 0 params, got 1."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_connection_false_not_async(mocker: object) -> None:
    """Test is_valid_connection with a method that is not async."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements ConnectionT protocol (manual runtime checks)"),
        mocker.call("ConnectionT: Method send_data is not async as expected."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


# Test for is_valid_secure_rpc_client
def test_is_valid_secure_rpc_client_true(mocker: object) -> None:
    """Test is_valid_secure_rpc_client with an object that correctly implements SecureRpcClientT."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"),
        mocker.call("SecureRpcClientT: All structural and signature checks passed."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_secure_rpc_client_false_missing_method(mocker: object) -> None:
    """Test is_valid_secure_rpc_client with an object missing a required method."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"),
        mocker.call("SecureRpcClientT: Method _create_grpc_channel is missing."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_secure_rpc_client_false_perform_handshake_signature(mocker: object) -> None:
    """Test is_valid_secure_rpc_client with incorrect _perform_handshake signature."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"),
        mocker.call("SecureRpcClientT: _perform_handshake signature incorrect. Expected 0 params, got 1."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2


def test_is_valid_secure_rpc_client_false_not_async(mocker: object) -> None:
    """Test is_valid_secure_rpc_client with a method that is not async."""
    mock_logger_debug = mocker.patch.object(types_module_logger_ref.logger, "debug", new_callable=MagicMock)

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
        mocker.call("🧰🔍✅ Checking if object implements SecureRpcClientT protocol (manual runtime checks)"),
        mocker.call("SecureRpcClientT: Method _setup_tls is not async as expected."),
    ]
    mock_logger_debug.assert_has_calls(expected_log_calls, any_order=False)
    assert mock_logger_debug.call_count == 2
