# tests/protocol/test_grpc_generated_direct.py

import pytest
from unittest.mock import patch, MagicMock
import importlib

from pyvider.rpcplugin.protocol import (
    grpc_broker_pb2,
    grpc_broker_pb2_grpc,
    grpc_controller_pb2,
    grpc_controller_pb2_grpc,
    grpc_stdio_pb2,
    grpc_stdio_pb2_grpc,
)

# Test pb2 descriptor options (lines 30-36 in various pb2 files)
def test_broker_pb2_descriptor():
    """Direct test for grpc_broker_pb2 descriptor options (lines 30-36)."""
    # Direct access to specific global symbols
    # These will exercise the if not _descriptor._USE_C_DESCRIPTORS block
    assert hasattr(grpc_broker_pb2, "DESCRIPTOR")
    with patch.object(grpc_broker_pb2.DESCRIPTOR, "_loaded_options", None), \
         patch.object(grpc_broker_pb2.DESCRIPTOR, "_USE_C_DESCRIPTORS", False):
        importlib.reload(grpc_broker_pb2)

    # Test specific serialized properties
    descriptor = grpc_broker_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "ConnInfo" in descriptor.message_types_by_name

def test_controller_pb2_descriptor():
    """Direct test for grpc_controller_pb2 descriptor options (lines 30-34)."""
    assert hasattr(grpc_controller_pb2, "DESCRIPTOR")
    with patch.object(grpc_controller_pb2.DESCRIPTOR, "_loaded_options", None), \
         patch.object(grpc_controller_pb2.DESCRIPTOR, "_USE_C_DESCRIPTORS", False):
        importlib.reload(grpc_controller_pb2)

    descriptor = grpc_controller_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "Empty" in descriptor.message_types_by_name

def test_stdio_pb2_descriptor():
    """Direct test for grpc_stdio_pb2 descriptor options (lines 32-38)."""
    assert hasattr(grpc_stdio_pb2, "DESCRIPTOR")
    with patch.object(grpc_stdio_pb2.DESCRIPTOR, "_loaded_options", None), \
         patch.object(grpc_stdio_pb2.DESCRIPTOR, "_USE_C_DESCRIPTORS", False):
        importlib.reload(grpc_stdio_pb2)

    descriptor = grpc_stdio_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "StdioData" in descriptor.message_types_by_name

# Test grpc version mismatch (lines 18-19 in *_grpc.py files)
def test_broker_grpc_version_mismatch():
    """Direct test for grpc_broker_pb2_grpc version check (lines 18-19)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_broker_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

def test_controller_grpc_version_mismatch():
    """Direct test for grpc_controller_pb2_grpc version check (lines 18-19, 22)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_controller_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

def test_stdio_grpc_version_mismatch():
    """Direct test for grpc_stdio_pb2_grpc version check (lines 19-20, 23)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_stdio_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

# Test experimental API (line 90 in various *_grpc.py files)
def test_broker_experimental_api():
    """Direct test for grpc_broker_pb2_grpc experimental API (line 90)."""
    assert hasattr(grpc_broker_pb2_grpc, "GRPCBroker")
    assert hasattr(grpc_broker_pb2_grpc.GRPCBroker, "StartStream")

    mock_request_iterator = MagicMock()
    mock_target = MagicMock()

    # Call the experimental method directly
    with patch('grpc.experimental.stream_stream') as mock_stream_stream:
        grpc_broker_pb2_grpc.GRPCBroker.StartStream(
            mock_request_iterator,
            mock_target,
            metadata={"test": "value"}
        )
        mock_stream_stream.assert_called_once()

def test_controller_experimental_api():
    """Direct test for grpc_controller_pb2_grpc experimental API (line 90)."""
    assert hasattr(grpc_controller_pb2_grpc, "GRPCController")
    assert hasattr(grpc_controller_pb2_grpc.GRPCController, "Shutdown")

    mock_request = MagicMock()
    mock_target = MagicMock()

    # Call the experimental method directly
    with patch('grpc.experimental.unary_unary') as mock_unary_unary:
        grpc_controller_pb2_grpc.GRPCController.Shutdown(
            mock_request,
            mock_target,
            metadata={"test": "value"}
        )
        mock_unary_unary.assert_called_once()

def test_stdio_experimental_api():
    """Direct test for grpc_stdio_pb2_grpc experimental API (line 105)."""
    assert hasattr(grpc_stdio_pb2_grpc, "GRPCStdio")
    assert hasattr(grpc_stdio_pb2_grpc.GRPCStdio, "StreamStdio")

    mock_request = MagicMock()
    mock_target = MagicMock()

    # Call the experimental method directly
    with patch('grpc.experimental.unary_stream') as mock_unary_stream:
        grpc_stdio_pb2_grpc.GRPCStdio.StreamStdio(
            mock_request,
            mock_target,
            metadata={"test": "value"}
        )
        mock_unary_stream.assert_called_once()

### 🐍🏗🧪️
