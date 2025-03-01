
# tests/protocol/test_grpc_controller.py

import pytest
import importlib
import grpc
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_controller_pb2,
    grpc_controller_pb2_grpc,
)

async def test_grpc_controller_pb2_imports():
    """Test importing grpc_controller_pb2 and accessing its components."""
    # Access message descriptors
    assert hasattr(grpc_controller_pb2, 'DESCRIPTOR')

    # Test creating an Empty message
    empty = grpc_controller_pb2.Empty()

    # Test serialization
    serialized = empty.SerializeToString()
    assert isinstance(serialized, bytes)

    # Test deserialization
    deserialized = grpc_controller_pb2.Empty()
    deserialized.ParseFromString(serialized)

async def test_grpc_controller_pb2_grpc_stub_creation():
    """Test creating a GRPCControllerStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_controller_pb2_grpc.GRPCControllerStub(mock_channel)

    # Verify methods
    assert hasattr(stub, 'Shutdown')

async def test_grpc_controller_servicer_methods():
    """Test GRPCControllerServicer methods."""
    # Create a servicer
    servicer = grpc_controller_pb2_grpc.GRPCControllerServicer()

    # Create mock context and request
    context = MagicMock()
    request = grpc_controller_pb2.Empty()

    # Call Shutdown
    with pytest.raises(NotImplementedError):
        servicer.Shutdown(request, context)

    # Verify context method calls
    context.set_code.assert_called_once_with(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details.assert_called_once_with("Method not implemented!")

async def test_controller_pb2_descriptor():
    """Direct test for grpc_controller_pb2 descriptor options (lines 30-34)."""
    assert hasattr(grpc_controller_pb2, "DESCRIPTOR")
    with patch.object(grpc_controller_pb2.DESCRIPTOR, "_loaded_options", None), \
         patch.object(grpc_controller_pb2.DESCRIPTOR, "_USE_C_DESCRIPTORS", False):
        importlib.reload(grpc_controller_pb2)
    
    descriptor = grpc_controller_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "Empty" in descriptor.message_types_by_name

async def test_controller_grpc_version_mismatch():
    """Direct test for grpc_controller_pb2_grpc version check (lines 18-19, 22)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_controller_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

async def test_controller_experimental_api():
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

### 🐍🏗🧪️
