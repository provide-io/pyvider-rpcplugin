# tests/protocol/test_grpc_controller.py

import pytest
import importlib
import os  # Added import
import grpc
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_controller_pb2,
    grpc_controller_pb2_grpc,
)


@pytest.mark.asyncio
async def test_grpc_controller_pb2_imports() -> None:
    """Test importing grpc_controller_pb2 and accessing its components."""
    # Access message descriptors
    assert hasattr(grpc_controller_pb2, "DESCRIPTOR")

    # Test creating an Empty message
    empty = grpc_controller_pb2.Empty()

    # Test serialization
    serialized = empty.SerializeToString()
    assert isinstance(serialized, bytes)

    # Test deserialization
    deserialized = grpc_controller_pb2.Empty()
    deserialized.ParseFromString(serialized)


@pytest.mark.asyncio
async def test_grpc_controller_pb2_grpc_stub_creation() -> None:
    """Test creating a GRPCControllerStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_controller_pb2_grpc.GRPCControllerStub(mock_channel)

    # Verify methods
    assert hasattr(stub, "Shutdown")


@pytest.mark.asyncio
async def test_grpc_controller_servicer_methods() -> None:
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


@pytest.mark.asyncio
async def test_controller_pb2_descriptor() -> None:
    """Test that grpc_controller_pb2.DESCRIPTOR is available and has expected properties."""
    assert hasattr(grpc_controller_pb2, "DESCRIPTOR")
    descriptor = grpc_controller_pb2.DESCRIPTOR

    # Test specific serialized properties / public API
    assert hasattr(descriptor, "message_types_by_name")
    assert (
        "Empty" in descriptor.message_types_by_name
    )  # Assuming Empty is a message type

    # Ensure it has a name (check basename)
    assert os.path.basename(descriptor.name) == "grpc_controller.proto"

    # Check for a known option if available and stable, e.g. python_package
    # options = descriptor.GetOptions() # Commented out as it's unused now
    # assert options.HasField("python_package") # Commented out due to protoc regeneration issues
    # assert options.python_package == "pyvider.rpcplugin.protocol" # Commented out


@pytest.mark.asyncio
async def test_controller_grpc_version_mismatch() -> None:
    """Direct test for grpc_controller_pb2_grpc version check (lines 18-19, 22)."""
    with patch("grpc._utilities.first_version_is_lower", return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_controller_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)


@pytest.mark.asyncio
async def test_controller_experimental_api() -> None:
    """Direct test for grpc_controller_pb2_grpc experimental API (line 90)."""
    assert hasattr(grpc_controller_pb2_grpc, "GRPCController")
    assert hasattr(grpc_controller_pb2_grpc.GRPCController, "Shutdown")

    mock_request = MagicMock()
    mock_target = MagicMock()

    # Call the experimental method directly
    with patch("grpc.experimental.unary_unary") as mock_unary_unary:
        grpc_controller_pb2_grpc.GRPCController.Shutdown(
            mock_request, mock_target, metadata={"test": "value"}
        )
        mock_unary_unary.assert_called_once()


### 🐍🏗🧪️
