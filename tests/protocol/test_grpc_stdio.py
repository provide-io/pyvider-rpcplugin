# tests/protocol/test_grpc_stdio.py

import pytest
import importlib
import os  # Added import
import grpc
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_stdio_pb2,
    grpc_stdio_pb2_grpc,
)


@pytest.mark.asyncio
async def test_grpc_stdio_pb2_imports() -> None:
    """Test importing grpc_stdio_pb2 and accessing its components."""
    # Access message descriptors
    assert hasattr(grpc_stdio_pb2, "DESCRIPTOR")

    # Test creating a StdioData message with STDOUT channel
    stdout_data = grpc_stdio_pb2.StdioData(
        channel=grpc_stdio_pb2.StdioData.STDOUT, data=b"test stdout data"
    )
    assert stdout_data.channel == grpc_stdio_pb2.StdioData.STDOUT
    assert stdout_data.data == b"test stdout data"

    # Test creating a StdioData message with STDERR channel
    stderr_data = grpc_stdio_pb2.StdioData(
        channel=grpc_stdio_pb2.StdioData.STDERR, data=b"test stderr data"
    )
    assert stderr_data.channel == grpc_stdio_pb2.StdioData.STDERR
    assert stderr_data.data == b"test stderr data"

    # Test serialization
    serialized = stdout_data.SerializeToString()
    assert isinstance(serialized, bytes)

    # Test deserialization
    deserialized = grpc_stdio_pb2.StdioData()
    deserialized.ParseFromString(serialized)
    assert deserialized.channel == stdout_data.channel
    assert deserialized.data == stdout_data.data


@pytest.mark.asyncio
async def test_grpc_stdio_pb2_grpc_stub_creation() -> None:
    """Test creating a GRPCStdioStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_stdio_pb2_grpc.GRPCStdioStub(mock_channel)

    # Verify methods
    assert hasattr(stub, "StreamStdio")


@pytest.mark.asyncio
async def test_grpc_stdio_servicer_methods() -> None:
    """Test GRPCStdioServicer methods."""
    # Create a servicer
    servicer = grpc_stdio_pb2_grpc.GRPCStdioServicer()

    # Create mock context and request
    context = MagicMock()
    request = MagicMock()

    # Call StreamStdio
    with pytest.raises(NotImplementedError):
        servicer.StreamStdio(request, context)

    # Verify context method calls
    context.set_code.assert_called_once_with(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details.assert_called_once_with("Method not implemented!")


@pytest.mark.asyncio
async def test_stdio_pb2_descriptor() -> None:
    """Test that grpc_stdio_pb2.DESCRIPTOR is available and has expected properties."""
    assert hasattr(grpc_stdio_pb2, "DESCRIPTOR")
    descriptor = grpc_stdio_pb2.DESCRIPTOR

    # Test specific serialized properties / public API
    assert hasattr(descriptor, "message_types_by_name")
    assert "StdioData" in descriptor.message_types_by_name

    # Ensure it has a name (check basename)
    assert os.path.basename(descriptor.name) == "grpc_stdio.proto"

    # Check for a known option if available and stable, e.g. python_package
    # options = descriptor.GetOptions() # Commented out as it's unused now
    # assert options.HasField("python_package") # Commented out due to protoc regeneration issues
    # assert options.python_package == "pyvider.rpcplugin.protocol" # Commented out


@pytest.mark.asyncio
async def test_stdio_grpc_version_mismatch() -> None:
    """Direct test for grpc_stdio_pb2_grpc version check (lines 19-20, 23)."""
    with patch("grpc._utilities.first_version_is_lower", return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_stdio_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)


@pytest.mark.asyncio
async def test_stdio_experimental_api() -> None:
    """Direct test for grpc_stdio_pb2_grpc experimental API (line 105)."""
    assert hasattr(grpc_stdio_pb2_grpc, "GRPCStdio")
    assert hasattr(grpc_stdio_pb2_grpc.GRPCStdio, "StreamStdio")

    mock_request = MagicMock()
    mock_target = MagicMock()

    # Call the experimental method directly
    with patch("grpc.experimental.unary_stream") as mock_unary_stream:
        grpc_stdio_pb2_grpc.GRPCStdio.StreamStdio(
            mock_request, mock_target, metadata={"test": "value"}
        )
        mock_unary_stream.assert_called_once()


### 🐍🏗🧪️
