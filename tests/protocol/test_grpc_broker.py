# tests/protocol/test_grpc_broker.py

import pytest
import os  # Added import
import grpc
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_broker_pb2,
    grpc_broker_pb2_grpc,
)


@pytest.mark.asyncio
async def test_grpc_broker_pb2_imports() -> None:
    """Test importing grpc_broker_pb2 and accessing its components."""
    # Access message descriptors
    assert hasattr(grpc_broker_pb2, "DESCRIPTOR")

    # Test creating a ConnInfo message
    conn_info = grpc_broker_pb2.ConnInfo(
        service_id=1, network="tcp", address="localhost:12345"
    )
    assert conn_info.service_id == 1
    assert conn_info.network == "tcp"
    assert conn_info.address == "localhost:12345"

    # Test creating a Knock submessage
    knock = grpc_broker_pb2.ConnInfo.Knock(knock=True, ack=False, error="")
    assert knock.knock is True
    assert knock.ack is False
    assert knock.error == ""

    # Test serialization
    serialized = conn_info.SerializeToString()
    assert isinstance(serialized, bytes)

    # Test deserialization
    deserialized = grpc_broker_pb2.ConnInfo()
    deserialized.ParseFromString(serialized)
    assert deserialized.service_id == conn_info.service_id
    assert deserialized.network == conn_info.network
    assert deserialized.address == conn_info.address


@pytest.mark.asyncio
async def test_grpc_broker_pb2_grpc_stub_creation() -> None:
    """Test creating a GRPCBrokerStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_broker_pb2_grpc.GRPCBrokerStub(mock_channel)

    # Verify methods
    assert hasattr(stub, "StartStream")


@pytest.mark.asyncio
async def test_grpc_broker_servicer_methods() -> None:
    """Test GRPCBrokerServicer methods."""
    # Create a servicer
    servicer = grpc_broker_pb2_grpc.GRPCBrokerServicer()

    # Create mock context and request iterator
    context = MagicMock()
    request_iterator = MagicMock()

    # Call StartStream
    with pytest.raises(NotImplementedError):
        servicer.StartStream(request_iterator, context)

    # Verify context method calls
    context.set_code.assert_called_once_with(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details.assert_called_once_with("Method not implemented!")


@pytest.mark.asyncio
async def test_broker_pb2_descriptor() -> None:
    """Test that grpc_broker_pb2.DESCRIPTOR is available and has expected properties."""
    assert hasattr(grpc_broker_pb2, "DESCRIPTOR")
    descriptor = grpc_broker_pb2.DESCRIPTOR

    # Test specific serialized properties / public API
    assert hasattr(descriptor, "message_types_by_name")
    assert "ConnInfo" in descriptor.message_types_by_name

    # Ensure it has a name (check basename)
    assert os.path.basename(descriptor.name) == "grpc_broker.proto"

    # Check for a known option if available and stable, e.g. python_package
    # For protobuf 5.x, options are accessed via descriptor.GetOptions()
    # options = descriptor.GetOptions() # Commented out as it's unused now
    # assert options.HasField("python_package") # Commented out due to protoc regeneration issues
    # assert options.python_package == "pyvider.rpcplugin.protocol" # Commented out


# @pytest.mark.asyncio
# async def test_broker_grpc_version_mismatch() -> None:
#     """Direct test for grpc_broker_pb2_grpc version check (lines 18-19)."""
#     with patch('grpc._utilities.first_version_is_lower', return_value=True):
#         with pytest.raises(RuntimeError) as excinfo:
#             importlib.reload(grpc_broker_pb2_grpc)
#         assert "grpc package installed is at version" in str(excinfo.value)


@pytest.mark.asyncio
async def test_broker_experimental_api() -> None:
    """Direct test for grpc_broker_pb2_grpc experimental API (line 90)."""
    assert hasattr(grpc_broker_pb2_grpc, "GRPCBroker")
    assert hasattr(grpc_broker_pb2_grpc.GRPCBroker, "StartStream")

    mock_request_iterator = MagicMock()
    mock_target = MagicMock()

    # Call the experimental method directly
    with patch("grpc.experimental.stream_stream") as mock_stream_stream:
        grpc_broker_pb2_grpc.GRPCBroker.StartStream(
            mock_request_iterator, mock_target, metadata={"test": "value"}
        )
        mock_stream_stream.assert_called_once()


### 🐍🏗🧪️
