
# tests/protocol/test_grpc_broker.py

import pytest
import importlib
import grpc
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_broker_pb2,
    grpc_broker_pb2_grpc,
)

def test_grpc_broker_pb2_imports():
    """Test importing grpc_broker_pb2 and accessing its components."""
    # Access message descriptors
    assert hasattr(grpc_broker_pb2, 'DESCRIPTOR')

    # Test creating a ConnInfo message
    conn_info = grpc_broker_pb2.ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345"
    )
    assert conn_info.service_id == 1
    assert conn_info.network == "tcp"
    assert conn_info.address == "localhost:12345"

    # Test creating a Knock submessage
    knock = grpc_broker_pb2.ConnInfo.Knock(
        knock=True,
        ack=False,
        error=""
    )
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

def test_grpc_broker_pb2_grpc_stub_creation():
    """Test creating a GRPCBrokerStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_broker_pb2_grpc.GRPCBrokerStub(mock_channel)

    # Verify methods
    assert hasattr(stub, 'StartStream')

def test_grpc_broker_servicer_methods():
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


### 🐍🏗🧪️
