
# tests/protocol/test_grpc_compatibility.py

import pytest
import importlib
import grpc
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_broker_pb2,
    grpc_broker_pb2_grpc,
    grpc_controller_pb2,
    grpc_controller_pb2_grpc,
    grpc_stdio_pb2,
    grpc_stdio_pb2_grpc,
)

# broker

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

# controller

def test_grpc_controller_pb2_imports():
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

def test_grpc_controller_pb2_grpc_stub_creation():
    """Test creating a GRPCControllerStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_controller_pb2_grpc.GRPCControllerStub(mock_channel)

    # Verify methods
    assert hasattr(stub, 'Shutdown')

def test_grpc_controller_servicer_methods():
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

def test_broker_grpc_version_mismatch():
    """Direct test for grpc_broker_pb2_grpc version check (lines 18-19)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_broker_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

def test_controller_pb2_descriptor():
    """Direct test for grpc_controller_pb2 descriptor options (lines 30-34)."""
    assert hasattr(grpc_controller_pb2, "DESCRIPTOR")
    with patch.object(grpc_controller_pb2.DESCRIPTOR, "_loaded_options", None), \
         patch.object(grpc_controller_pb2.DESCRIPTOR, "_USE_C_DESCRIPTORS", False):
        importlib.reload(grpc_controller_pb2)
    
    descriptor = grpc_controller_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "Empty" in descriptor.message_types_by_name

def test_controller_grpc_version_mismatch():
    """Direct test for grpc_controller_pb2_grpc version check (lines 18-19, 22)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_controller_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

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

# stdio

def test_grpc_stdio_pb2_imports():
    """Test importing grpc_stdio_pb2 and accessing its components."""
    # Access message descriptors
    assert hasattr(grpc_stdio_pb2, 'DESCRIPTOR')

    # Test creating a StdioData message with STDOUT channel
    stdout_data = grpc_stdio_pb2.StdioData(
        channel=grpc_stdio_pb2.StdioData.STDOUT,
        data=b"test stdout data"
    )
    assert stdout_data.channel == grpc_stdio_pb2.StdioData.STDOUT
    assert stdout_data.data == b"test stdout data"

    # Test creating a StdioData message with STDERR channel
    stderr_data = grpc_stdio_pb2.StdioData(
        channel=grpc_stdio_pb2.StdioData.STDERR,
        data=b"test stderr data"
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

def test_grpc_stdio_pb2_grpc_stub_creation():
    """Test creating a GRPCStdioStub."""
    # Mock a channel
    mock_channel = MagicMock()

    # Try to create a stub
    stub = grpc_stdio_pb2_grpc.GRPCStdioStub(mock_channel)

    # Verify methods
    assert hasattr(stub, 'StreamStdio')

def test_grpc_stdio_servicer_methods():
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

def test_stdio_pb2_descriptor():
    """Direct test for grpc_stdio_pb2 descriptor options (lines 32-38)."""
    assert hasattr(grpc_stdio_pb2, "DESCRIPTOR")
    with patch.object(grpc_stdio_pb2.DESCRIPTOR, "_loaded_options", None), \
         patch.object(grpc_stdio_pb2.DESCRIPTOR, "_USE_C_DESCRIPTORS", False):
        importlib.reload(grpc_stdio_pb2)
    
    descriptor = grpc_stdio_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "StdioData" in descriptor.message_types_by_name

def test_stdio_grpc_version_mismatch():
    """Direct test for grpc_stdio_pb2_grpc version check (lines 19-20, 23)."""
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        with pytest.raises(RuntimeError) as excinfo:
            importlib.reload(grpc_stdio_pb2_grpc)
        assert "grpc package installed is at version" in str(excinfo.value)

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

###

def test_add_servicers_to_server():
    """Test the add_*Servicer_to_server functions."""
    # Mock a server
    mock_server = MagicMock()

    # Create mock servicers
    broker_servicer = MagicMock(spec=grpc_broker_pb2_grpc.GRPCBrokerServicer)
    controller_servicer = MagicMock(spec=grpc_controller_pb2_grpc.GRPCControllerServicer)
    stdio_servicer = MagicMock(spec=grpc_stdio_pb2_grpc.GRPCStdioServicer)

    # Add servicers to server
    grpc_broker_pb2_grpc.add_GRPCBrokerServicer_to_server(broker_servicer, mock_server)
    grpc_controller_pb2_grpc.add_GRPCControllerServicer_to_server(controller_servicer, mock_server)
    grpc_stdio_pb2_grpc.add_GRPCStdioServicer_to_server(stdio_servicer, mock_server)

    # Verify that add_generic_rpc_handlers was called for each servicer
    assert mock_server.add_generic_rpc_handlers.call_count == 3
    assert mock_server.add_registered_method_handlers.call_count == 3

def test_experimental_api():
    """Test the experimental API methods in the grpc_*_pb2_grpc modules."""
    # Just verify these objects exist and have the right methods
    assert hasattr(grpc_broker_pb2_grpc, 'GRPCBroker')
    assert hasattr(grpc_broker_pb2_grpc.GRPCBroker, 'StartStream')

    assert hasattr(grpc_controller_pb2_grpc, 'GRPCController')
    assert hasattr(grpc_controller_pb2_grpc.GRPCController, 'Shutdown')

    assert hasattr(grpc_stdio_pb2_grpc, 'GRPCStdio')
    assert hasattr(grpc_stdio_pb2_grpc.GRPCStdio, 'StreamStdio')

def test_version_compatibility_check():
    """Test the version compatibility check code in the grpc modules."""
    # We'll simulate a version mismatch by patching first_version_is_lower
    with patch('grpc._utilities.first_version_is_lower', return_value=True):
        # Reimporting should raise RuntimeError
        with pytest.raises(RuntimeError):
            importlib.reload(grpc_broker_pb2_grpc)

    # Reset to normal behavior
    with patch('grpc._utilities.first_version_is_lower', return_value=False):
        # Should not raise
        importlib.reload(grpc_broker_pb2_grpc)

### 🐍🏗🧪️
