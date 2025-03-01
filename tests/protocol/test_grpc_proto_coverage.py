
# tests/protocol/test_grpc_proto_coverage.py

import pytest
from unittest.mock import MagicMock, patch
import grpc
import importlib

from pyvider.rpcplugin.protocol import (
    grpc_broker_pb2,
    grpc_broker_pb2_grpc,
    grpc_controller_pb2,
    grpc_controller_pb2_grpc,
    grpc_stdio_pb2,
    grpc_stdio_pb2_grpc,
)


def test_grpc_proto_descriptors():
    """Test accessing proto descriptors from all proto modules."""
    assert hasattr(grpc_broker_pb2, "DESCRIPTOR")
    assert hasattr(grpc_controller_pb2, "DESCRIPTOR")
    assert hasattr(grpc_stdio_pb2, "DESCRIPTOR")

    # Access specific loaded options
    if not grpc_broker_pb2.DESCRIPTOR._USE_C_DESCRIPTORS:
        assert "_CONNINFO" in grpc_broker_pb2._globals
        assert "_GRPCBROKER" in grpc_broker_pb2._globals

    if not grpc_controller_pb2.DESCRIPTOR._USE_C_DESCRIPTORS:
        assert "_EMPTY" in grpc_controller_pb2._globals
        assert "_GRPCCONTROLLER" in grpc_controller_pb2._globals

    if not grpc_stdio_pb2.DESCRIPTOR._USE_C_DESCRIPTORS:
        assert "_STDIODATA" in grpc_stdio_pb2._globals
        assert "_GRPCSTDIO" in grpc_stdio_pb2._globals


def test_grpc_stub_creation():
    """Test creating stubs from gRPC classes."""
    mock_channel = MagicMock()

    # Create stubs
    broker_stub = grpc_broker_pb2_grpc.GRPCBrokerStub(mock_channel)
    controller_stub = grpc_controller_pb2_grpc.GRPCControllerStub(mock_channel)
    stdio_stub = grpc_stdio_pb2_grpc.GRPCStdioStub(mock_channel)

    # Verify methods
    assert hasattr(broker_stub, "StartStream")
    assert hasattr(controller_stub, "Shutdown")
    assert hasattr(stdio_stub, "StreamStdio")


def test_grpc_version_check():
    """Test the gRPC version compatibility check."""
    # Force a version mismatch
    with patch("grpc._utilities.first_version_is_lower", return_value=True):
        # Reload should raise RuntimeError due to version mismatch
        with pytest.raises(RuntimeError):
            importlib.reload(grpc_broker_pb2_grpc)

    # Reset to normal behavior
    with patch("grpc._utilities.first_version_is_lower", return_value=False):
        # Should not raise
        importlib.reload(grpc_broker_pb2_grpc)


def test_grpc_add_handlers_to_server():
    """Test adding handlers to server."""
    mock_server = MagicMock()

    # Create mock servicers
    broker_servicer = MagicMock()
    controller_servicer = MagicMock()
    stdio_servicer = MagicMock()

    # Add servicers to server
    grpc_broker_pb2_grpc.add_GRPCBrokerServicer_to_server(broker_servicer, mock_server)
    grpc_controller_pb2_grpc.add_GRPCControllerServicer_to_server(controller_servicer, mock_server)
    grpc_stdio_pb2_grpc.add_GRPCStdioServicer_to_server(stdio_servicer, mock_server)

    # Verify calls to server's registration methods
    assert mock_server.add_generic_rpc_handlers.call_count == 3
    assert mock_server.add_registered_method_handlers.call_count == 3

### 🐍🏗🧪️
