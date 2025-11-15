# tests/protocol/test_grpc_compatibility.py

import pytest
import importlib
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.protocol import (
    grpc_broker_pb2_grpc,
    grpc_controller_pb2_grpc,
    grpc_stdio_pb2_grpc,
)


async def test_add_servicers_to_server() -> None:
    """Test the add_*Servicer_to_server functions."""
    # Mock a server
    mock_server = MagicMock()

    # Create mock servicers
    broker_servicer = MagicMock(spec=grpc_broker_pb2_grpc.GRPCBrokerServicer)
    controller_servicer = MagicMock(
        spec=grpc_controller_pb2_grpc.GRPCControllerServicer
    )
    stdio_servicer = MagicMock(spec=grpc_stdio_pb2_grpc.GRPCStdioServicer)

    # Add servicers to server
    grpc_broker_pb2_grpc.add_GRPCBrokerServicer_to_server(broker_servicer, mock_server)
    grpc_controller_pb2_grpc.add_GRPCControllerServicer_to_server(
        controller_servicer, mock_server
    )
    grpc_stdio_pb2_grpc.add_GRPCStdioServicer_to_server(stdio_servicer, mock_server)

    # Verify that add_generic_rpc_handlers was called for each servicer
    assert mock_server.add_generic_rpc_handlers.call_count == 3
    assert mock_server.add_registered_method_handlers.call_count == 3


async def test_experimental_api() -> None:
    """Test the experimental API methods in the grpc_*_pb2_grpc modules."""
    # Just verify these objects exist and have the right methods
    assert hasattr(grpc_broker_pb2_grpc, "GRPCBroker")
    assert hasattr(grpc_broker_pb2_grpc.GRPCBroker, "StartStream")

    assert hasattr(grpc_controller_pb2_grpc, "GRPCController")
    assert hasattr(grpc_controller_pb2_grpc.GRPCController, "Shutdown")

    assert hasattr(grpc_stdio_pb2_grpc, "GRPCStdio")
    assert hasattr(grpc_stdio_pb2_grpc.GRPCStdio, "StreamStdio")


async def test_version_compatibility_check() -> None:
    """Test the version compatibility check code in the grpc modules."""
    # We'll simulate a version mismatch by patching first_version_is_lower
    with patch("grpc._utilities.first_version_is_lower", return_value=True):
        # Reimporting should raise RuntimeError
        with pytest.raises(RuntimeError):
            importlib.reload(grpc_broker_pb2_grpc)

    # Reset to normal behavior
    with patch("grpc._utilities.first_version_is_lower", return_value=False):
        # Should not raise
        importlib.reload(grpc_broker_pb2_grpc)


### 🐍🏗🧪️
