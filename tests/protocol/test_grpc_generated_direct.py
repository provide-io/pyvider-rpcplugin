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

    # Test specific serialized properties
    descriptor = grpc_broker_pb2.DESCRIPTOR
    assert hasattr(descriptor, "message_types_by_name")
    assert "ConnInfo" in descriptor.message_types_by_name

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
