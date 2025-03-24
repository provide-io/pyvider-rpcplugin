# tests/protocol/test_service_improvements.py
import asyncio
import pytest
import signal
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
import grpc


@pytest.mark.asyncio
async def test_stdio_put_line_exception_handling() -> None:
    """Test GRPCStdioService.PutLine handling of exceptions."""
    service = GRPCStdioService()
    service._message_queue = AsyncMock()
    service._message_queue.put.side_effect = Exception("Queue error")
    mock_request_iterator = MagicMock()
    mock_request_iterator.__aiter__.return_value = [StdioData(data=b"test data\n")]
    mock_context = MagicMock()
    with pytest.raises(grpc.RpcError) as e:
        await service.PutLine(mock_request_iterator, mock_context)
    assert e.value.code() == grpc.StatusCode.UNKNOWN
    service._message_queue.put.assert_called_once()


@pytest.mark.asyncio
async def test_broker_service_start_stream_error_handling() -> None:
    """Test GRPCBrokerService.StartStream error handling."""
    service = GRPCBrokerService()
    mock_request_iterator = MagicMock()
    mock_request_iterator.__aiter__.side_effect = Exception("Iterator error")
    with pytest.raises(grpc.RpcError) as e:
        await service.StartStream(mock_request_iterator, None)
    assert e.value.code() == grpc.StatusCode.UNKNOWN
