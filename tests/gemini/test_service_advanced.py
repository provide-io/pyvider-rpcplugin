# tests/service_advanced.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from google.protobuf.empty_pb2 import Empty
import grpc


@pytest.fixture
def stdio_service_with_error():
    """Fixture providing a GRPCStdioService that raises errors on queue operations."""
    service = GRPCStdioService()

    # Mock the message queue to raise exceptions
    service._message_queue = MagicMock()
    service._message_queue.put = AsyncMock(side_effect=Exception("Queue error"))
    service._message_queue.get = AsyncMock(side_effect=Exception("Queue get error"))

    return service


@pytest.mark.asyncio
async def test_stdio_put_line_exception_handling(stdio_service_with_error) -> None:
    """Test GRPCStdioService.PutLine handling of exceptions."""
    mock_request_iterator = MagicMock()
    mock_request_iterator.__aiter__.return_value = [StdioData(data=b"test data\n")]
    mock_context = MagicMock()
    with pytest.raises(grpc.RpcError) as e:
        await stdio_service_with_error.PutLine(mock_request_iterator, mock_context)
    assert e.value.code() == grpc.StatusCode.UNKNOWN
    stdio_service_with_error._message_queue.put.assert_called_once() # Expecting only one call before exception


@pytest.mark.asyncio
async def test_stdio_get_line_exception_handling(stdio_service_with_error) -> None:
    """Test GRPCStdioService.GetLine handling of exceptions."""
    mock_context = MagicMock()
    with pytest.raises(grpc.RpcError) as e:
        await stdio_service_with_error.GetLine(Empty(), mock_context)
    assert e.value.code() == grpc.StatusCode.UNKNOWN
    stdio_service_with_error._message_queue.get.assert_called_once()


@pytest.mark.asyncio
async def test_broker_service_handle_subchannel_error() -> None:
    """Test GRPCBrokerService handling of subchannel errors."""
    service = GRPCBrokerService()
    mock_conn_info = ConnInfo(connection_id=1, address="localhost:12345")
    mock_context = MagicMock()
    with patch.object(service, '_subchannel_close') as mock_close:
        await service._handle_subchannel_error(mock_conn_info, mock_context)
        mock_close.assert_called_once_with(mock_conn_info.connection_id)
        mock_context.abort.assert_called_once_with(grpc.StatusCode.UNAVAILABLE, "Subchannel connection error")
