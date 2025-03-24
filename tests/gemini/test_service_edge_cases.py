# tests/service_edge_cases.py
import asyncio
import pytest
from unittest.mock import MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    GRPCBrokerService,
    SubchannelConnection,
    BrokerError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from google.protobuf.empty_pb2 import Empty
import grpc

class MockRequestIterator:
    """Mock request iterator for broker stream."""
    def __init__(self, requests) -> None:
        self.requests = asyncio.Queue()
        for req in requests:
            self.requests.put_nowait(req)
        self._cancelled = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._cancelled and self.requests.empty():
            raise StopAsyncIteration
        try:
            return await self.requests.get()
        except asyncio.CancelledError:
            raise StopAsyncIteration

    async def cancel(self):
        self._cancelled = True

    def put(self, request):
        self.requests.put_nowait(request)

from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_broker_service_subchannel_open_failure() -> None:
    """Test broker service handling of subchannel open failure."""
    service = GRPCBrokerService()
    subchannel = SubchannelConnection(conn_id=1, address="localhost:12345")
    mock_open_func = AsyncMock(side_effect=Exception("Open failed"))
    with patch.object(subchannel, 'open', mock_open_func):
        with pytest.raises(BrokerError) as excinfo:
            await service._subchannel_open(subchannel)
        mock_open_func.assert_called_once()
        assert not subchannel.is_open
        assert "Failed to open subchannel" in str(excinfo.value)


@pytest.mark.asyncio
async def test_stdio_service_timeouts() -> None:
    """Test stdio service handling of timeouts."""
    service = GRPCStdioService()
    service._message_queue = AsyncMock()
    service._message_queue.get.side_effect = asyncio.TimeoutError()
    mock_context = MagicMock()
    response = await service.get_line(Empty(), mock_context)
    assert response.data == b"" # Expect empty response on timeout


@pytest.mark.asyncio
async def test_broker_exception_handling_line95() -> None:
    """Test broker StartStream handling of exceptions in the request iterator."""
    service = GRPCBrokerService()
    mock_request_iterator = MockRequestIterator([ConnInfo(connection_id=1)])
    mock_request_iterator.__aiter__.side_effect = Exception("Iterator error")
    with pytest.raises(grpc.RpcError) as e:
        await service.StartStream(mock_request_iterator, None)
    assert e.value.code() == grpc.StatusCode.UNKNOWN
