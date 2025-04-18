# tests/protocol/test_service.py

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    SubchannelConnection,
    GRPCBrokerService,
    GRPCStdioService,
    BrokerError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData

@pytest.fixture
def subchannel():
    """Fixture providing a SubchannelConnection instance."""
    return SubchannelConnection(conn_id=1, address="localhost:12345")

@pytest.mark.asyncio
async def test_subchannel_open(subchannel) -> None:
    """Test opening a subchannel connection."""
    assert not subchannel.is_open
    subchannel._is_open = True # Simulate opening
    assert subchannel.is_open

@pytest.mark.asyncio
async def test_subchannel_close(subchannel) -> None:
    """Test closing a subchannel connection."""
    subchannel._is_open = True
    assert subchannel.is_open
    await subchannel.close()
    assert not subchannel.is_open

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


@pytest.mark.asyncio
async def test_broker_service_subchannel_open(subchannel) -> None:
    """Test broker service handling of subchannel open."""
    service = GRPCBrokerService()
    service._subchannels[subchannel.conn_id] = subchannel
    mock_open_func = AsyncMock()
    with patch.object(subchannel, 'open', mock_open_func):
        await service._handle_subchannel_open(ConnInfo(connection_id=subchannel.conn_id, address=subchannel.address))
        mock_open_func.assert_called_once()
        assert subchannel.is_open


@pytest.mark.asyncio
async def test_broker_service_subchannel_open_failure() -> None:
    """Test broker service handling of subchannel open failure."""
    subchannel = SubchannelConnection(conn_id=1, address="localhost:12345")
    service = GRPCBrokerService()
    service._subchannels[subchannel.conn_id] = subchannel
    mock_open_func = AsyncMock(side_effect=Exception("Open failed"))
    with patch.object(subchannel, 'open', mock_open_func):
        with pytest.raises(BrokerError) as excinfo:
            await service._handle_subchannel_open(ConnInfo(connection_id=subchannel.conn_id, address=subchannel.address))
        mock_open_func.assert_called_once()
        assert not subchannel.is_open
        assert "Failed to open subchannel" in str(excinfo.value)


@pytest.mark.asyncio
async def test_broker_start_stream_exception() -> None:
    """Test broker StartStream handling of exceptions in the request iterator."""
    service = GRPCBrokerService()
    mock_request_iterator = MockRequestIterator([ConnInfo(connection_id=1, address="localhost:12345")])
    mock_request_iterator.__aiter__.side_effect = Exception("Iterator error")
    with pytest.raises(grpc.RpcError) as e:
        await service.StartStream(mock_request_iterator, None)
    assert e.value.code() == grpc.StatusCode.UNKNOWN


@pytest.mark.asyncio
async def test_stdio_stream_stdio() -> None:
    """Test the stdio stream implementation."""
    service = GRPCStdioService()
    mock_context = MagicMock()
    mock_context.write = AsyncMock()
    async def mock_request_iterator():
        yield StdioData(data=b"line1\n")
        yield StdioData(data=b"line2\n")
    request_iter = mock_request_iterator()
    await service.StreamStdio(request_iter, mock_context)
    calls = [call[0][0].data for call in mock_context.write.call_args_list]
    assert calls == [b"line1\n", b"line2\n"]
