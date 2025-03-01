
# tests/protocol/test_service.py

import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import grpc

from pyvider.rpcplugin.protocol.service import (
    BrokerError,
    SubchannelConnection, 
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from google.protobuf.empty_pb2 import Empty

@pytest.fixture
def subchannel():
    """Fixture providing a SubchannelConnection instance."""
    return SubchannelConnection(conn_id=1, address="localhost:12345")

@pytest.mark.asyncio
async def test_subchannel_open(subchannel):
    """Test opening a subchannel connection."""
    assert not subchannel.is_open
    await subchannel.open()
    assert subchannel.is_open

@pytest.mark.asyncio
async def test_subchannel_close(subchannel):
    """Test closing a subchannel connection."""
    await subchannel.open()
    assert subchannel.is_open
    await subchannel.close()
    assert not subchannel.is_open

class MockRequestIterator:
    """Mock request iterator for broker stream."""
    def __init__(self, requests):
        self.requests = requests
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index < len(self.requests):
            request = self.requests[self.index]
            self.index += 1
            return request
        raise StopAsyncIteration

@pytest.fixture
def broker_service():
    """Fixture providing a GRPCBrokerService instance."""
    return GRPCBrokerService()

@pytest.fixture
def mock_context():
    """Mock gRPC context for broker."""
    context = MagicMock()
    context.add_done_callback = MagicMock()
    return context

@pytest.mark.asyncio
async def test_broker_start_stream_open_subchannel(broker_service, mock_context):
    """Test StartStream with a knock request."""
    # Create a request with knock=True
    knock_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )
    
    # Create request iterator with single knock request
    request_iterator = MockRequestIterator([knock_info])
    
    # Collect responses
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)
    
    # Verify response
    assert len(responses) == 1
    assert responses[0].service_id == 1
    assert responses[0].knock.ack == True
    assert responses[0].knock.error == ""
    
    # Verify subchannel was created
    assert 1 in broker_service._subchannels
    assert broker_service._subchannels[1].is_open

@pytest.mark.asyncio
async def test_broker_start_stream_close_subchannel(broker_service, mock_context):
    """Test StartStream with closing an existing subchannel."""
    # First create a subchannel
    subchan = SubchannelConnection(1, "localhost:12345")
    await subchan.open()
    broker_service._subchannels[1] = subchan
    
    # Create a request to close it (knock=False)
    close_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=False, ack=False, error="")
    )
    
    # Create request iterator with single close request
    request_iterator = MockRequestIterator([close_info])
    
    # Collect responses
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)
    
    # Verify response
    assert len(responses) == 1
    assert responses[0].service_id == 1
    assert responses[0].knock.ack == True
    
    # Verify subchannel was removed
    assert 1 not in broker_service._subchannels

@pytest.mark.asyncio
async def test_broker_start_stream_exception(broker_service, mock_context):
    """Test StartStream with an exception during processing."""
    # Create a request that will cause an exception
    with patch.object(broker_service, '_subchannels', side_effect=Exception("Test exception")):
        knock_info = ConnInfo(
            service_id=1,
            network="tcp",
            address="localhost:12345",
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )
        
        # Create request iterator with request that will cause exception
        request_iterator = MockRequestIterator([knock_info])
        
        # Collect responses
        responses = []
        async for response in broker_service.StartStream(request_iterator, mock_context):
            responses.append(response)
        
        # Verify error response
        assert len(responses) == 1
        assert responses[0].service_id == 0
        assert responses[0].knock.ack == False
        assert "error" in responses[0].knock.error
