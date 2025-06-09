# tests/protocol/test_service_advanced.py

import asyncio
import signal
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

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
from google.protobuf.empty_pb2 import Empty


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
async def test_stdio_error_handling_in_put_line(stdio_service_with_error) -> None:
    """Test that put_line gracefully handles exceptions."""
    # This should not raise an exception even though queue.put will fail
    await stdio_service_with_error.put_line(b"test data")

    # Verify put was called
    stdio_service_with_error._message_queue.put.assert_called_once()

# test_stdio_stream_error_handling removed, moved to test_service.py

# test_stdio_stream_cancellation_handling removed, functionality covered by test_service.py::test_stdio_stream_cancellation
# MockRequestIterator (if present below this line and only used by removed tests) will be removed later if file becomes empty or it's confirmed unused.

@pytest.mark.asyncio
async def test_broker_service_exception_handling() -> None:
    """Test that StartStream properly handles exceptions."""
    service = GRPCBrokerService()

    # Create a subchannel that raises an exception
    mock_subchannel = MagicMock(spec=SubchannelConnection)
    mock_subchannel.open = AsyncMock(side_effect=BrokerError("Failed to open subchannel"))

    # Add the subchannel to the service
    service._subchannels = {}

    # Create a request that will try to use this subchannel
    knock_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )

    # Mock the subchannel creation to return our problematic subchannel

    class MockSubchannelConnection:
        def __init__(self, conn_id, address):
            self.conn_id = conn_id
            self.address = address
            self.is_open = False

        async def open(self):
            raise BrokerError("Failed to open subchannel")

        async def close(self):
            pass

    # Patch SubchannelConnection
    with patch('pyvider.rpcplugin.protocol.service.SubchannelConnection', MockSubchannelConnection):
        # Create request iterator
        # Assuming MockRequestIterator is defined elsewhere or this test needs it.
        # If MockRequestIterator was defined in this file and is now unused by other tests, it should be removed.
        # For now, let's assume it's available or will be handled.
        # If it was defined above the removed test_stdio_stream_cancellation_handling,
        # it might still be here.
        class LocalMockRequestIterator: # Define locally if needed for this test only
            def __init__(self, requests) -> None:
                self.requests = requests
                self.index = 0

            def __aiter__(self) -> "LocalMockRequestIterator":
                return self

            async def __anext__(self):
                if self.index < len(self.requests):
                    request = self.requests[self.index]
                    self.index += 1
                    return request
                raise StopAsyncIteration
        request_iterator = LocalMockRequestIterator([knock_info])


        # Collect responses
        responses = []
        context = MagicMock()
        async for response in service.StartStream(request_iterator, context):
            responses.append(response)

        # Check for error response
        assert len(responses) == 1
        assert responses[0].knock.ack is False
        assert "Failed to open subchannel" in responses[0].knock.error or "Broker error" in responses[0].knock.error

# test_controller_delayed_shutdown_signal_handlers removed, moved to test_service.py

@pytest.mark.asyncio
async def test_register_protocol_service_with_mocks() -> None:
    """Test registering all services with detailed verification."""
    # Mock the services and their add_*_to_server functions
    with patch('pyvider.rpcplugin.protocol.service.GRPCStdioService') as mock_stdio_cls, \
         patch('pyvider.rpcplugin.protocol.service.GRPCBrokerService') as mock_broker_cls, \
         patch('pyvider.rpcplugin.protocol.service.GRPCControllerService') as mock_controller_cls, \
         patch('pyvider.rpcplugin.protocol.service.add_GRPCStdioServicer_to_server') as mock_add_stdio, \
         patch('pyvider.rpcplugin.protocol.service.add_GRPCBrokerServicer_to_server') as mock_add_broker, \
         patch('pyvider.rpcplugin.protocol.service.add_GRPCControllerServicer_to_server') as mock_add_controller:

        # Setup the mocks
        mock_stdio = MagicMock()
        mock_broker = MagicMock()
        mock_controller = MagicMock()

        mock_stdio_cls.return_value = mock_stdio
        mock_broker_cls.return_value = mock_broker
        mock_controller_cls.return_value = mock_controller

        # Mock server
        mock_server = MagicMock()

        # Mock shutdown event
        mock_shutdown_event = MagicMock(spec=asyncio.Event)

        # Call register_protocol_service
        register_protocol_service(mock_server, mock_shutdown_event)

        # Verify service instantiation
        mock_stdio_cls.assert_called_once()
        mock_broker_cls.assert_called_once()
        mock_controller_cls.assert_called_once_with(mock_shutdown_event, mock_stdio)

        # Verify services were added to server
        mock_add_stdio.assert_called_once_with(mock_stdio, mock_server)
        mock_add_broker.assert_called_once_with(mock_broker, mock_server)
        mock_add_controller.assert_called_once_with(mock_controller, mock_server)

### 🐍🏗🧪️
