# tests/protocol/test_service_broker.py
"""Tests for broker service and subchannel functionality."""

from provide.testkit.mocking import MagicMock
import pytest

from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    SubchannelConnection,
)


@pytest.fixture
def subchannel() -> SubchannelConnection:
    """Fixture providing a SubchannelConnection instance."""
    return SubchannelConnection(conn_id=1, address="localhost:12345")


@pytest.fixture
def broker_service() -> GRPCBrokerService:
    """Fixture providing a GRPCBrokerService instance."""
    return GRPCBrokerService()


@pytest.fixture
def mock_context() -> MagicMock:
    """Mock gRPC context for broker."""
    context = MagicMock()
    context.add_done_callback = MagicMock()
    return context


class MockRequestIterator:
    """Mock request iterator for broker stream."""

    def __init__(self, requests: list[ConnInfo]) -> None:
        self.requests = requests
        self.index = 0

    def __aiter__(self) -> "MockRequestIterator":
        return self

    async def __anext__(self) -> ConnInfo:
        if self.index < len(self.requests):
            request = self.requests[self.index]
            self.index += 1
            return request
        raise StopAsyncIteration


@pytest.mark.asyncio
async def test_subchannel_open(subchannel: SubchannelConnection) -> None:
    """Test opening a subchannel connection."""
    subchannel.is_open = False
    assert not subchannel.is_open
    await subchannel.open()
    assert subchannel.is_open


@pytest.mark.asyncio
async def test_subchannel_close(subchannel: SubchannelConnection) -> None:
    """Test closing a subchannel connection."""
    await subchannel.open()
    assert subchannel.is_open
    await subchannel.close()
    assert not subchannel.is_open


@pytest.mark.asyncio
async def test_broker_start_stream_open_subchannel(
    broker_service: GRPCBrokerService, mock_context: MagicMock
) -> None:
    """Test StartStream with a knock request."""
    knock_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error=""),
    )
    request_iterator = MockRequestIterator([knock_info])
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)
    assert len(responses) == 1
    assert responses[0].service_id == 1
    assert responses[0].knock.ack is True
    assert responses[0].knock.error == ""
    assert 1 in broker_service._subchannels
    assert broker_service._subchannels[1].is_open


@pytest.mark.asyncio
async def test_broker_start_stream_close_subchannel(
    broker_service: GRPCBrokerService, mock_context: MagicMock
) -> None:
    """Test StartStream with a close request."""
    # First open a subchannel
    open_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error=""),
    )
    close_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=False, ack=False, error=""),
    )
    request_iterator = MockRequestIterator([open_info, close_info])
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)
    assert len(responses) == 2
    # First response opens the subchannel
    assert responses[0].knock.ack is True
    # Second response closes it
    assert responses[1].knock.ack is True
    assert 1 not in broker_service._subchannels


@pytest.mark.asyncio
async def test_broker_start_stream_exception(
    broker_service: GRPCBrokerService, mock_context: MagicMock
) -> None:
    """Test StartStream with an exception during processing."""
    # Create a request that will cause an exception
    invalid_info = ConnInfo(
        service_id=999,
        network="invalid",
        address="",
        knock=ConnInfo.Knock(knock=True, ack=False, error=""),
    )

    # Mock the subchannel creation to raise an exception
    original_method = broker_service._handle_subchannel_open

    async def mock_handle_open(*args: object, **kwargs: object) -> ConnInfo:
        raise Exception("Simulated error")

    broker_service._handle_subchannel_open = mock_handle_open

    request_iterator = MockRequestIterator([invalid_info])
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)

    # Should get a response with error
    assert len(responses) == 1
    assert responses[0].knock.ack is False
    assert "Simulated error" in responses[0].knock.error

    # Restore original method
    broker_service._handle_subchannel_open = original_method


@pytest.mark.asyncio
async def test_broker_service_subchannel_open_failure(
    broker_service: GRPCBrokerService, mock_context: MagicMock
) -> None:
    """Test broker service handling subchannel open failures."""
    # Create a knock request
    knock_info = ConnInfo(
        service_id=2,
        network="tcp",
        address="invalid:address",  # Invalid address should cause error
        knock=ConnInfo.Knock(knock=True, ack=False, error=""),
    )

    request_iterator = MockRequestIterator([knock_info])
    responses = []

    # Mock SubchannelConnection to raise an exception during open
    broker_service.__class__.__dict__.get("_create_subchannel")

    def mock_create_subchannel(service_id: int, address: str) -> SubchannelConnection:
        subchannel = SubchannelConnection(conn_id=service_id, address=address)

        async def failing_open() -> None:
            raise Exception("Connection failed")

        subchannel.open = failing_open  # type: ignore[method-assign]
        return subchannel

    broker_service._create_subchannel = mock_create_subchannel  # type: ignore[method-assign]

    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)

    assert len(responses) == 1
    assert responses[0].knock.ack is False
    assert "Connection failed" in responses[0].knock.error


@pytest.mark.asyncio
async def test_broker_exception_handling_subchannel_open_fails(
    broker_service: GRPCBrokerService, mock_context: MagicMock
) -> None:
    """Test broker handling when subchannel open fails with detailed error handling."""
    knock_info = ConnInfo(
        service_id=3,
        network="tcp",
        address="localhost:54321",
        knock=ConnInfo.Knock(knock=True, ack=False, error=""),
    )

    # Mock the entire subchannel creation and opening process
    async def mock_handle_subchannel_open(conn_info: ConnInfo) -> ConnInfo:
        # Simulate failure in subchannel opening
        response = ConnInfo(
            service_id=conn_info.service_id,
            network=conn_info.network,
            address=conn_info.address,
            knock=ConnInfo.Knock(knock=False, ack=False, error="Failed to establish subchannel connection"),
        )
        return response

    broker_service._handle_subchannel_open = mock_handle_subchannel_open  # type: ignore[method-assign]

    request_iterator = MockRequestIterator([knock_info])
    responses = []

    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)

    assert len(responses) == 1
    assert responses[0].knock.ack is False
    assert "Failed to establish subchannel connection" in responses[0].knock.error
    # Ensure subchannel wasn't added to the service
    assert 3 not in broker_service._subchannels
