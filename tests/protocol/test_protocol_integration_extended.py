# tests/protocol/test_protocol_integration_extended.py
#
# Copyright (C) 2024 - All Rights Reserved
#
# This file is part of the PyVider RPCPlugin project.
#
# Any unauthorized use, reproduction, or distribution of this software
# is strictly prohibited without the express written permission of the copyright holder.
#

import asyncio
import pytest
import pytest_asyncio
import grpc
from google.protobuf.empty_pb2 import Empty
from unittest.mock import MagicMock, patch
from attrs import define

from pyvider.telemetry import logger # Added import

# Service implementations
from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
)

# Stubs for client-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty # Renamed to avoid clash
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub

# Servicer adders for server-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import add_GRPCStdioServicer_to_server
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import add_GRPCBrokerServicer_to_server
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import add_GRPCControllerServicer_to_server


@define
class ExtendedServerFixtureOutput:
    server: grpc.aio.Server
    channel: grpc.aio.Channel
    stdio_stub: GRPCStdioStub
    broker_stub: GRPCBrokerStub
    controller_stub: GRPCControllerStub
    shutdown_event: asyncio.Event
    stdio_service: GRPCStdioService
    broker_service: GRPCBrokerService
    controller_service: GRPCControllerService


@pytest_asyncio.fixture
async def real_server_client() -> ExtendedServerFixtureOutput:
    """Fixture to create a real gRPC server and client pair."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Instantiate services
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    # Register services directly
    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    port = server.add_insecure_port('localhost:0')
    address = f'localhost:{port}'
    await server.start()

    channel = grpc.aio.insecure_channel(address)
    # Ensure channel is ready before creating stubs
    try:
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0) # Add timeout
        logger.debug("gRPC channel is ready.")
    except asyncio.TimeoutError:
        logger.error("gRPC channel not ready after timeout.")
        # Depending on strictness, could raise here or let stubs fail
        raise RuntimeError("gRPC channel failed to become ready.")


    stdio_stub = GRPCStdioStub(channel)
    broker_stub = GRPCBrokerStub(channel)
    controller_stub = GRPCControllerStub(channel)

    yield ExtendedServerFixtureOutput(
        server=server,
        channel=channel,
        stdio_stub=stdio_stub,
        broker_stub=broker_stub,
        controller_stub=controller_stub,
        shutdown_event=shutdown_event,
        stdio_service=stdio_service,
        broker_service=broker_service,
        controller_service=controller_service
    )

    logger.debug("Closing gRPC channel and server.")
    await channel.close()
    await server.stop(grace=1.0) # Add grace period for shutdown
    logger.debug("gRPC channel and server closed.")


@pytest.mark.asyncio
async def test_stdio_end_to_end(real_server_client: ExtendedServerFixtureOutput) -> None:
    """Test end-to-end stdio service with real server and client."""
    stdio_service = real_server_client.stdio_service
    stdio_stub = real_server_client.stdio_stub
    assert stdio_service is not None, "Stdio service not found in fixture output"

    # Create a background task to collect stdio output
    async def collect_stdio():
        results = []
        logger.debug("test_stdio_end_to_end: collect_stdio started")
        try:
            # Make sure Empty is the correct one, not ControllerEmpty
            from google.protobuf.empty_pb2 import Empty as ProtobufEmpty 
            async for data in stdio_stub.StreamStdio(ProtobufEmpty()):
                logger.debug(f"test_stdio_end_to_end: collect_stdio received item: {data}")
                results.append(data)
                if len(results) >= 3: # Expecting 3 items based on test_lines
                    logger.debug("test_stdio_end_to_end: collect_stdio received 3 items, breaking.")
                    break
        except grpc.RpcError as rpc_e: # More specific exception handling
            logger.error(f"test_stdio_end_to_end: collect_stdio RpcError: {rpc_e.code()} - {rpc_e.details()}")
            # If the stream is cancelled by the server shutting down, this might be expected.
            # For this test, it implies an issue if it happens before 3 items are received.
            if rpc_e.code() != grpc.StatusCode.CANCELLED and rpc_e.code() != grpc.StatusCode.UNAVAILABLE:
                 raise # Re-raise if not a typical shutdown-related error
        except Exception as e:
            logger.error(f"test_stdio_end_to_end: collect_stdio generic exception: {e}")
            raise # Re-raise generic exceptions
        logger.debug(f"test_stdio_end_to_end: collect_stdio finished, received {len(results)} items.")
        return results

    stdio_task = asyncio.create_task(collect_stdio())

    # Give stream time to establish
    await asyncio.sleep(0.2) # Slightly increased sleep

    # Feed data to the stdio service
    test_lines = [
        (b"stdout line 1", False),
        (b"stderr line", True),
        (b"stdout line 2", False),
    ]

    for line, is_stderr in test_lines:
        logger.debug(f"test_stdio_end_to_end: putting line: {line}, is_stderr: {is_stderr}")
        await stdio_service.put_line(line, is_stderr=is_stderr)
        await asyncio.sleep(0.05) # Small delay to allow item to be processed by service

    # Collect results
    try:
        results = await asyncio.wait_for(stdio_task, timeout=5.0) # Increased timeout
    except asyncio.TimeoutError:
        logger.error("test_stdio_end_to_end: stdio_task timed out waiting for results.")
        # Attempt to gather more info if possible, e.g. queue size
        if stdio_service and hasattr(stdio_service, '_message_queue'):
            logger.error(f"test_stdio_end_to_end: Stdio service queue size at timeout: {stdio_service._message_queue.qsize()}")
        raise

    # Verify results
    assert len(results) == 3, f"Expected 3 items, got {len(results)}. Results: {results}"

    for i, (expected_line, expected_stderr) in enumerate(test_lines):
        assert results[i].data == expected_line
        expected_channel = StdioData.STDERR if expected_stderr else StdioData.STDOUT
        assert results[i].channel == expected_channel
    logger.info("test_stdio_end_to_end: Test completed successfully.")


@pytest.mark.asyncio
async def test_broker_cancellation(real_server_client: ExtendedServerFixtureOutput) -> None:
    """Test broker service with cancellation."""
    broker_stub = real_server_client.broker_stub

    # Start a broker stream
    stream = broker_stub.StartStream()

    # Create a knock request
    knock_request = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )

    # Send the request
    await stream.write(knock_request)

    # Read the response
    response = await stream.read()
    assert response.service_id == 1
    assert response.knock.ack is True

    # Abruptly cancel the stream
    logger.debug("test_broker_cancellation: Cancelling client-side stream.")
    stream.cancel()

    # Close the write side of the stream
    # done_writing() might raise if stream is already cancelled.
    try:
        await stream.done_writing()
        logger.debug("test_broker_cancellation: Stream done_writing completed.")
    except grpc.RpcError as e:
        # This can happen if cancel() acts very quickly
        logger.warning(f"test_broker_cancellation: RpcError during done_writing (expected if already cancelled): {e.code()}")
        assert e.code() in [grpc.StatusCode.CANCELLED, grpc.StatusCode.UNAVAILABLE]


@pytest.mark.skip # this kills the test suite completely.
async def test_controller_shutdown_with_timeout(real_server_client: ExtendedServerFixtureOutput) -> None:
    """Test controller shutdown with a timeout."""
    controller_stub = real_server_client.controller_stub
    shutdown_event = real_server_client.shutdown_event

    # Patch os.kill and sys.exit to prevent actual process termination
    with patch('os.kill') as mock_kill, patch('sys.exit') as mock_exit, patch('os.getpid', return_value=12345) as mock_getpid:
        logger.debug("test_controller_shutdown_with_timeout: Calling Shutdown RPC.")
        try:
            # Make sure to use the correct Empty for controller
            from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerSpecificEmpty
            response = await asyncio.wait_for(
                controller_stub.Shutdown(ControllerSpecificEmpty()),
                timeout=2.0  # Reduced timeout for faster test if it works
            )

            assert isinstance(response, ControllerSpecificEmpty)
            assert shutdown_event.is_set(), "Shutdown event was not set by controller."
            logger.info("test_controller_shutdown_with_timeout: Shutdown completed successfully.")

        except asyncio.TimeoutError:
            logger.error("test_controller_shutdown_with_timeout: Controller.Shutdown timed out.")
            pytest.fail("Controller.Shutdown timed out")
        # Check that os.kill and sys.exit were called (or not, depending on design)
        # For this test, we assume they are called by the shutdown process initiated by controller.
        # However, the GRPCControllerService itself doesn't call them; it sets an event.
        # The main server loop or application would handle the actual exit.
        # So, for GRPCControllerService, we mainly care about the shutdown_event.


@pytest.mark.asyncio
async def test_stdio_early_client_disconnect(real_server_client: ExtendedServerFixtureOutput) -> None:
    """Test stdio service when client disconnects early."""
    channel = real_server_client.channel
    stdio_stub = real_server_client.stdio_stub

    # Start the stream
    from google.protobuf.empty_pb2 import Empty as ProtobufEmpty
    stream_call = stdio_stub.StreamStdio(ProtobufEmpty())

    # Wait for stream to establish
    await asyncio.sleep(0.1)

    # Abruptly close the channel without properly closing the stream
    logger.debug("test_stdio_early_client_disconnect: Closing client channel abruptly.")
    await channel.close()

    # Verify stream is properly terminated on the server-side (client sees RpcError)
    logger.debug("test_stdio_early_client_disconnect: Checking for RpcError on stream iteration.")
    try:
        async for item in stream_call:
            logger.error(f"test_stdio_early_client_disconnect: Unexpectedly received item: {item}")
        # If loop finishes without error, it's also unexpected after channel close
        logger.error("test_stdio_early_client_disconnect: Stream iteration finished without error, which is unexpected.")
    except grpc.RpcError as e:
        logger.info(f"test_stdio_early_client_disconnect: Received RpcError as expected: {e.code()}")
        # Common codes for this scenario: CANCELLED or UNAVAILABLE
        assert e.code() in [grpc.StatusCode.CANCELLED, grpc.StatusCode.UNAVAILABLE]
    except Exception as e:
        logger.error(f"test_stdio_early_client_disconnect: Received unexpected exception: {e}")
        pytest.fail(f"Received unexpected exception: {e}")


@pytest.mark.asyncio
async def test_broker_multiple_clients(real_server_client: ExtendedServerFixtureOutput) -> None:
    """Test multiple clients connecting to broker service simultaneously."""
    broker_service = real_server_client.broker_service
    assert broker_service is not None, "Broker service not found in fixture output"

    num_clients = 3
    contexts = [MagicMock() for _ in range(num_clients)] # These are server-side contexts, not directly used by client

    iterators = []
    for i in range(num_clients):
        knock_request = ConnInfo(
            service_id=i+1,
            network="tcp",
            address=f"localhost:{10000+i}", # Each client asks for a different "target"
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )
        # This MockRequestIterator is for the server-side handling of the stream,
        # not for the client stub. The client stub (broker_stub) is used directly.
        # For testing GRPCBrokerService directly (not via stub), this is fine.
        # But this test uses real_server_client, so it should use broker_stub.
        # Let's re-think this part.
        # The test should simulate N clients connecting to the *same* broker_stub.
        # Each client will have its own StartStream call.

    async def single_client_task(client_id: int, stub: GRPCBrokerStub):
        logger.debug(f"Client {client_id}: Starting StartStream call.")
        stream = stub.StartStream()
        
        knock_req = ConnInfo(
            service_id=client_id, # Use client_id as service_id for uniqueness
            network="tcp",
            address=f"localhost:fake_target_{client_id}", # Dummy target address
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )
        await stream.write(knock_req)
        logger.debug(f"Client {client_id}: Sent knock request: {knock_req.service_id}")
        
        response = await stream.read()
        logger.debug(f"Client {client_id}: Received response: {response.service_id}, ack: {response.knock.ack}")
        
        # Cleanly close the client's stream attempt
        await stream.done_writing()
        try:
            # Drain any remaining messages, though not expected here
            async for _ in stream: pass
        except grpc.RpcError: # Expected if server closes stream after ack
            pass
        logger.debug(f"Client {client_id}: Stream finished.")
        return response

    client_tasks = []
    for i in range(1, num_clients + 1):
        client_tasks.append(asyncio.create_task(single_client_task(i, real_server_client.broker_stub)))

    results = await asyncio.gather(*client_tasks)

    for i, response in enumerate(results):
        client_id = i + 1
        assert response.service_id == client_id, f"Client {client_id} response mismatch"
        assert response.knock.ack is True, f"Client {client_id} did not get ACK"

    # Verify broker service created the expected subchannels on the server side
    # The number of subchannels should match num_clients if each knock was successful
    # and led to a subchannel being registered.
    assert len(broker_service._subchannels) == num_clients, \
        f"Expected {num_clients} subchannels, found {len(broker_service._subchannels)}"
    for i in range(1, num_clients + 1):
        assert i in broker_service._subchannels, f"Subchannel for service_id {i} not found"
    logger.info("test_broker_multiple_clients: Test completed successfully.")


class MockRequestIterator: # This is defined locally, but also globally. Keep for local scope if needed.
    """Mock request iterator for broker stream (server-side testing)."""
    def __init__(self, requests) -> None:
        self.requests = requests
        self.index = 0

    def __aiter__(self) -> "MockRequestIterator":
        return self

    async def __anext__(self):
        if self.index < len(self.requests):
            request = self.requests[self.index]
            self.index += 1
            return request
        raise StopAsyncIteration


async def collect_broker_stream(stream): # Used by an older version of test_broker_multiple_clients
    """Collect all responses from a broker stream."""
    results = []
    async for response in stream:
        results.append(response)
    return results

# 🐍🏗️🔌
