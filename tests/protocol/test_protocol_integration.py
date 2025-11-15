# tests/protocol/test_protocol_integration.py

import asyncio
import pytest
import pytest_asyncio
import attr  # Added import

from unittest.mock import patch, AsyncMock

import grpc
from google.protobuf.empty_pb2 import Empty
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty

# Service implementations
from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    GRPCBrokerService,
    GRPCControllerService,
    # register_protocol_service, # Removed
)

# Stubs for client-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub

# Servicer adders for server-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import (
    add_GRPCStdioServicer_to_server,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import (
    add_GRPCBrokerServicer_to_server,
)
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import (
    add_GRPCControllerServicer_to_server,
)

from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.telemetry import logger
from typing import AsyncGenerator # Added import


@attr.s(auto_attribs=True, frozen=True)
class ServerFixtureOutput:
    server: grpc.aio.Server
    address: str
    shutdown_event: asyncio.Event
    stdio_service: GRPCStdioService
    broker_service: GRPCBrokerService
    controller_service: GRPCControllerService


@pytest_asyncio.fixture
async def grpc_server_output() -> AsyncGenerator[ServerFixtureOutput, None]:
    """Fixture providing a real gRPC server with our services registered."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Instantiate services
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(
        shutdown_event, stdio_service
    )  # Assuming it needs stdio_service

    # Register services directly
    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    # Add an insecure port
    port = server.add_insecure_port("localhost:0")
    address = f"localhost:{port}"

    # Start the server
    await server.start()

    yield ServerFixtureOutput(
        server=server,
        address=address,
        shutdown_event=shutdown_event,
        stdio_service=stdio_service,
        broker_service=broker_service,
        controller_service=controller_service,
    )

    # Cleanup
    await server.stop(grace=0.1)


@pytest_asyncio.fixture
async def grpc_channel(grpc_server_output: ServerFixtureOutput):  # Changed fixture name
    """Fixture providing a client channel to the gRPC server."""
    channel = grpc.aio.insecure_channel(grpc_server_output.address)
    yield channel
    await channel.close()


# Removed old test_stdio_integration; test_stdio_integration_consolidated is preferred.


@pytest.mark.asyncio
async def test_stdio_integration_consolidated(
    grpc_server_output: ServerFixtureOutput, grpc_channel
) -> None:
    """
    Consolidated integration test for the stdio service.
    Checks data content and channel type (stdout/stderr).
    """
    stdio_service = grpc_server_output.stdio_service
    stub = GRPCStdioStub(grpc_channel)
    assert stdio_service is not None

    log_func = logger.debug  # Use a standard logger for tests

    test_lines_to_send = [
        (b"stdout line 1 from consolidated", False, StdioData.STDOUT),
        (b"stderr line 1 from consolidated", True, StdioData.STDERR),
        (b"stdout line 2 from consolidated", False, StdioData.STDOUT),
    ]
    num_expected_messages = len(test_lines_to_send)
    results = []

    stream_call = stub.StreamStdio(Empty())

    client_task_completed_normally = False

    async def client_receive_task():
        nonlocal results, client_task_completed_normally
        try:
            log_func("Client: Starting to iterate over stream_call")
            async for data_item in stream_call:
                log_func(
                    f"Client: Received item: channel={data_item.channel}, data='{data_item.data.decode()[:30]}...'"
                )
                results.append(data_item)
                if len(results) >= num_expected_messages:
                    log_func(f"Client: Received {len(results)} items, breaking loop.")
                    break
            log_func("Client: Exited async for loop.")
            client_task_completed_normally = True
        except grpc.aio.AioRpcError as e:
            log_func(f"Client stream error: Code={e.code()} Details={e.details()}")
            # Do not fail here for CANCELLED or UNAVAILABLE if server is shutting down
            if e.code() not in [grpc.StatusCode.CANCELLED, grpc.StatusCode.UNAVAILABLE]:
                pytest.fail(f"Client stream error: {e.code()} - {e.details()}")
        except Exception as e:
            log_func(f"Client receive task error: {type(e).__name__}: {e}")
            pytest.fail(f"Client receive task error: {e}")
        finally:
            log_func(
                f"Client: Receive task finally block. Results count: {len(results)}"
            )

    client_task = asyncio.create_task(client_receive_task())
    await asyncio.sleep(0.2)

    for line_content, is_stderr, _ in test_lines_to_send:
        log_func(f"Server: Sending line: {line_content}, stderr={is_stderr}")
        await stdio_service.put_line(line_content, is_stderr=is_stderr)

    try:
        log_func("Test: Waiting for client_task to complete...")
        await asyncio.wait_for(
            client_task, timeout=3.0
        )  # Shorter timeout, should be quick
        log_func("Test: client_task completed.")
    except asyncio.TimeoutError:
        log_func("Test: Client task timed out. Cancelling stream_call if not done.")
        if not stream_call.done():
            stream_call.cancel()
        if (
            not client_task_completed_normally
        ):  # Only fail if we didn't actually get all messages
            pytest.fail("Client task timed out waiting for stdio messages.")
    finally:
        # Ensure client_task is cancelled if it's still running (e.g. due to timeout in wait_for)
        if not client_task.done():
            log_func("Test: Client task not done in finally, cancelling.")
            client_task.cancel()
            await asyncio.gather(
                client_task, return_exceptions=True
            )  # Allow cancellation

        # Ensure the RPC call itself is cleaned up from the client side
        if not stream_call.done():
            log_func("Test: Stream_call not done in finally, cancelling.")
            stream_call.cancel()

    assert len(results) == num_expected_messages, (
        f"Expected {num_expected_messages} messages, got {len(results)}"
    )
    for i, (expected_line, _, expected_channel_enum) in enumerate(test_lines_to_send):
        assert results[i].data == expected_line
        assert results[i].channel == expected_channel_enum


# Removed old test_broker_integration; other broker tests are more specific or comprehensive.


@pytest.mark.asyncio
async def test_broker_start_stream_error_handling(
    grpc_server_output: ServerFixtureOutput, grpc_channel
) -> None:
    """Tests error handling in GRPCBrokerService.StartStream when SubchannelConnection.open fails."""
    # broker_service is available if direct interaction is needed later

    stub = GRPCBrokerStub(grpc_channel)
    stream = stub.StartStream()

    simulated_error_message = "Simulated open error"
    with patch(
        "pyvider.rpcplugin.protocol.service.SubchannelConnection.open",
        new_callable=AsyncMock,
        side_effect=RuntimeError(simulated_error_message),
    ):
        knock_request = ConnInfo(
            service_id=123,  # Distinct service_id for this test
            network="tcp",
            address="localhost:6789",
            knock=ConnInfo.Knock(knock=True, ack=False, error=""),
        )
        await stream.write(knock_request)

        response = await stream.read()

        # If SubchannelConnection.open fails, ack should be False and error populated.
        assert response.knock.ack is False  # This is the correct assertion
        assert simulated_error_message in response.knock.error

        assert response.service_id == knock_request.service_id

    await stream.done_writing()


@pytest.mark.asyncio
async def test_broker_cancellation_consolidated(
    grpc_server_output: ServerFixtureOutput, grpc_channel
) -> None:
    """Consolidated test for broker service stream cancellation."""
    stub = GRPCBrokerStub(grpc_channel)
    stream = stub.StartStream()

    knock_request = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error=""),
    )
    await stream.write(knock_request)
    response = await stream.read()
    assert response.service_id == 1
    assert response.knock.ack is True

    # Attempt cancellation
    cancelled_successfully = False
    try:
        if hasattr(stream, "cancel") and callable(stream.cancel):
            stream.cancel()  # Newer gRPC might return a future or be an async call
            if asyncio.iscoroutine(stream.cancel()):  # Handle if it's now async
                await stream.cancel()
            cancelled_successfully = True
        elif hasattr(stream, "_cython_call") and hasattr(
            stream._cython_call, "cancel"
        ):  # Older versions
            stream._cython_call.cancel("Client cancelled")
            cancelled_successfully = True
    except Exception as e:
        logger.error(f"Error during stream cancellation: {e}")
        # Optionally re-raise or assert based on whether cancellation itself should fail

    assert cancelled_successfully, "Stream cancellation method not found or failed"

    # Attempt to mark writing as done, which might raise if stream is truly hard-cancelled
    try:
        await stream.done_writing()
    except grpc.aio.AioRpcError as e:
        # Expecting an error if cancellation was effective (e.g., RpcError with CANCELLED status)
        assert e.code() == grpc.StatusCode.CANCELLED, (
            f"Expected CANCELLED status, got {e.code()}"
        )
    except Exception as e:
        # Other exceptions might indicate issues with done_writing itself
        pytest.fail(f"Unexpected error on done_writing after cancel: {e}")


# Removed old test_controller_integration; test_controller_shutdown_with_timeout_consolidated is preferred.


@pytest.mark.asyncio
async def test_stdio_early_client_disconnect_consolidated(
    grpc_server_output: ServerFixtureOutput,
) -> None:  # Removed grpc_channel fixture
    """
    Consolidated test for stdio service when client disconnects early.
    Verifies that attempting to read from the stream after channel closure raises an appropriate gRPC error.
    """
    # Create a new channel specifically for this test, ensuring it's fresh
    temp_channel = grpc.aio.insecure_channel(grpc_server_output.address)
    try:
        await temp_channel.channel_ready()  # Ensure it's ready
        stub = GRPCStdioStub(temp_channel)

        # Start the stream
        stream_call = stub.StreamStdio(Empty())

        # Wait for stream to potentially establish on server side
        await asyncio.sleep(0.1)

        # Abruptly close the channel
        await temp_channel.close()

        # Attempting to iterate over the stream after channel closure should raise an error
        # Common errors include RpcError with status CANCELLED or UNAVAILABLE.
        # asyncio.CancelledError can also occur if the tasks managing the stream are cancelled.
        raised_expected_error = False
        try:  # Inner try for stream iteration
            async for _ in stream_call:
                # We should not receive any items if channel is closed before server sends anything
                # or during server sending.
                pass
        except grpc.aio.AioRpcError as e:
            # Expected gRPC error codes after channel closure by client.
            # CANCELLED if client closes before server finishes.
            # UNAVAILABLE if server is already down or closes connection abruptly.
            if e.code() in [grpc.StatusCode.CANCELLED, grpc.StatusCode.UNAVAILABLE]:
                raised_expected_error = True
            else:
                pytest.fail(
                    f"Unexpected grpc.aio.AioRpcError: {e.code()} - {e.details()}"
                )
        except asyncio.CancelledError:
            # This can happen if the client's tasks are cancelled due to channel closure.
            raised_expected_error = True
        except Exception as e:
            pytest.fail(f"Unexpected exception type raised: {type(e).__name__} - {e}")

        assert raised_expected_error, (
            "Expected an AioRpcError (Cancelled/Unavailable) or asyncio.CancelledError"
        )
    finally:
        # Ensure the temporary channel is closed if not already
        await temp_channel.close()


@pytest.mark.asyncio
async def test_broker_multiple_clients_consolidated(
    grpc_server_output: ServerFixtureOutput, grpc_channel
) -> None:
    """
    Consolidated test for multiple clients connecting to broker service simultaneously.
    """
    broker_service = grpc_server_output.broker_service
    # broker_stub = GRPCBrokerStub(grpc_channel) # New stubs needed for each client task

    num_clients = 3
    client_tasks = []

    # Helper to simulate a client's interaction
    async def single_client_interaction(service_id: int):
        # Each client needs its own channel and stub
        # Re-use the server address from the main fixture
        client_specific_channel = grpc.aio.insecure_channel(grpc_server_output.address)
        try:
            stub = GRPCBrokerStub(client_specific_channel)
            stream = stub.StartStream()

            knock_request = ConnInfo(
                service_id=service_id,
                network="tcp",
                address=f"localhost:{10000 + service_id}",
                knock=ConnInfo.Knock(knock=True, ack=False, error=""),
            )
            await stream.write(knock_request)
            response = await stream.read()

            assert response.service_id == service_id
            assert response.knock.ack is True

            # Simulate some activity or just close
            await stream.done_writing()
            return True  # Indicate success
        except Exception as e:
            logger.error(f"Client {service_id} failed: {e}")
            return False  # Indicate failure
        finally:
            await client_specific_channel.close()

    for i in range(num_clients):
        client_tasks.append(asyncio.create_task(single_client_interaction(i + 1)))

    results = await asyncio.gather(*client_tasks)

    assert all(results), "Not all client interactions succeeded"
    # The assertion on len(broker_service._subchannels) might be racy if subchannels
    # are removed immediately on stream end. A better check might be if the service
    # *handled* N distinct service_ids if it tracks them, or to verify logs.
    # For now, let's assume the original check was valid if subchannels persist for a bit.
    # This might require the broker_service to be more testable or use mocks for subchannel creation.
    # Given the original test structure, this check is maintained.
    # However, if broker_service._subchannels are cleaned up immediately after a stream ends,
    # this count might be 0 or less than num_clients by the time this check runs.
    # Await a brief moment for all stream processing on server to settle if needed.
    await asyncio.sleep(0.1)
    assert len(broker_service._subchannels) == num_clients, (
        f"Expected {num_clients} subchannels, found {len(broker_service._subchannels)}"
    )
    for i in range(num_clients):
        assert (i + 1) in broker_service._subchannels


@pytest.mark.asyncio
async def test_controller_shutdown_with_timeout_consolidated(
    grpc_server_output: ServerFixtureOutput, grpc_channel
) -> None:
    """
    Consolidated test for controller shutdown with a timeout.
    Verifies that the shutdown event is set and internal shutdown logic is called.
    """
    controller_service = grpc_server_output.controller_service
    shutdown_event = grpc_server_output.shutdown_event
    stub = GRPCControllerStub(grpc_channel)

    # Patch os.kill and sys.exit to prevent actual process termination during test
    with (
        patch("os.kill"),
        patch("sys.exit"),
        patch("os.getpid", return_value=12345),
    ):  # Mock getpid as it might be used by shutdown logic
        # Mock the internal _delayed_shutdown method of the specific controller_service instance
        with patch.object(
            controller_service, "_delayed_shutdown", new_callable=AsyncMock
        ) as mock_delayed_shutdown_method:
            try:
                response = await asyncio.wait_for(
                    stub.Shutdown(
                        ControllerEmpty()
                    ),  # Use ControllerEmpty for controller
                    timeout=2.0,  # Reasonable timeout for the RPC call
                )

                assert isinstance(response, ControllerEmpty), (
                    "Response should be an Empty message"
                )

                # Check that the server's shutdown event was set
                assert shutdown_event.is_set(), "Server's shutdown_event was not set"

                # Allow a brief moment for the _delayed_shutdown task to be called
                await asyncio.sleep(0.05)
                mock_delayed_shutdown_method.assert_called_once()

            except asyncio.TimeoutError:
                pytest.fail("Controller.Shutdown RPC call timed out")
            except Exception as e:
                pytest.fail(f"Controller shutdown test failed: {e}")


### 🐍🏗🧪️
