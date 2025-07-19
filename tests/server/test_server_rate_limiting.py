import asyncio
import os
import grpc
import pytest
from typing import Any

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer, RateLimitingInterceptor
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import HandlerT, ServerT # Keep ServerT for type hinting protocol
from pyvider.telemetry import logger

# Import generated gRPC stubs
from tests.fixtures.proto import echo_pb2
from tests.fixtures.proto import echo_pb2_grpc


# Concrete Handler/Servicer for Echo service
class EchoServicerImpl(echo_pb2_grpc.EchoServiceServicer): # Changed
    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        logger.debug(f"EchoServicerImpl received: {request.message}")
        return echo_pb2.EchoResponse(reply=f"Echo: {request.message}") # Changed

# Concrete Protocol for Echo service
class EchoProtocolImpl(RPCPluginProtocol[ServerT, EchoServicerImpl]): # HandlerT becomes EchoServicerImpl
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        logger.debug("EchoProtocolImpl get_grpc_descriptors called")
        return echo_pb2.DESCRIPTOR, "echo.EchoService" # Changed

    async def add_to_server(self, server: ServerT, handler: EchoServicerImpl) -> None:
        logger.debug(f"EchoProtocolImpl add_to_server called with handler {type(handler)} and server {type(server)}")
        echo_pb2_grpc.add_EchoServiceServicer_to_server(handler, server) # Changed


@pytest.fixture
def server_config_override_rl(request):
    """Fixture to temporarily override rpcplugin_config settings for rate limiting."""
    original_values = {}
    default_params = {
        "PLUGIN_RATE_LIMIT_ENABLED": "true",
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 100.0,
        "PLUGIN_RATE_LIMIT_BURST_CAPACITY": 200.0,
        "PLUGIN_SHUTDOWN_FILE_PATH": None, # Ensure no interference from shutdown file
        "PLUGIN_AUTO_MTLS": "false", # Run server in insecure mode for these tests
    }

    # Merge default_params with request.param if provided
    params_to_apply = default_params.copy()
    if hasattr(request, "param") and request.param is not None:
        params_to_apply.update(request.param)

    for key, value in params_to_apply.items():
        original_values[key] = rpcplugin_config.get(key)
        rpcplugin_config.set(key, value)
        logger.debug(f"Overriding config for rate limit test: {key} = {value}")

    yield

    for key, value in original_values.items():
        rpcplugin_config.set(key, value)
        logger.debug(f"Restoring config post rate limit test: {key} = {value}")


@pytest.mark.asyncio
async def test_server_initializes_with_rate_limiter_enabled(server_config_override_rl):
    """Test that the server initializes the rate limiter when configured."""

    protocol = EchoProtocolImpl()
    handler = EchoServicerImpl()
    # server_config_override_rl is active via fixture for rate limiting config
    server = RPCPluginServer(protocol=protocol, handler=handler)

    assert server._rate_limiter is not None, "Rate limiter should be initialized."
    assert isinstance(server._rate_limiter, TokenBucketRateLimiter), "Rate limiter is not of TokenBucketRateLimiter type."

    # Check if the values from config were correctly passed to the limiter
    # This requires the limiter to store them or have accessors, which it does.
    expected_capacity = rpcplugin_config.rate_limit_burst_capacity()
    expected_rate = rpcplugin_config.rate_limit_requests_per_second()

    # Accessing private attributes for tests is not ideal but sometimes necessary
    # if no public accessors are provided. TokenBucketRateLimiter does store them.
    assert server._rate_limiter._capacity == expected_capacity
    assert server._rate_limiter._refill_rate == expected_rate

    logger.info("Rate limiter initialized with correct parameters.")

    serve_task = None
    try:
        logger.info("Starting server for rate limiter initialization test.")
        serve_task = asyncio.create_task(server.serve())

        # Let the server start up. The handshake response will be printed by the server.
        # We're not making a real RPC call in this test, just checking initialization.
        await asyncio.sleep(0.5) # Allow server to start, print handshake etc.

        # Check that the server is running
        assert not server._serving_future.done(), "Server's serving_future was done prematurely."

        logger.info("Server running with rate limiter. Attempting normal stop.")
        await server.stop()
        await asyncio.wait_for(serve_task, timeout=5.0)
        assert server._serving_future.done(), "Server's serving_future was not done after explicit stop."
        logger.info("Server with rate limiter stopped successfully.")

    except asyncio.TimeoutError:
        if serve_task and not serve_task.done():
            serve_task.cancel()
        pytest.fail("Server task did not complete within timeout (rate limiter init test).")
    except Exception as e:
        if serve_task and not serve_task.done():
            serve_task.cancel()
        pytest.fail(f"An unexpected error occurred (rate limiter init test): {e}")
    finally:
        # Fixture server_config_override_rl will handle restoring config
        if hasattr(server, '_server') and server._server is not None:
            if not server._serving_future.done():
                logger.warning("Server might not have shut down cleanly, attempting explicit stop.")
                await server.stop()
        logger.info("Test test_server_initializes_with_rate_limiter_enabled finished.")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_config_override_rl",
    [
        {
            "PLUGIN_RATE_LIMIT_ENABLED": "true",
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 2.0, # Low rate for testing
            "PLUGIN_RATE_LIMIT_BURST_CAPACITY": 2.0,      # Low burst for testing
        }
    ],
    indirect=True,
)
async def test_rate_limiter_denies_requests_when_limit_exceeded(server_config_override_rl):
    """Tests that requests are denied when the rate limit is exceeded."""
    protocol = EchoProtocolImpl()
    handler = EchoServicerImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    serve_task = None
    channel = None
    try:
        logger.info("Starting server for rate limit denial test.")
        serve_task = asyncio.create_task(server.serve())

        # Wait for server to be ready (handshake printed to stdout indicates readiness)
        # The server prints handshake like "1|1|unix|/path/to/socket|grpc|cert_data"
        # We need to capture this to know the endpoint.
        # For simplicity in this test, we'll assume unix socket and try to guess the path
        # or use a fixed one if possible, though the server generates unique sock names.
        # A better way would be to parse stdout or have server signal readiness with endpoint.

        # Let's give it a moment to start and print handshake.
        await asyncio.sleep(0.5) # Increased sleep

        # This part is tricky: the server's handshake output needs to be captured.
        # For now, we'll assume a common pattern or make it predictable for testing.
        # The RPCPluginServer uses a unique socket path like /tmp/pyvider-<pid>.sock
        # This test needs to connect to that.
        # The server.serve() prints the handshake string. We need to capture that.
        # This test setup does not capture stdout from server.serve() easily.

        # Hacky way for test: find the socket. This assumes only one such socket.
        # This is not robust.
        socket_path = None
        if server._transport and hasattr(server._transport, "path") and server._transport.path:
             socket_path = server._transport.path

        assert socket_path, "Could not determine server socket path for client connection."
        logger.info(f"Test client connecting to guessed socket path: {socket_path}")

        channel = grpc.aio.insecure_channel(f"unix:{socket_path}")
        stub = echo_pb2_grpc.EchoServiceStub(channel) # Changed

        logger.info("Making initial requests that should pass...")
        # Burst capacity is 2, rate is 2.
        # First 2 should pass immediately.
        for i in range(2):
            response = await stub.Echo(echo_pb2.EchoRequest(message=f"hello {i}"))
            assert response.reply == f"Echo: hello {i}" # Changed
            logger.info(f"Request {i+1} succeeded.")

        logger.info("Making a request that should be rate-limited...")
        # The 3rd request should be denied as tokens are (initially 2 - 2 = 0).
        # It needs 0.5s for one token to refill.
        try:
            await stub.Echo(echo_pb2.EchoRequest(message="hello rate-limited"))
            pytest.fail("Request was not rate-limited when it should have been.")
        except grpc.aio.AioRpcError as e:
            assert e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED, \
                f"Expected RESOURCE_EXHAUSTED, got {e.code()}"
            logger.info(f"Request correctly denied with RESOURCE_EXHAUSTED: {e.details()}")

        logger.info("Waiting for tokens to refill...")
        await asyncio.sleep(1.0) # Wait 1 second, should allow 2 tokens to refill

        logger.info("Making requests that should now pass after refill...")
        for i in range(2):
            response = await stub.Echo(echo_pb2.EchoRequest(message=f"hello post-wait {i}"))
            assert response.reply == f"Echo: hello post-wait {i}" # Changed
            logger.info(f"Request post-wait {i+1} succeeded.")

    except Exception as e:
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        if channel:
            await channel.close()
        if server: # Ensure server is stopped even on failure
            await server.stop()
        if serve_task and not serve_task.done():
            serve_task.cancel()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass # Expected
        logger.info("Test test_rate_limiter_denies_requests_when_limit_exceeded finished.")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_config_override_rl",
    [{"PLUGIN_RATE_LIMIT_ENABLED": "false"}],
    indirect=True,
)
async def test_server_runs_without_rate_limiter_if_disabled(server_config_override_rl):
    """Test that the server runs normally and no rate limiter is active if disabled in config."""
    protocol = EchoProtocolImpl()
    handler = EchoServicerImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    assert server._rate_limiter is None, "Rate limiter should NOT be initialized if disabled."

    serve_task = None
    channel = None
    try:
        logger.info("Starting server for 'rate limiting disabled' test.")
        serve_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5)

        socket_path = None
        if server._transport and hasattr(server._transport, "path") and server._transport.path:
             socket_path = server._transport.path
        assert socket_path, "Could not determine server socket path for client connection."

        channel = grpc.aio.insecure_channel(f"unix:{socket_path}")
        stub = echo_pb2_grpc.EchoServiceStub(channel) # Changed

        logger.info("Making multiple requests, should all pass as rate limiting is off.")
        for i in range(5): # Make a few calls
            response = await stub.Echo(echo_pb2.EchoRequest(message=f"disabled test {i}"))
            assert response.reply == f"Echo: disabled test {i}" # Changed
            await asyncio.sleep(0.01) # Tiny sleep, but shouldn't matter

        logger.info("All requests passed with rate limiting disabled.")

    except Exception as e:
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        if channel:
            await channel.close()
        if server:
            await server.stop()
        if serve_task and not serve_task.done():
            serve_task.cancel()
            try:
                await serve_task
            except asyncio.CancelledError:
                pass
        logger.info("Test test_server_runs_without_rate_limiter_if_disabled finished.")
