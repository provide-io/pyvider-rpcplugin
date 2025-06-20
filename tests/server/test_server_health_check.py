import asyncio
import grpc
import pytest
from typing import Any

from grpc_health.v1 import health_pb2, health_pb2_grpc

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import ServerT # Keep ServerT for type hinting protocol

# Import Echo service stubs from previous tests for a dummy main service
from tests.fixtures.proto import echo_pb2
from tests.fixtures.proto import echo_pb2_grpc

from pyvider.telemetry import logger

# Concrete Handler/Servicer for Echo service
class EchoServiceImpl(echo_pb2_grpc.EchoServicer):
    service_name = "pyvider.testing.echo.Echoer" # Expose service name

    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        logger.debug(f"EchoServiceImpl received: {request.message}")
        return echo_pb2.EchoResponse(message=f"Echo: {request.message}")

# Concrete Protocol for Echo service
class EchoProtocolImpl(RPCPluginProtocol[ServerT, EchoServiceImpl]):
    service_name = "pyvider.testing.echo.Echoer" # Expose service name

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        logger.debug("EchoProtocolImpl get_grpc_descriptors called")
        # The first element is usually the file descriptor from _pb2.py
        return echo_pb2.DESCRIPTOR, self.service_name

    async def add_to_server(self, server: ServerT, handler: EchoServiceImpl) -> None:
        logger.debug(f"EchoProtocolImpl add_to_server called with handler {type(handler)} and server {type(server)}")
        echo_pb2_grpc.add_EchoServicer_to_server(handler, server)


@pytest.fixture
def health_test_config_override(request):
    """Fixture to temporarily override rpcplugin_config settings for health check tests."""
    original_values = {}
    default_params = {
        "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
        "PLUGIN_AUTO_MTLS": "false", # Run server in insecure mode for easier client connection
        "PLUGIN_SHUTDOWN_FILE_PATH": None,
        "PLUGIN_RATE_LIMIT_ENABLED": "false", # Disable rate limiting for these tests
    }

    params_to_apply = default_params.copy()
    if hasattr(request, "param") and request.param is not None:
        params_to_apply.update(request.param)

    for key, value in params_to_apply.items():
        original_values[key] = rpcplugin_config.get(key)
        rpcplugin_config.set(key, value)
        logger.debug(f"Overriding config for health test: {key} = {value}")

    yield

    for key, value in original_values.items():
        rpcplugin_config.set(key, value)
        logger.debug(f"Restoring config post health test: {key} = {value}")


@pytest.mark.asyncio
async def test_health_service_enabled_and_serving(health_test_config_override):
    """Test health service when enabled and main app is healthy."""
    protocol = EchoProtocolImpl()
    handler = EchoServiceImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    assert server._health_servicer is not None, "Health servicer should be initialized."
    assert server._health_servicer._service_name == EchoProtocolImpl.service_name, \
        "Health servicer not monitoring the correct main service name."

    serve_task = None
    channel = None
    try:
        logger.info("Starting server for health check (enabled, serving) test.")
        serve_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5) # Allow server to start

        socket_path = None
        if server._transport and hasattr(server._transport, "path") and server._transport.path:
             socket_path = server._transport.path
        assert socket_path, "Could not determine server socket path for client connection."

        channel = grpc.aio.insecure_channel(f"unix:{socket_path}")
        health_stub = health_pb2_grpc.HealthStub(channel)
        echo_stub = echo_pb2_grpc.EchoerStub(channel)

        # 1. Check main service via Echo call
        echo_response = await echo_stub.Echo(echo_pb2.EchoRequest(message="ping"))
        assert echo_response.message == "Echo: ping"
        logger.info("Main Echo service responded.")

        # 2. Check health of the main monitored service
        health_check_req = health_pb2.HealthCheckRequest(service=EchoProtocolImpl.service_name)
        response = await health_stub.Check(health_check_req)
        assert response.status == health_pb2.HealthCheckResponse.SERVING
        logger.info(f"Health check for '{EchoProtocolImpl.service_name}' returned SERVING.")

        # 3. Check health with empty service (overall server status)
        health_check_req_empty = health_pb2.HealthCheckRequest(service="")
        response_empty = await health_stub.Check(health_check_req_empty)
        assert response_empty.status == health_pb2.HealthCheckResponse.SERVING
        logger.info("Overall health check (empty service) returned SERVING.")

        # 4. Check health of a non-existent service
        try:
            await health_stub.Check(health_pb2.HealthCheckRequest(service="nonexistent.Service"))
            pytest.fail("Health check for non-existent service should have failed.")
        except grpc.aio.AioRpcError as e:
            assert e.code() == grpc.StatusCode.NOT_FOUND
            logger.info("Health check for non-existent service correctly returned NOT_FOUND.")

        # 5. Check Watch method (expected UNIMPLEMENTED)
        try:
            async for _ in health_stub.Watch(health_check_req_empty):
                pytest.fail("Watch RPC should be unimplemented and not yield anything.")
        except grpc.aio.AioRpcError as e:
            assert e.code() == grpc.StatusCode.UNIMPLEMENTED
            logger.info("Watch RPC correctly returned UNIMPLEMENTED.")

    except Exception as e:
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        if channel:
            await channel.close()
        if server:
            await server.stop()
        if serve_task and not serve_task.done():
            serve_task.cancel()
            try: await serve_task
            except asyncio.CancelledError: pass
        logger.info("Test test_health_service_enabled_and_serving finished.")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "health_test_config_override",
    [{"PLUGIN_HEALTH_SERVICE_ENABLED": "false"}],
    indirect=True,
)
async def test_health_service_disabled(health_test_config_override):
    """Test that the health service is not available if disabled in config."""
    protocol = EchoProtocolImpl()
    handler = EchoServiceImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    assert server._health_servicer is None, "Health servicer should NOT be initialized if disabled."

    serve_task = None
    channel = None
    try:
        logger.info("Starting server for health check (disabled) test.")
        serve_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5)

        socket_path = None
        if server._transport and hasattr(server._transport, "path") and server._transport.path:
             socket_path = server._transport.path
        assert socket_path, "Could not determine server socket path."

        channel = grpc.aio.insecure_channel(f"unix:{socket_path}")
        health_stub = health_pb2_grpc.HealthStub(channel)

        # Attempting to check health should fail, likely with UNIMPLEMENTED
        # as the service itself won't be registered with the gRPC server.
        try:
            await health_stub.Check(health_pb2.HealthCheckRequest(service=EchoProtocolImpl.service_name))
            pytest.fail("Health check should have failed as the service is disabled.")
        except grpc.aio.AioRpcError as e:
            # Depending on server behavior for missing service, could be UNIMPLEMENTED or UNAVAILABLE
            assert e.code() in (grpc.StatusCode.UNIMPLEMENTED, grpc.StatusCode.UNAVAILABLE), \
                f"Expected UNIMPLEMENTED or UNAVAILABLE, got {e.code()}"
            logger.info(f"Health check correctly failed with {e.code()} as service is disabled.")

        # Main service should still work
        echo_stub = echo_pb2_grpc.EchoerStub(channel)
        echo_response = await echo_stub.Echo(echo_pb2.EchoRequest(message="ping disabled health"))
        assert echo_response.message == "Echo: ping disabled health"
        logger.info("Main Echo service responded while health service was disabled.")

    except Exception as e:
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        if channel:
            await channel.close()
        if server:
            await server.stop()
        if serve_task and not serve_task.done():
            serve_task.cancel()
            try: await serve_task
            except asyncio.CancelledError: pass
        logger.info("Test test_health_service_disabled finished.")


@pytest.mark.asyncio
async def test_health_service_reports_not_serving_when_app_unhealthy(health_test_config_override):
    """Test that health service reports NOT_SERVING if app becomes unhealthy (e.g., during shutdown)."""
    protocol = EchoProtocolImpl()
    handler = EchoServiceImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    serve_task = None
    channel = None
    try:
        logger.info("Starting server for health check (unhealthy) test.")
        serve_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.2) # Short sleep for server to start

        socket_path = None
        if server._transport and hasattr(server._transport, "path") and server._transport.path:
             socket_path = server._transport.path
        assert socket_path, "Could not determine server socket path."

        channel = grpc.aio.insecure_channel(f"unix:{socket_path}")
        health_stub = health_pb2_grpc.HealthStub(channel)

        # Initially should be SERVING
        response = await health_stub.Check(health_pb2.HealthCheckRequest(service=EchoProtocolImpl.service_name))
        assert response.status == health_pb2.HealthCheckResponse.SERVING
        logger.info("Initial health check returned SERVING.")

        # Simulate server starting to shut down
        logger.info("Simulating server shutdown to make app unhealthy.")
        server._shutdown_event.set() # This makes _is_main_app_healthy return False

        # Now health check should return NOT_SERVING
        response_unhealthy = await health_stub.Check(health_pb2.HealthCheckRequest(service=EchoProtocolImpl.service_name))
        assert response_unhealthy.status == health_pb2.HealthCheckResponse.NOT_SERVING
        logger.info("Health check correctly returned NOT_SERVING after shutdown event set.")

        # Also check for overall server status
        response_overall_unhealthy = await health_stub.Check(health_pb2.HealthCheckRequest(service=""))
        assert response_overall_unhealthy.status == health_pb2.HealthCheckResponse.NOT_SERVING
        logger.info("Overall health check also returned NOT_SERVING.")


    except Exception as e:
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        # Clear the event if set by this test specifically, for server's own stop logic
        if server and server._shutdown_event.is_set():
             # If the test set it, the server.stop() might behave differently or already be in progress
             # For this test, it's okay as we expect serve_task to end due to shutdown_event.
             pass

        if channel:
            await channel.close()

        # Server stop might now be very quick or already done due to _shutdown_event
        if server:
             await server.stop() # Will resolve _serving_future

        if serve_task and not serve_task.done():
            # Wait for serve_task to finish, it should exit due to _shutdown_event being set
            try:
                await asyncio.wait_for(serve_task, timeout=2.0)
            except asyncio.TimeoutError:
                logger.warning("Serve task did not finish quickly after shutdown event was set.")
                serve_task.cancel()
                try: await serve_task
                except asyncio.CancelledError: pass
            except Exception as e_task:
                 logger.error(f"Error waiting for serve_task: {e_task}")


        logger.info("Test test_health_service_reports_not_serving_when_app_unhealthy finished.")
