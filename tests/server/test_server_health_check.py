import asyncio
import grpc
import pytest
from typing import Any

from grpc_health.v1 import health_pb2, health_pb2_grpc

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import ServerT

from tests.fixtures.proto import echo_pb2
from tests.fixtures.proto import echo_pb2_grpc

from pyvider.telemetry import logger

class EchoServiceImpl(echo_pb2_grpc.EchoServiceServicer):
    service_name = "echo.EchoService"

    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        logger.debug(f"EchoServiceImpl received: {request.message}")
        return echo_pb2.EchoResponse()

class EchoProtocolImpl(RPCPluginProtocol[ServerT, EchoServiceImpl]):
    service_name = "echo.EchoService"

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return echo_pb2.DESCRIPTOR, self.service_name

    async def add_to_server(self, server: ServerT, handler: EchoServiceImpl) -> None:
        echo_pb2_grpc.add_EchoServiceServicer_to_server(handler, server)


@pytest.fixture
def health_test_config_override(request):
    original_values = {}
    default_params = {
        "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
        "PLUGIN_AUTO_MTLS": "false",
        "PLUGIN_SHUTDOWN_FILE_PATH": None,
        "PLUGIN_RATE_LIMIT_ENABLED": "false",
    }

    params_to_apply = default_params.copy()
    if hasattr(request, "param") and request.param is not None:
        params_to_apply.update(request.param)

    for key, value in params_to_apply.items():
        original_values[key] = rpcplugin_config.get(key)
        rpcplugin_config.set(key, value)

    yield

    for key, value in original_values.items():
        rpcplugin_config.set(key, value)


@pytest.mark.asyncio
async def test_health_service_enabled_and_serving(health_test_config_override, monkeypatch): # Added monkeypatch
    # Ensure the magic cookie environment variable is set for direct server instantiation
    cookie_key = rpcplugin_config.magic_cookie_key()
    cookie_value = rpcplugin_config.magic_cookie_value()
    monkeypatch.setenv(cookie_key, cookie_value)

    protocol = EchoProtocolImpl()
    handler = EchoServiceImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=5.0)

        socket_path = server._transport.endpoint
        assert socket_path, "Could not determine server socket path for client connection."

        async with grpc.aio.insecure_channel(f"unix:{socket_path}") as channel:
            health_stub = health_pb2_grpc.HealthStub(channel)
            echo_stub = echo_pb2_grpc.EchoServiceStub(channel)

            await echo_stub.Echo(echo_pb2.EchoRequest(message="ping"))
            logger.info("Main Echo service responded.")

            health_check_req = health_pb2.HealthCheckRequest(service=EchoProtocolImpl.service_name)
            response = await health_stub.Check(health_check_req)
            assert response.status == health_pb2.HealthCheckResponse.SERVING

            health_check_req_empty = health_pb2.HealthCheckRequest(service="")
            response_empty = await health_stub.Check(health_check_req_empty)
            assert response_empty.status == health_pb2.HealthCheckResponse.SERVING

            with pytest.raises(grpc.aio.AioRpcError) as exc_info:
                await health_stub.Check(health_pb2.HealthCheckRequest(service="nonexistent.Service"))
            assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND

            with pytest.raises(grpc.aio.AioRpcError) as exc_info_watch:
                async for _ in health_stub.Watch(health_check_req_empty):
                    pytest.fail("Watch RPC should be unimplemented.")
            assert exc_info_watch.value.code() == grpc.StatusCode.UNIMPLEMENTED

    finally:
        await server.stop()
        await asyncio.wait_for(serve_task, timeout=2.0)
