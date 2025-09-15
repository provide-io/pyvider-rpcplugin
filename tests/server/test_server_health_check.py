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

from provide.foundation import logger

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
    # Map environment variable keys to Foundation attribute names
    key_to_attr = {
        "PLUGIN_HEALTH_SERVICE_ENABLED": "plugin_health_service_enabled",
        "PLUGIN_AUTO_MTLS": "plugin_auto_mtls",
        "PLUGIN_SHUTDOWN_FILE_PATH": "plugin_shutdown_file_path",
        "PLUGIN_RATE_LIMIT_ENABLED": "plugin_rate_limit_enabled",
    }
    
    original_values = {}
    default_params = {
        "PLUGIN_HEALTH_SERVICE_ENABLED": True,
        "PLUGIN_AUTO_MTLS": False,
        "PLUGIN_SHUTDOWN_FILE_PATH": None,
        "PLUGIN_RATE_LIMIT_ENABLED": False,
    }

    params_to_apply = default_params.copy()
    if hasattr(request, "param") and request.param is not None:
        params_to_apply.update(request.param)

    # Apply params using direct attribute access
    for key, value in params_to_apply.items():
        attr_name = key_to_attr.get(key)
        if attr_name and hasattr(rpcplugin_config, attr_name):
            original_values[attr_name] = getattr(rpcplugin_config, attr_name)
            setattr(rpcplugin_config, attr_name, value)

    yield

    # Restore original values
    for attr_name, value in original_values.items():
        setattr(rpcplugin_config, attr_name, value)


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

        endpoint = server._transport.endpoint
        assert endpoint, "Could not determine server endpoint for client connection."

        # Use appropriate connection string based on transport type
        from pyvider.rpcplugin.transport.unix import UnixSocketTransport
        if isinstance(server._transport, UnixSocketTransport):
            connection_string = f"unix:{endpoint}"
        else:
            connection_string = endpoint

        async with grpc.aio.insecure_channel(connection_string) as channel:
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


# 🐍🔌🧪🪄
