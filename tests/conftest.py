# tests/conftest.py
import asyncio
import os
import sys
import types

os.environ.pop("OPENOBSERVE_URL", None)

from attrs import fields

# Provide lightweight stubs for grpc-health when appropriate version is unavailable.
if "grpc_health.v1.health_pb2" not in sys.modules:
    health_pb2 = types.ModuleType("grpc_health.v1.health_pb2")

    class HealthCheckResponse:
        SERVING = 1
        NOT_SERVING = 2
        SERVICE_UNKNOWN = 3

        def __init__(self, status: int | None = None) -> None:
            self.status = status

    class HealthCheckRequest:
        def __init__(self, service: str = "") -> None:
            self.service = service

    health_pb2.HealthCheckResponse = HealthCheckResponse
    health_pb2.HealthCheckRequest = HealthCheckRequest
    health_pb2.Empty = type("Empty", (), {})  # minimal stub

    health_pb2_grpc = types.ModuleType("grpc_health.v1.health_pb2_grpc")

    import grpc

    class HealthServicer:  # pragma: no cover - simple stub
        async def Check(  # type: ignore[override]
            self,
            request: HealthCheckRequest,
            context: grpc.aio.ServicerContext,
        ) -> HealthCheckResponse:
            raise NotImplementedError()

        async def Watch(  # type: ignore[override]
            self,
            request: HealthCheckRequest,
            context: grpc.aio.ServicerContext,
        ):
            raise NotImplementedError()

    class HealthStub:
        def __init__(self, channel: grpc.aio.Channel) -> None:
            self.Check = channel.unary_unary(
                "/grpc.health.v1.Health/Check",
                request_serializer=lambda req: req.SerializeToString()
                if hasattr(req, "SerializeToString")
                else b"",
                response_deserializer=lambda data: HealthCheckResponse(),  # pragma: no cover
            )
            self.Watch = channel.stream_stream(
                "/grpc.health.v1.Health/Watch",
                request_serializer=lambda req: req.SerializeToString()
                if hasattr(req, "SerializeToString")
                else b"",
                response_deserializer=lambda data: HealthCheckResponse(),  # pragma: no cover
            )

    def add_HealthServicer_to_server(servicer, server) -> None:  # pragma: no cover
        rpc_method_handlers = {
            "Check": grpc.aio.unary_unary_rpc_method_handler(
                servicer.Check,
                request_deserializer=lambda data: HealthCheckRequest(),
                response_serializer=lambda resp: b"",
            ),
            "Watch": grpc.aio.stream_stream_rpc_method_handler(
                servicer.Watch,
                request_deserializer=lambda data: HealthCheckRequest(),
                response_serializer=lambda resp: b"",
            ),
        }
        generic_handler = grpc.method_handlers_generic_handler(
            "grpc.health.v1.Health", rpc_method_handlers
        )
        server.add_generic_rpc_handlers((generic_handler,))

    health_pb2_grpc.HealthServicer = HealthServicer
    health_pb2_grpc.HealthStub = HealthStub
    health_pb2_grpc.add_HealthServicer_to_server = add_HealthServicer_to_server

    grpc_health = types.ModuleType("grpc_health")
    grpc_health.v1 = types.ModuleType("grpc_health.v1")
    sys.modules["grpc_health"] = grpc_health
    sys.modules["grpc_health.v1"] = grpc_health.v1
    sys.modules["grpc_health.v1.health_pb2"] = health_pb2
    sys.modules["grpc_health.v1.health_pb2_grpc"] = health_pb2_grpc
    grpc_health.v1.health_pb2 = health_pb2
    grpc_health.v1.health_pb2_grpc = health_pb2_grpc

# Import provide-testkit fixtures directly
import pytest

from pyvider.rpcplugin.config import RPCPluginConfig
from tests.fixtures import *

# Import provide-testkit fixtures directly
from provide.testkit.mocking.fixtures import (
    async_mock_factory,
    magic_mock_factory,
    spy_fixture,
    auto_patch,
    mock_open_fixture,
)
from provide.testkit.transport.fixtures import free_port, tcp_client_server
from provide.testkit.crypto import (
    client_cert,
    server_cert,
    ca_cert,
    valid_key_pem,
    valid_cert_pem,
    invalid_key_pem,
    invalid_cert_pem,
    malformed_cert_pem,
    empty_cert,
    temporary_cert_file,
    temporary_key_file,
    external_ca_pem,
)


def get_all_env_vars() -> list[str]:
    """
    Extract all environment variable keys from RPCPluginConfig metadata.

    This provides dynamic env var discovery without hardcoded constants,
    ensuring test isolation covers all config fields automatically.
    """
    return [
        field.metadata.get("env_var") for field in fields(RPCPluginConfig) if field.metadata.get("env_var")
    ]


@pytest.fixture
def _function_event_loop():
    """Provide the event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    # Cleanup pending tasks
    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.9+ uses asyncio.all_tasks without loop parameter
        pending = asyncio.all_tasks()
        pending = {task for task in pending if task.get_loop() == loop}

    for task in pending:
        task.cancel()

    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.close()


@pytest.fixture(autouse=True, scope="function")
def reset_rpcplugin_config_singleton():
    """
    Fixture to reset the RPCPluginConfig singleton and relevant env vars before each test.
    This ensures complete test isolation with respect to configuration.

    Uses metadata-driven env var discovery to eliminate hardcoded constants.
    """
    # Foundation config doesn't use singleton pattern like old implementation
    # Environment cleanup is sufficient for test isolation

    # Backup and clear all environment variables from config metadata
    env_keys_to_clear = get_all_env_vars()
    original_env_values = {key: os.environ.get(key) for key in env_keys_to_clear if key}

    for key in env_keys_to_clear:
        if key and key in os.environ:
            del os.environ[key]

    # The test runs now in a pristine environment. The first call to
    # RPCPluginConfig.from_env() in the test will create a fresh instance.
    yield

    # Teardown: Restore original environment variables
    for key, value in original_env_values.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:
            del os.environ[key]

    # Foundation config loads fresh from environment each time
    # No singleton cleanup needed


# 🐍🔌🧪🪄
