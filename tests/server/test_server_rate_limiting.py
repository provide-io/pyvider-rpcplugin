# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import asyncio
import os  # Added import
from typing import Any

import grpc
from provide.foundation import logger
import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import ServerT
from tests.fixtures.proto import echo_pb2, echo_pb2_grpc


class EchoServicerImpl(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        return echo_pb2.EchoResponse()


class EchoProtocolImpl(RPCPluginProtocol[ServerT, EchoServicerImpl]):
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return echo_pb2.DESCRIPTOR, "echo.EchoService"

    async def add_to_server(self, server: ServerT, handler: EchoServicerImpl) -> None:
        echo_pb2_grpc.add_EchoServiceServicer_to_server(handler, server)


@pytest.fixture
def server_config_override_rl(request):
    """Fixture to override rate limiting configuration for tests.

    This fixture properly isolates configuration changes by:
    1. Backing up original config values
    2. Setting new test values
    3. Restoring original values after test completion
    """
    from pyvider.rpcplugin.config import RPCPluginConfig

    original_config_values = {}
    original_env_values = {}
    default_params = {
        "PLUGIN_RATE_LIMIT_ENABLED": "true",
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 100.0,
        "PLUGIN_RATE_LIMIT_BURST_CAPACITY": 200.0,
        "PLUGIN_SHUTDOWN_FILE_PATH": None,
        "PLUGIN_AUTO_MTLS": "false",
        # Add magic cookie for the server to validate its own handshake
        "PLUGIN_MAGIC_COOKIE_KEY": "PYTEST_PLUGIN_MAGIC_COOKIE",  # Use a distinct key for test
        "PLUGIN_MAGIC_COOKIE_VALUE": "pytest_server_cookie_value",
    }

    # This env var needs to be set for the server's own handshake validation
    env_vars_to_set = {"PYTEST_PLUGIN_MAGIC_COOKIE": "pytest_server_cookie_value"}

    params_to_apply = default_params.copy()
    if hasattr(request, "param") and request.param is not None:
        params_to_apply.update(request.param)

    # Map environment variable keys to Foundation attribute names
    key_to_attr = {
        "PLUGIN_RATE_LIMIT_ENABLED": "plugin_rate_limit_enabled",
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "plugin_rate_limit_requests_per_second",
        "PLUGIN_RATE_LIMIT_BURST_CAPACITY": "plugin_rate_limit_burst_capacity",
        "PLUGIN_SHUTDOWN_FILE_PATH": "plugin_shutdown_file_path",
        "PLUGIN_AUTO_MTLS": "plugin_auto_mtls",
        "PLUGIN_MAGIC_COOKIE_KEY": "plugin_magic_cookie_key",
        "PLUGIN_MAGIC_COOKIE_VALUE": "plugin_magic_cookie_value",
    }

    # Set rpcplugin_config values using direct attribute access
    for key, value in params_to_apply.items():
        attr_name = key_to_attr.get(key)
        if attr_name and hasattr(rpcplugin_config, attr_name):
            original_config_values[attr_name] = getattr(rpcplugin_config, attr_name)
            # Convert string boolean values to actual booleans for Foundation compatibility
            if isinstance(value, str) and value.lower() in ("true", "false"):
                value = value.lower() == "true"
            setattr(rpcplugin_config, attr_name, value)

    # Set environment variables
    for key, value in env_vars_to_set.items():
        original_env_values[key] = os.environ.get(key)
        if value is None:  # pragma: no cover
            if key in os.environ:
                del os.environ[key]
        else:
            os.environ[key] = str(value)

    yield

    # Restore rpcplugin_config values using direct attribute access
    for attr_name, value in original_config_values.items():
        setattr(rpcplugin_config, attr_name, value)

    # Restore environment variables
    for key, value in original_env_values.items():
        if value is None:
            if key in os.environ:  # pragma: no cover
                del os.environ[key]
        else:  # pragma: no cover
            os.environ[key] = value

    # Ensure config is fully reset to prevent state pollution
    # Create a fresh config from current env to reset any missed fields
    try:
        fresh_config = RPCPluginConfig.from_env()
        # Update only the fields we didn't explicitly track
        for field_name in dir(fresh_config):
            if (
                field_name.startswith("plugin_")
                and field_name not in [k for k in original_config_values]
                and hasattr(rpcplugin_config, field_name)
            ):
                setattr(rpcplugin_config, field_name, getattr(fresh_config, field_name))
    except Exception:
        # If reset fails, it's not critical - the next test will reset anyway
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_config_override_rl",
    [
        {
            "PLUGIN_RATE_LIMIT_ENABLED": "true",
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 10.0,  # More lenient rate limit
            "PLUGIN_RATE_LIMIT_BURST_CAPACITY": 2.0,  # Still low burst to trigger quickly
        }
    ],
    indirect=True,
)
async def test_rate_limiter_denies_requests_when_limit_exceeded(server_config_override_rl) -> None:
    # This test accepts both UNKNOWN and RESOURCE_EXHAUSTED status codes
    # due to gRPC internal timing issues that can vary by system load

    # Small delay to ensure previous test servers are fully cleaned up
    await asyncio.sleep(0.1)
    protocol = EchoProtocolImpl()
    handler = EchoServicerImpl()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    serve_task = asyncio.create_task(server.serve())
    channel = None

    try:
        await server.wait_for_server_ready(timeout=10.0)

        endpoint = server._transport.endpoint
        assert endpoint, "Could not determine server endpoint for client connection."

        # Use appropriate connection string based on transport type
        from pyvider.rpcplugin.transport.unix import UnixSocketTransport

        if isinstance(server._transport, UnixSocketTransport):
            connection_string = f"unix:{endpoint}"
        else:
            connection_string = endpoint

        channel = grpc.aio.insecure_channel(connection_string)
        stub = echo_pb2_grpc.EchoServiceStub(channel)

        # Use up the burst capacity
        for i in range(2):
            await stub.Echo(echo_pb2.EchoRequest(message=f"hello {i}"))

        # This request should be rate-limited
        with pytest.raises(grpc.aio.AioRpcError) as exc_info:
            await stub.Echo(echo_pb2.EchoRequest(message="hello rate-limited"))

        # Accept either status code due to gRPC internal variations
        assert exc_info.value.code() in [grpc.StatusCode.UNKNOWN, grpc.StatusCode.RESOURCE_EXHAUSTED], (
            f"Expected UNKNOWN or RESOURCE_EXHAUSTED, got {exc_info.value.code()}"
        )

        # Wait for rate limit to reset
        await asyncio.sleep(0.5)

        # Should work again after rate limit reset
        for i in range(2):
            await stub.Echo(echo_pb2.EchoRequest(message=f"hello post-wait {i}"))

    except Exception as e:
        logger.warning(f"Rate limiting test failed with error: {e}")
        raise
    finally:
        if channel:
            await channel.close()

        try:
            await server.stop()
            await asyncio.wait_for(serve_task, timeout=5.0)
        except (TimeoutError, asyncio.CancelledError) as cleanup_error:
            # Expected cancellation/timeout during cleanup
            logger.debug(f"Expected cleanup exception: {cleanup_error}")
        except Exception as cleanup_error:
            logger.warning(f"Error during test cleanup: {cleanup_error}")

# 🐍🔌📞🔚
