#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for handshake retry logic and complex scenarios."""

import subprocess

from provide.testkit.mocking import AsyncMock
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient


@pytest.fixture
def client_instance_for_retry_tests(mocker: object) -> RPCPluginClient:
    client = RPCPluginClient(command=["dummy-plugin-cmd"])
    mock_process_obj = mocker.MagicMock(spec=subprocess.Popen)
    mock_process_obj.poll.return_value = None
    mock_process_obj.returncode = None
    mock_process_obj.stderr = mocker.MagicMock()
    mock_process_obj.stdout = mocker.MagicMock()
    client._process = mock_process_obj
    return client


@pytest.mark.asyncio
async def test_connect_handshake_retry_success_first_attempt(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    # Mock Foundation attributes directly
    mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.plugin_client_retry_enabled", True)
    mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.plugin_client_max_retries", 3)
    mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.plugin_client_initial_backoff_ms", 10)
    mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.plugin_client_max_backoff_ms", 100)
    mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.plugin_client_retry_jitter_ms", 5)
    mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.plugin_client_retry_total_timeout_s", 5)

    mock_perform_handshake = mocker.patch(
        "pyvider.rpcplugin.client.core.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
    )
    mock_create_grpc_channel = mocker.patch(
        "pyvider.rpcplugin.client.core.RPCPluginClient._create_grpc_channel",
        new_callable=AsyncMock,
    )

    async def side_effect_perform_handshake() -> None:
        client_instance._address = "mock_address"
        client_instance._transport_name = "mock_transport"
        client_instance._protocol_version = 1
        client_instance._server_cert = None
        client_instance._transport = AsyncMock()

    mock_perform_handshake.side_effect = side_effect_perform_handshake

    async def side_effect_create_channel() -> None:
        client_instance.target_endpoint = "mock_target_endpoint"
        client_instance.grpc_channel = AsyncMock()

    mock_create_grpc_channel.side_effect = side_effect_create_channel


    client_instance.is_started = False
    client_instance._handshake_complete_event.clear()
    client_instance._handshake_failed_event.clear()
    client_instance.grpc_channel = None
    client_instance._transport = None

    await client_instance._connect_and_handshake_with_retry()

    mock_perform_handshake.assert_called_once()
    mock_create_grpc_channel.assert_called_once()
    assert client_instance.is_started is True
    assert client_instance._handshake_complete_event.is_set() is True
    assert client_instance._handshake_failed_event.is_set() is False

# 📞🔌🔚
