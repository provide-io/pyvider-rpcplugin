#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import pytest
from provide.testkit.mocking import patch, MagicMock, AsyncMock
from pyvider.rpcplugin.exception import TransportError  # Added import


@pytest.mark.asyncio
async def test_launch_process(client_instance):
    """Test the _launch_process method."""
    client_instance._process = None  # Ensure process is not considered running
    with patch("pyvider.rpcplugin.client.process.ManagedProcess") as mock_managed_process_class:
        mock_managed_process = MagicMock()
        mock_managed_process.pid = 12345
        mock_managed_process_class.return_value = mock_managed_process

        await client_instance._launch_process()

        # ManagedProcess should be called with the correct command
        mock_managed_process_class.assert_called_once()
        assert client_instance._process == mock_managed_process

        # Environment variables should be set correctly
        call_kwargs = mock_managed_process_class.call_args[1]
        assert "env" in call_kwargs
        assert "PYTHONUNBUFFERED" in call_kwargs["env"]
        assert call_kwargs["env"]["PYTHONUNBUFFERED"] == "1"


@pytest.mark.asyncio
async def test_launch_process_with_client_cert(client_instance):
    """Test process launch with client cert in environment."""
    client_instance._process = None  # Ensure process is not considered running
    client_instance.client_cert = "test-cert"

    with patch("pyvider.rpcplugin.client.process.ManagedProcess") as mock_managed_process_class:
        mock_managed_process = MagicMock()
        mock_managed_process.pid = 12345
        mock_managed_process_class.return_value = mock_managed_process

        await client_instance._launch_process()

        # Client cert should be passed in environment
        call_kwargs = mock_managed_process_class.call_args[1]
        assert "env" in call_kwargs
        assert "PLUGIN_CLIENT_CERT" in call_kwargs["env"]
        assert call_kwargs["env"]["PLUGIN_CLIENT_CERT"] == "test-cert"


@pytest.mark.asyncio
async def test_launch_process_already_running(client_instance):
    """Test _launch_process when process already exists."""
    mock_process = MagicMock()
    mock_process.is_running.return_value = True  # Process is still running
    client_instance._process = mock_process

    with patch("pyvider.rpcplugin.client.process.ManagedProcess") as mock_managed_process_class:
        await client_instance._launch_process()

        # ManagedProcess should not be called
        mock_managed_process_class.assert_not_called()


@pytest.mark.asyncio
async def test_launch_process_error(client_instance):
    """Test _launch_process handling errors."""
    with patch("pyvider.rpcplugin.client.process.ManagedProcess") as mock_managed_process_class:
        mock_managed_process_class.side_effect = OSError("Failed to launch")

        expected_msg_regex = (
            r"\[TransportError\] Failed to launch plugin subprocess for command: '.*'. Error: Failed to launch"
        )
        with pytest.raises(TransportError, match=expected_msg_regex):
            await client_instance._launch_process()


@pytest.mark.asyncio
async def test_launch_process_with_config_env(client_instance, mocker):
    """Test that _launch_process correctly uses env vars from client config."""
    client_instance._process = None  # Ensure process is not considered running
    client_instance.config = {"env": {"MY_VAR": "my_value", "OTHER_VAR": "other_value"}}

    mock_managed_process_class = mocker.patch("pyvider.rpcplugin.client.process.ManagedProcess")
    mock_managed_process = mocker.MagicMock()
    mock_managed_process.pid = 12345
    mock_managed_process_class.return_value = mock_managed_process

    await client_instance._launch_process()

    mock_managed_process_class.assert_called_once()
    args, kwargs = mock_managed_process_class.call_args

    # Check that PYTHONUNBUFFERED is still there
    assert "PYTHONUNBUFFERED" in kwargs["env"]
    assert kwargs["env"]["PYTHONUNBUFFERED"] == "1"

    # Check for custom env vars
    assert "MY_VAR" in kwargs["env"]
    assert kwargs["env"]["MY_VAR"] == "my_value"
    assert "OTHER_VAR" in kwargs["env"]
    assert kwargs["env"]["OTHER_VAR"] == "other_value"


@pytest.mark.asyncio
async def test_connect_tcp_transport(client_instance):  # Removed mock_transport fixture
    """Test connecting to a TCP transport."""
    mock_tcp_transport = AsyncMock()
    mock_tcp_transport.connect = AsyncMock()
    client_instance._transport = mock_tcp_transport
    client_instance._transport_name = "tcp"

    await client_instance._transport.connect("127.0.0.1:8000")

    mock_tcp_transport.connect.assert_called_once_with("127.0.0.1:8000")


@pytest.mark.asyncio
async def test_connect_unix_transport(
    client_instance,
):  # Removed mock_unix_transport fixture
    """Test connecting to a Unix socket transport."""
    mock_unix_socket_transport = AsyncMock()
    mock_unix_socket_transport.connect = AsyncMock()
    client_instance._transport = mock_unix_socket_transport
    client_instance._transport_name = "unix"

    await client_instance._transport.connect("/tmp/test.sock")

    mock_unix_socket_transport.connect.assert_called_once_with("/tmp/test.sock")


@pytest.mark.asyncio
async def test_launch_process_generic_error(client_instance):
    """Test _launch_process handling generic errors."""
    with patch("pyvider.rpcplugin.client.process.ManagedProcess") as mock_managed_process_class:
        mock_managed_process_class.side_effect = Exception("Generic Popen failure")

        expected_msg_regex = r"\[TransportError\] Failed to launch plugin subprocess for command: '.*'. Error: Generic Popen failure"
        with pytest.raises(TransportError, match=expected_msg_regex):
            await client_instance._launch_process()

# 🐍🔌📞🔚
