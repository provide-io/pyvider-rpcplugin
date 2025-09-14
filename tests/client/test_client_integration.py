# tests/client/test_client_integration.py

import pytest
import asyncio
from unittest.mock import patch

from provide.testkit.crypto import client_cert
from provide.testkit.mocking import async_mock_factory, magic_mock_factory
from provide.testkit.process import subprocess_fixtures

from pyvider.rpcplugin.client.core import RPCPluginClient


@pytest.mark.asyncio
async def test_client_integration(test_client_command, client_cert, async_mock_factory, magic_mock_factory):
    """
    Integration test for RPCPluginClient full lifecycle.

    Tests the complete flow:
    1. Create client
    2. Start client (setup certs, launch process, handshake, create channel)
    3. Use client (read logs, open subchannel, shutdown plugin)
    4. Close client
    """
    # Create mocks using provide-testkit factories
    mock_popen = magic_mock_factory(name="subprocess.Popen")
    mock_read_handshake_line = async_mock_factory(name="read_handshake_line", return_value="1|1|tcp|127.0.0.1:8000|grpc|")
    mock_channel_func = async_mock_factory(name="grpc_channel_func")
    mock_stdio_stub_class = magic_mock_factory(name="GRPCStdioStub")
    mock_broker_stub_class = magic_mock_factory(name="GRPCBrokerStub")
    mock_controller_stub_class = magic_mock_factory(name="GRPCControllerStub")
    mock_transport_class = magic_mock_factory(name="TCPSocketTransport")

    # Mock all external dependencies
    with (
        patch("pyvider.rpcplugin.client.core.subprocess.Popen", mock_popen),
        patch(
            "pyvider.rpcplugin.client.core.RPCPluginClient._read_raw_handshake_line_from_stdout",
            mock_read_handshake_line,
        ),
        patch("provide.foundation.crypto.Certificate") as mock_cert_class,
        patch(
            "pyvider.rpcplugin.client.core.grpc.aio.insecure_channel",
            mock_channel_func
        ),
        patch("pyvider.rpcplugin.client.core.GRPCStdioStub", mock_stdio_stub_class),
        patch("pyvider.rpcplugin.client.core.GRPCBrokerStub", mock_broker_stub_class),
        patch(
            "pyvider.rpcplugin.client.core.GRPCControllerStub",
            mock_controller_stub_class
        ),
        patch(
            "pyvider.rpcplugin.transport.TCPSocketTransport",
            mock_transport_class
        ),
        patch("threading.Thread"),
    ):
        # Mock process using provide-testkit patterns
        mock_process = magic_mock_factory(name="plugin_process")
        mock_process.stdout = magic_mock_factory(name="process_stdout")
        mock_process.stderr = magic_mock_factory(name="process_stderr")
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        # Mock certificate to use testkit cert but override for test expectations
        mock_cert_class.return_value = client_cert
        mock_cert_class.create_self_signed_client_cert = magic_mock_factory(name="create_self_signed_cert")
        test_cert_mock = magic_mock_factory(name="test_cert")
        test_cert_mock.cert = "test-cert"
        test_cert_mock.key = "test-key"
        mock_cert_class.create_self_signed_client_cert.return_value = test_cert_mock

        # Mock transport using provide-testkit
        mock_transport = async_mock_factory(name="tcp_transport")
        mock_transport.endpoint = "127.0.0.1:8000"
        mock_transport_class.return_value = mock_transport

        # Mock channel using provide-testkit
        mock_channel = async_mock_factory(name="grpc_channel")
        mock_channel.channel_ready = async_mock_factory(name="channel_ready")
        mock_channel_func.return_value = mock_channel

        # Mock stubs using provide-testkit
        mock_stdio_stub = magic_mock_factory(name="stdio_stub")
        mock_broker_stub = magic_mock_factory(name="broker_stub")
        mock_controller_stub = magic_mock_factory(name="controller_stub")

        mock_stdio_stub_class.return_value = mock_stdio_stub
        mock_broker_stub_class.return_value = mock_broker_stub
        mock_controller_stub_class.return_value = mock_controller_stub

        # Setup mock stdio stream - fix coroutine issue
        async def mock_stream_stdio(_):
            log_message = magic_mock_factory(name="log_message")
            log_message.channel = 1
            log_message.data = b"log message"
            yield log_message
            await asyncio.sleep(0.1)

        mock_stdio_stub.StreamStdio = lambda _: mock_stream_stdio(_)

        # Mock broker call using provide-testkit
        mock_call_object = async_mock_factory(name="broker_call_object")
        # StartStream itself is a synchronous method returning an awaitable call object
        mock_broker_stub.StartStream = magic_mock_factory(name="start_stream", return_value=mock_call_object)

        # Mock shutdown using provide-testkit
        mock_controller_stub.Shutdown = async_mock_factory(name="shutdown")

        # Create and configure client
        client = RPCPluginClient(command=test_client_command)

        # Mock config for mTLS using Foundation patterns
        with patch(
            "pyvider.rpcplugin.client.core.rpcplugin_config.plugin_auto_mtls", True
        ):

            # Start client
            await client.start()

            # Verify client initialized correctly
            assert client._process == mock_process
            assert client.client_cert == "test-cert"
            assert client.grpc_channel == mock_channel

        # Test broker subchannel
        await client.open_broker_subchannel(123, "127.0.0.1:8001")
        if client._broker_task:  # Good practice to check if the task was created
            await client._broker_task
        mock_broker_stub.StartStream.assert_called_once()

        # Test shutdown
        await client.shutdown_plugin()
        mock_controller_stub.Shutdown.assert_called_once()

        # Clean up
        await client.close()

        # Verify resources cleaned up
        assert client.grpc_channel is None
        assert client._process is None
        assert client._transport is None


# 🐍🔌🧪🪄
