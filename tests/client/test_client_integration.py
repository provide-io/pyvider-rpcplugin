# tests/client/test_client_integration.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from pyvider.rpcplugin.client.base import RPCPluginClient


@pytest.mark.asyncio
async def test_client_integration(test_client_command):
    """
    Integration test for RPCPluginClient full lifecycle.

    Tests the complete flow:
    1. Create client
    2. Start client (setup certs, launch process, handshake, create channel)
    3. Use client (read logs, open subchannel, shutdown plugin)
    4. Close client
    """
    # Mock all external dependencies
    with (
        patch("pyvider.rpcplugin.client.base.subprocess.Popen") as mock_popen,
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._read_raw_handshake_line_from_stdout",
            new_callable=AsyncMock,
        ) as mock_read_handshake_line,
        patch("pyvider.rpcplugin.client.base.Certificate") as mock_cert_class,
        patch(
            "pyvider.rpcplugin.client.base.grpc.aio.insecure_channel"
        ) as mock_channel_func,
        patch("pyvider.rpcplugin.client.base.GRPCStdioStub") as mock_stdio_stub_class,
        patch("pyvider.rpcplugin.client.base.GRPCBrokerStub") as mock_broker_stub_class,
        patch(
            "pyvider.rpcplugin.client.base.GRPCControllerStub"
        ) as mock_controller_stub_class,
        patch(
            "pyvider.rpcplugin.client.base.TCPSocketTransport"
        ) as mock_transport_class,
        patch("threading.Thread"),
    ):  # Corrected target for threading.Thread
        mock_read_handshake_line.return_value = "1|1|tcp|127.0.0.1:8000|grpc|"

        # Mock process
        mock_process = MagicMock()
        mock_process.stdout = MagicMock()
        mock_process.stderr = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        # Mock certificate
        mock_cert = MagicMock()
        mock_cert.cert = "test-cert"
        mock_cert.key = "test-key"
        mock_cert_class.return_value = mock_cert

        # Mock transport
        mock_transport = AsyncMock()
        mock_transport.endpoint = "127.0.0.1:8000"
        mock_transport_class.return_value = mock_transport

        # Mock channel
        mock_channel = AsyncMock()
        mock_channel.channel_ready = AsyncMock()
        mock_channel_func.return_value = mock_channel

        # Mock stubs
        mock_stdio_stub = MagicMock()
        mock_broker_stub = MagicMock()
        mock_controller_stub = MagicMock()

        mock_stdio_stub_class.return_value = mock_stdio_stub
        mock_broker_stub_class.return_value = mock_broker_stub
        mock_controller_stub_class.return_value = mock_controller_stub

        # Setup mock stdio stream
        async def mock_stream_stdio(_):
            yield MagicMock(channel=1, data=b"log message")
            await asyncio.sleep(0.1)

        mock_stdio_stub.StreamStdio = mock_stream_stdio

        # Refined Mock broker call
        mock_call_object = (
            AsyncMock()
        )  # This will be the object returned by StartStream
        # StartStream itself is a synchronous method returning an awaitable call object
        mock_broker_stub.StartStream = MagicMock(return_value=mock_call_object)

        # Mock shutdown
        mock_controller_stub.Shutdown = AsyncMock()

        # Create and configure client
        client = RPCPluginClient(command=test_client_command)

        # Mock config for mTLS
        with patch(
            "pyvider.rpcplugin.client.base.rpcplugin_config.get"
        ) as mock_config_get:
            mock_config_get.side_effect = (
                lambda key, default=None: "true" if key == "PLUGIN_AUTO_MTLS" else None
            )

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
