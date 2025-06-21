import asyncio
import pytest
import contextlib
from unittest.mock import AsyncMock, patch

from pyvider.rpcplugin.server import RPCPluginServer

from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
)

@pytest.mark.asyncio
async def test_register_signal_handlers_exception_logging(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_transport,
):
    mocked_logger_exception = mocker.patch("pyvider.rpcplugin.server.logger.exception")

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=mock_server_transport,
    )

    mock_loop = mocker.MagicMock()
    mock_loop.add_signal_handler.side_effect = RuntimeError(
        "Test signal registration error"
    )
    mocker.patch("asyncio.get_event_loop", return_value=mock_loop)

    server._register_signal_handlers()

    mocked_logger_exception.assert_called_once()
    args, kwargs = mocked_logger_exception.call_args
    assert "Error registering signal handlers" in args[0]
    assert "Test signal registration error" in kwargs.get("extra", {}).get("error", "")
