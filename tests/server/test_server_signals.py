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
async def test_register_signal_handlers_suppresses_errors(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_transport,
):
    """
    Tests that _register_signal_handlers suppresses registration errors
    and does not log an exception, confirming robust behavior on platforms
    where signal handling might not be supported.
    """
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

    # This call should now complete without raising an exception due to contextlib.suppress
    server._register_signal_handlers()

    # Assert that the exception logger was NOT called, as the error is suppressed.
    mocked_logger_exception.assert_not_called()
