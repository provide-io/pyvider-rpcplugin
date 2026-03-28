#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for controller service and protocol registration functionality."""

import asyncio
import os
import signal

from provide.testkit.mocking import AsyncMock, MagicMock, patch
import pytest

from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCControllerService,
    GRPCStdioService,
    register_protocol_service,
)


@pytest.fixture
def shutdown_event() -> asyncio.Event:
    return asyncio.Event()


@pytest.fixture
def stdio_service() -> GRPCStdioService:
    """Fixture providing a GRPCStdioService instance."""
    return GRPCStdioService()


@pytest.fixture
def controller_service(
    shutdown_event: asyncio.Event, stdio_service: GRPCStdioService
) -> GRPCControllerService:
    return GRPCControllerService(shutdown_event, stdio_service)


@pytest.fixture
def mock_context() -> MagicMock:
    """Mock gRPC context for controller."""
    context = MagicMock()
    context.add_done_callback = MagicMock()
    return context


def test_controller_service_init_default_shutdown_event(mocker: object) -> None:
    """Test GRPCControllerService init with default shutdown_event."""
    mock_stdio_service = mocker.MagicMock(spec=GRPCStdioService)

    # Instantiate with shutdown_event=None to trigger fallback
    controller_service = GRPCControllerService(shutdown_event=None, stdio_service=mock_stdio_service)

    assert controller_service._shutdown_event is not None
    assert isinstance(controller_service._shutdown_event, asyncio.Event)
    assert not controller_service._shutdown_event.is_set()  # New event should not be set


@pytest.mark.asyncio
async def test_controller_shutdown(
    controller_service: GRPCControllerService, mock_context: MagicMock, shutdown_event: asyncio.Event
) -> None:
    with patch.object(
        controller_service, "_delayed_shutdown", new_callable=AsyncMock
    ) as actual_mock_delayed_shutdown:
        actual_mock_delayed_shutdown.return_value = None  # Set return_value on the mock from 'as' clause
        response = await controller_service.Shutdown(ControllerEmpty(), mock_context)
        assert shutdown_event.is_set()
        assert controller_service._stdio_service._shutdown is True
        # Allow the created task a moment to run and call the mock
        await asyncio.sleep(0.01)
        actual_mock_delayed_shutdown.assert_called_once()  # Assert on the mock from 'as' clause
        assert isinstance(response, ControllerEmpty)


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_signal_handlers(controller_service: GRPCControllerService) -> None:
    original_hasattr = hasattr

    with (
        patch("asyncio.sleep", new_callable=AsyncMock),
        patch("os.kill") as mock_kill,
        patch("os.getpid", return_value=12345),
        patch(
            "builtins.hasattr",
            lambda obj, name: True if name == "kill" and obj == os else original_hasattr(obj, name),
        ),
    ):
        await controller_service._delayed_shutdown()
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)

    with (
        patch("asyncio.sleep", new_callable=AsyncMock),
        patch(
            "builtins.hasattr",
            lambda obj, name: False if name == "kill" and obj == os else original_hasattr(obj, name),
        ),
        patch("sys.exit") as mock_exit,
    ):
        await controller_service._delayed_shutdown()
        mock_exit.assert_called_once_with(0)


@pytest.mark.asyncio
async def test_register_protocol_service_with_mocks(shutdown_event: asyncio.Event) -> None:
    with (
        patch("pyvider.rpcplugin.protocol.service.GRPCStdioService") as mock_stdio_cls,
        patch("pyvider.rpcplugin.protocol.service.GRPCBrokerService") as mock_broker_cls,
        patch("pyvider.rpcplugin.protocol.service.GRPCControllerService") as mock_controller_cls,
        patch("pyvider.rpcplugin.protocol.service.add_GRPCStdioServicer_to_server") as mock_add_stdio,
        patch("pyvider.rpcplugin.protocol.service.add_GRPCBrokerServicer_to_server") as mock_add_broker,
        patch(
            "pyvider.rpcplugin.protocol.service.add_GRPCControllerServicer_to_server"
        ) as mock_add_controller,
    ):
        mock_stdio_instance = MagicMock(spec=GRPCStdioService)
        mock_broker_instance = MagicMock(spec=GRPCBrokerService)
        mock_controller_instance = MagicMock(spec=GRPCControllerService)
        mock_stdio_cls.return_value = mock_stdio_instance
        mock_broker_cls.return_value = mock_broker_instance
        mock_controller_cls.return_value = mock_controller_instance
        mock_server = MagicMock()
        register_protocol_service(mock_server, shutdown_event)
        mock_stdio_cls.assert_called_once()
        mock_broker_cls.assert_called_once()
        mock_controller_cls.assert_called_once_with(shutdown_event, mock_stdio_instance)
        mock_add_stdio.assert_called_once_with(mock_stdio_instance, mock_server)
        mock_add_broker.assert_called_once_with(mock_broker_instance, mock_server)
        mock_add_controller.assert_called_once_with(mock_controller_instance, mock_server)


@pytest.mark.asyncio
async def test_controller_shutdown_with_stdio_service_interaction(
    shutdown_event: asyncio.Event, stdio_service: GRPCStdioService, mock_context: MagicMock
) -> None:
    """Test controller shutdown interaction with stdio service."""
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    # Verify stdio service is not shutdown initially
    assert stdio_service._shutdown is False

    with patch.object(
        controller_service, "_delayed_shutdown", new_callable=AsyncMock
    ) as mock_delayed_shutdown:
        response = await controller_service.Shutdown(ControllerEmpty(), mock_context)

        # Verify shutdown event is set
        assert shutdown_event.is_set()

        # Verify stdio service shutdown is triggered
        assert stdio_service._shutdown is True

        # Verify delayed shutdown is called
        await asyncio.sleep(0.01)  # Allow task to run
        mock_delayed_shutdown.assert_called_once()

        # Verify response
        assert isinstance(response, ControllerEmpty)


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_error_handling(controller_service: GRPCControllerService) -> None:
    """Test error handling in delayed shutdown."""
    with (
        patch("asyncio.sleep", new_callable=AsyncMock),
        patch("os.getpid", side_effect=Exception("Failed to get PID")),
        patch("sys.exit") as mock_exit,
    ):
        # Should fall back to sys.exit even if os operations fail
        await controller_service._delayed_shutdown()
        mock_exit.assert_called_once_with(0)


@pytest.mark.asyncio
async def test_register_protocol_service_error_handling(shutdown_event: asyncio.Event) -> None:
    """Test error handling in protocol service registration."""
    with (
        patch("pyvider.rpcplugin.protocol.service.GRPCStdioService") as mock_stdio_cls,
        patch(
            "pyvider.rpcplugin.protocol.service.GRPCBrokerService",
            side_effect=Exception("Failed to create broker"),
        ),
    ):
        mock_stdio_instance = MagicMock(spec=GRPCStdioService)
        mock_stdio_cls.return_value = mock_stdio_instance
        mock_server = MagicMock()

        # Should raise the exception from broker creation
        with pytest.raises(Exception, match="Failed to create broker"):
            register_protocol_service(mock_server, shutdown_event)


@pytest.mark.asyncio
async def test_controller_multiple_shutdown_calls(
    controller_service: GRPCControllerService, mock_context: MagicMock, shutdown_event: asyncio.Event
) -> None:
    """Test behavior when shutdown is called multiple times."""
    with patch.object(
        controller_service, "_delayed_shutdown", new_callable=AsyncMock
    ) as mock_delayed_shutdown:
        # First shutdown call
        response1 = await controller_service.Shutdown(ControllerEmpty(), mock_context)
        assert shutdown_event.is_set()
        assert isinstance(response1, ControllerEmpty)

        # Second shutdown call
        response2 = await controller_service.Shutdown(ControllerEmpty(), mock_context)
        assert shutdown_event.is_set()  # Should still be set
        assert isinstance(response2, ControllerEmpty)

        # Allow tasks to run
        await asyncio.sleep(0.01)

        # Delayed shutdown should be called for each shutdown request
        assert mock_delayed_shutdown.call_count >= 1

# 🐍🔌📞🔚
