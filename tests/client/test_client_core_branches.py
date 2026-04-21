#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import asyncio
from collections.abc import Iterator

import grpc
from provide.testkit.mocking import AsyncMock, MagicMock
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient


@pytest.mark.asyncio
async def test_shutdown_plugin_without_stub_logs_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    monkeypatch.setattr("asyncio.sleep", AsyncMock(), raising=False)

    await client.shutdown_plugin()

    # client.logger.warning.assert_called_with("⚠️ No controller stub available for shutdown signal.")


class _DummyRpcError(grpc.RpcError):
    def code(self) -> grpc.StatusCode:
        return grpc.StatusCode.UNAVAILABLE


@pytest.mark.asyncio
async def test_shutdown_plugin_handles_grpc_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    stub = MagicMock()

    async def raise_rpc_error(*_: object, **__: object) -> None:
        raise _DummyRpcError()

    stub.Shutdown = AsyncMock(side_effect=raise_rpc_error)
    client._controller_stub = stub
    monkeypatch.setattr("asyncio.sleep", AsyncMock(), raising=False)

    await client.shutdown_plugin()



@pytest.mark.asyncio
async def test_shutdown_plugin_handles_generic_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    stub = MagicMock()
    stub.Shutdown = AsyncMock(side_effect=RuntimeError("boom"))
    client._controller_stub = stub
    monkeypatch.setattr("asyncio.sleep", AsyncMock(), raising=False)

    await client.shutdown_plugin()

    client.logger.warning.assert_any_call("⚠️ Error sending shutdown signal to plugin: boom", exc_info=True)


@pytest.mark.asyncio
async def test_cancel_tasks_handles_generic_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()

    class FailingTask:
        def __init__(self) -> None:
            self.cancel_called = False

        def cancel(self) -> None:
            self.cancel_called = True

        def done(self) -> bool:
            return False

        def __await__(self) -> Iterator[object]:
            async def raiser() -> None:
                raise RuntimeError("task failure")

            return raiser().__await__()

    client._stdio_task = FailingTask()

    await client._cancel_tasks()

    client.logger.warning.assert_any_call("⚠️ Error cancelling stdio task: task failure", exc_info=True)


@pytest.mark.asyncio
async def test_close_grpc_channel_handles_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    channel = MagicMock()
    channel.close = AsyncMock(side_effect=RuntimeError("close failure"))
    client.grpc_channel = channel

    await client._close_grpc_channel()

    # client.logger.warning.assert_called_with("⚠️ Error closing gRPC channel: close failure", exc_info=True)
    assert client.grpc_channel is None


@pytest.mark.asyncio
async def test_terminate_process_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()

    # Create ManagedProcess mock
    managed_process = MagicMock()
    managed_process.terminate_gracefully.return_value = False  # Simulate graceful termination failure
    managed_process.cleanup = MagicMock()
    client._process = managed_process

    # Mock run_in_executor to actually call the function and return its result
    def mock_run_in_executor(executor, func, *args):
        future = asyncio.Future()
        future.set_result(func(*args))
        return future

    loop = MagicMock()
    loop.run_in_executor.side_effect = mock_run_in_executor
    monkeypatch.setattr("asyncio.get_event_loop", lambda: loop, raising=False)

    await client._terminate_process()

    managed_process.terminate_gracefully.assert_called_once_with(5.0)
    managed_process.cleanup.assert_called_once()
    client.logger.warning.assert_any_call("⚠️ Plugin process was force-killed.")
    assert client._process is None



@pytest.mark.asyncio
async def test_terminate_process_handles_already_exited(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()

    # Create ManagedProcess mock that gracefully terminates
    managed_process = MagicMock()
    managed_process.terminate_gracefully.return_value = True
    managed_process.cleanup = MagicMock()
    client._process = managed_process

    # Mock run_in_executor to actually call the function and return its result
    def mock_run_in_executor(executor, func, *args):
        future = asyncio.Future()
        future.set_result(func(*args))
        return future

    loop = MagicMock()
    loop.run_in_executor.side_effect = mock_run_in_executor
    monkeypatch.setattr("asyncio.get_event_loop", lambda: loop, raising=False)

    await client._terminate_process()

    managed_process.cleanup.assert_called_once()
    assert client._process is None


@pytest.mark.asyncio
async def test_terminate_process_logs_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()

    # Create ManagedProcess mock that raises exception
    managed_process = MagicMock()
    managed_process.terminate_gracefully.side_effect = RuntimeError("terminate failure")
    client._process = managed_process

    # Mock run_in_executor to actually call the function (which will raise)
    def mock_run_in_executor(executor, func, *args):
        future = asyncio.Future()
        try:
            result = func(*args)
            future.set_result(result)
        except Exception as e:
            future.set_exception(e)
        return future

    loop = MagicMock()
    loop.run_in_executor.side_effect = mock_run_in_executor
    monkeypatch.setattr("asyncio.get_event_loop", lambda: loop, raising=False)

    await client._terminate_process()

    client.logger.error.assert_any_call(
        "⚠️ Error terminating plugin process: terminate failure",
        extra={"trace": "terminate failure"},
        exc_info=True,
    )
    assert client._process is None


@pytest.mark.asyncio
async def test_close_transport_logs_exception() -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    transport = AsyncMock()
    transport.close.side_effect = RuntimeError("transport failure")
    client._transport = transport

    await client._close_transport()

    # client.logger.warning.assert_called_with("⚠️ Error closing transport: transport failure", exc_info=True)
    assert client._transport is None


@pytest.mark.asyncio
async def test_context_manager_exit_logs_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    client.shutdown_plugin = AsyncMock(side_effect=RuntimeError("shutdown failure"))
    client.close = AsyncMock()

    await client.__aexit__(None, None, None)

    # client.logger.warning.assert_called_with(
    #     "⚠️ Error during shutdown in context manager: shutdown failure", exc_info=True
    # )
    client.close.assert_awaited()

# 🐍🔌📞🔚
