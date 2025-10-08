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

    client.logger.warning.assert_called_with("⚠️ No controller stub available for shutdown signal.")


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

    client.logger.debug.assert_any_call("🔌 Plugin shutdown RPC completed: StatusCode.UNAVAILABLE")


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

    client.logger.warning.assert_called_with("⚠️ Error closing gRPC channel: close failure", exc_info=True)
    assert client.grpc_channel is None


@pytest.mark.asyncio
async def test_terminate_process_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    process = MagicMock()
    process.poll.return_value = None
    process.wait.return_value = None
    client._process = process

    loop = MagicMock()
    fut = asyncio.Future()
    loop.run_in_executor.return_value = fut
    monkeypatch.setattr("asyncio.get_event_loop", lambda: loop, raising=False)

    async def raise_timeout(awaitable: object, timeout: float) -> None:
        raise TimeoutError()

    monkeypatch.setattr("pyvider.rpcplugin.client.core.asyncio.wait_for", raise_timeout, raising=True)

    await client._terminate_process()

    process.kill.assert_called_once()
    client.logger.warning.assert_any_call("⚠️ Plugin process did not terminate gracefully, killing...")
    assert client._process is None

    fut.cancel()


@pytest.mark.asyncio
async def test_terminate_process_handles_already_exited() -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    process = MagicMock()
    process.poll.return_value = 0
    client._process = process

    await client._terminate_process()

    client.logger.debug.assert_any_call("✅ Plugin process already terminated.")
    assert client._process is None


@pytest.mark.asyncio
async def test_terminate_process_logs_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    process = MagicMock()
    process.poll.return_value = None
    process.terminate.side_effect = RuntimeError("terminate failure")
    client._process = process

    await client._terminate_process()

    client.logger.error.assert_any_call(
        "⚠️ Error sending terminate signal to plugin process: terminate failure",
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

    client.logger.warning.assert_called_with("⚠️ Error closing transport: transport failure", exc_info=True)
    assert client._transport is None


@pytest.mark.asyncio
async def test_context_manager_exit_logs_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RPCPluginClient(command=["dummy"])
    client.logger = MagicMock()
    client.shutdown_plugin = AsyncMock(side_effect=RuntimeError("shutdown failure"))
    client.close = AsyncMock()

    await client.__aexit__(None, None, None)

    client.logger.warning.assert_called_with(
        "⚠️ Error during shutdown in context manager: shutdown failure", exc_info=True
    )
    client.close.assert_awaited()
