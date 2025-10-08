import asyncio
import subprocess

import pytest
from provide.testkit.mocking import AsyncMock, MagicMock

from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.exception import TransportError


@pytest.fixture
def basic_client(mocker: object) -> RPCPluginClient:
    client = RPCPluginClient(command=['dummy'])
    client.logger = mocker.MagicMock(spec=['debug', 'error'])
    return client


@pytest.mark.asyncio
async def test_relay_stderr_background_reads_lines(basic_client: RPCPluginClient, mocker: object) -> None:
    process = MagicMock(spec=subprocess.Popen)
    process.poll.side_effect = [None, None, 0]
    process.stderr = MagicMock()

    future1 = asyncio.Future()
    future1.set_result(b'')
    future2 = asyncio.Future()
    future2.set_result(b'line\n')

    loop_mock = MagicMock()
    loop_mock.run_in_executor.side_effect = [future1, future2]
    mocker.patch('asyncio.get_event_loop', return_value=loop_mock)
    mocker.patch('asyncio.sleep', AsyncMock())

    basic_client._process = process
    await basic_client._relay_stderr_background()
    loop_mock.run_in_executor.assert_called()


@pytest.mark.asyncio
async def test_get_stderr_output_error(basic_client: RPCPluginClient) -> None:
    process = MagicMock(spec=subprocess.Popen)
    process.stderr.read.side_effect = RuntimeError('boom')
    basic_client._process = process
    assert 'Error reading stderr' in basic_client._get_stderr_output()


@pytest.mark.asyncio
async def test_launch_process_failure(basic_client: RPCPluginClient, mocker: object) -> None:
    mocker.patch('pyvider.rpcplugin.client.process.subprocess.Popen', side_effect=RuntimeError('start fail'))
    with pytest.raises(TransportError, match='start fail'):
        await basic_client._launch_process()
