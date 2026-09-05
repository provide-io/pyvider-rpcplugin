#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import asyncio
import subprocess  # nosec

import pytest
from provide.testkit.mocking import AsyncMock, MagicMock

from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.exception import TransportError


@pytest.fixture
def basic_client(mocker: object) -> RPCPluginClient:
    client = RPCPluginClient(command=["dummy"])
    return client


@pytest.mark.asyncio
async def test_relay_stderr_background_reads_lines(basic_client: RPCPluginClient, mocker: object) -> None:
    # Create underlying Popen mock
    popen_mock = MagicMock(spec=subprocess.Popen)
    popen_mock.poll.side_effect = [None, None, 0]
    popen_mock.stderr = MagicMock()

    # Create ManagedProcess wrapper mock
    managed_process = MagicMock()
    managed_process.process = popen_mock
    managed_process.is_running.side_effect = [True, True, False]

    future1 = asyncio.Future()
    future1.set_result(b"")
    future2 = asyncio.Future()
    future2.set_result(b"line\n")

    loop_mock = MagicMock()
    loop_mock.run_in_executor.side_effect = [future1, future2]
    mocker.patch("asyncio.get_event_loop", return_value=loop_mock)
    mocker.patch("asyncio.sleep", AsyncMock())

    basic_client._process = managed_process
    await basic_client._relay_stderr_background()
    loop_mock.run_in_executor.assert_called()


@pytest.mark.asyncio
async def test_get_stderr_output_survives_a_broken_pipe(basic_client: RPCPluginClient) -> None:
    """A pipe that raises on read cannot affect the report, which never reads it.

    The relay owns stderr; see tests/client/test_stderr_tail.py.
    """
    # Create underlying Popen mock
    popen_mock = MagicMock(spec=subprocess.Popen)
    popen_mock.stderr = MagicMock()
    popen_mock.stderr.read.side_effect = RuntimeError("boom")

    # Create ManagedProcess wrapper mock
    managed_process = MagicMock()
    managed_process.process = popen_mock

    basic_client._process = managed_process
    basic_client._stderr_tail.append("plugin said something")

    assert basic_client._get_stderr_output() == "plugin said something"


@pytest.mark.asyncio
async def test_launch_process_failure(basic_client: RPCPluginClient, mocker: object) -> None:
    mocker.patch("pyvider.rpcplugin.client.process.ManagedProcess", side_effect=RuntimeError("start fail"))
    with pytest.raises(TransportError, match="start fail"):
        await basic_client._launch_process()

# 🐍🔌📞🔚
