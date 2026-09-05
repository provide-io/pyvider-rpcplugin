#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""The handshake's stderr report must never read the plugin's pipe.

Two invariants are pinned here.

A read to EOF on a live child's pipe cannot return. `_get_stderr_output` is
called from the handshake-timeout path, which is reached only once the loop
above it has established the child is still running -- so the child holds the
write end open. `subprocess.Popen` pipes are blocking, and this runs inside the
event loop, where one blocked thread stops every timer and cancellation with it.
The symptom is a stall at ~0% CPU, of the kind terraform-provider-pyvider's
pytest configuration sets its timeout to catch.

`_relay_stderr_background` owns the pipe. It reads every line for the life of
the process, so a second reader splits the plugin's output between the two of
them and neither sees all of it.

Both are satisfied by taking the report from the bounded tail the relay keeps.
"""

import asyncio
import subprocess  # nosec

from provide.testkit.mocking import MagicMock
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient


@pytest.fixture
def client() -> RPCPluginClient:
    return RPCPluginClient(command=["dummy"])


def _process_that_must_not_be_read() -> MagicMock:
    """A live process whose pipe explodes if anyone reads it."""
    popen_mock = MagicMock(spec=subprocess.Popen)
    popen_mock.stderr = MagicMock()
    popen_mock.stderr.read.side_effect = AssertionError("must not read the pipe")
    popen_mock.stderr.readline.side_effect = AssertionError("must not read the pipe")

    managed = MagicMock()
    managed.process = popen_mock
    managed.is_running.return_value = True
    return managed


def test_the_report_never_reads_the_pipe(client: RPCPluginClient) -> None:
    """The hang, pinned: a live child must not be read to EOF."""
    client._process = _process_that_must_not_be_read()

    assert client._get_stderr_output() == ""


def test_the_report_is_what_the_relay_saw(client: RPCPluginClient) -> None:
    client._process = _process_that_must_not_be_read()
    client._stderr_tail.append("provider failed to bind")

    assert "provider failed to bind" in client._get_stderr_output()


def test_the_tail_is_bounded(client: RPCPluginClient) -> None:
    """An unbounded buffer on a chatty plugin is its own bug."""
    for i in range(10_000):
        client._stderr_tail.append(f"line {i}")

    assert len(client._stderr_tail) < 10_000


def test_a_long_report_is_truncated(client: RPCPluginClient) -> None:
    """A hint is a hint, not a log dump."""
    client._process = _process_that_must_not_be_read()
    client._stderr_tail.append("x" * 5000)

    output = client._get_stderr_output()

    assert output.endswith("...")
    assert len(output) <= 210


@pytest.mark.asyncio
async def test_the_relay_records_what_it_logs(client: RPCPluginClient) -> None:
    """The relay is the only reader, so it is the only source for the tail."""
    popen_mock = MagicMock(spec=subprocess.Popen)
    popen_mock.stderr = MagicMock()

    managed = MagicMock()
    managed.process = popen_mock
    # One pass through the loop, then stop.
    managed.is_running.side_effect = [True, False]

    future: asyncio.Future[bytes] = asyncio.Future()
    future.set_result(b"panic: bind: address already in use\n")
    loop_mock = MagicMock()
    loop_mock.run_in_executor.return_value = future

    client._process = managed
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(asyncio, "get_event_loop", lambda: loop_mock)
        await client._relay_stderr_background()

    assert "address already in use" in client._get_stderr_output()


# 🐍🔌🔚
