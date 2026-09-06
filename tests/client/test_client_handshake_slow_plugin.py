#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A plugin slower than the inner timeout must still be heard.

readline runs in an executor, and an executor call cannot be cancelled: when
asyncio.wait_for times out it abandons the future while the thread stays blocked
in the read. The line that read eventually returns is then discarded, so a
plugin that takes longer than the inner timeout to print its handshake has that
handshake consumed and thrown away, and every later read blocks for ever.

That is a race, not a platform limit. It stays invisible wherever the plugin
prints inside the inner timeout, which is why it went unseen on Linux and macOS
and failed every time on a cold Windows launch.
"""

from __future__ import annotations

import threading
import time

from provide.testkit.mocking import MagicMock
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient

HANDSHAKE = b"1|6|tcp|127.0.0.1:1234|grpc|\n"


class _SlowStdout:
    """A pipe whose first readline outlives the inner timeout, then answers."""

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self._sent = False
        self.readline_calls = 0
        self.read_calls = 0
        self._lock = threading.Lock()

    def read(self, _size: int = -1) -> bytes:
        """A second reader on the same pipe, which is the race being tested."""
        with self._lock:
            self.read_calls += 1
        time.sleep(30)
        return b""

    def readline(self) -> bytes:
        with self._lock:
            self.readline_calls += 1
            first = not self._sent
            self._sent = True
        if first:
            time.sleep(self._delay)
            return HANDSHAKE
        # Any second reader would block on a real pipe with nothing left to read.
        time.sleep(30)
        return b""


@pytest.fixture
def client_with_slow_plugin() -> tuple[RPCPluginClient, _SlowStdout]:
    client = RPCPluginClient(command=["dummy-plugin-cmd"])
    stdout = _SlowStdout(delay=3.0)

    popen_mock = MagicMock()
    popen_mock.poll.return_value = None
    popen_mock.returncode = None
    popen_mock.stdout = stdout
    popen_mock.stderr = MagicMock()

    managed = MagicMock()
    managed.process = popen_mock
    managed.is_running.return_value = True
    managed.pid = 4321
    managed.returncode = None
    client._process = managed
    return client, stdout


@pytest.mark.asyncio
async def test_a_plugin_slower_than_the_inner_timeout_is_still_read(
    client_with_slow_plugin: tuple[RPCPluginClient, _SlowStdout],
) -> None:
    """The handshake arrives late; it must not be swallowed by an abandoned read."""
    client, stdout = client_with_slow_plugin

    raw = await client._read_raw_handshake_line_from_stdout()

    assert "1|6|tcp|127.0.0.1:1234|grpc|" in raw
    assert stdout.readline_calls == 1, (
        f"the pipe was read {stdout.readline_calls} times; a second reader races "
        "the first for the handshake line"
    )
    assert stdout.read_calls == 0, (
        f"the chunk strategy read the same pipe {stdout.read_calls} times while a "
        "readline was still outstanding"
    )


# 🧪🤝🔚
