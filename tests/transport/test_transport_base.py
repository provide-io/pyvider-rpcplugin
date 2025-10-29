#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

import pytest

from pyvider.rpcplugin.transport.base import RPCPluginTransport


class MockTransport(RPCPluginTransport):
    """Concrete implementation of RPCPluginTransport for testing."""

    def __init__(self, endpoint=None) -> None:
        self.endpoint = endpoint
        self._listen_called = False
        self._connect_called = False
        self._close_called = False

    async def listen(self) -> str:
        self._listen_called = True
        return "test://endpoint"

    async def connect(self, endpoint) -> None:
        self._connect_called = True
        self.endpoint = endpoint

    async def close(self) -> None:
        self._close_called = True


def test_transport_init() -> None:
    """Test transport initialization."""
    transport = MockTransport()
    assert transport.endpoint is None

    transport = MockTransport(endpoint="test://preset")
    assert transport.endpoint == "test://preset"


@pytest.mark.asyncio
async def test_transport_listen() -> None:
    """Test transport listen method."""
    transport = MockTransport()
    endpoint = await transport.listen()

    assert transport._listen_called
    assert endpoint == "test://endpoint"


@pytest.mark.asyncio
async def test_transport_connect() -> None:
    """Test transport connect method."""
    transport = MockTransport()
    await transport.connect("test://target")

    assert transport._connect_called
    assert transport.endpoint == "test://target"


@pytest.mark.asyncio
async def test_transport_close() -> None:
    """Test transport close method."""
    transport = MockTransport()
    await transport.close()

    assert transport._close_called


@pytest.mark.asyncio
async def test_abstract_transport_methods() -> None:
    """Test that abstract transport methods raise NotImplementedError."""

    # Create a transport with missing implementation
    class IncompleteTransport(RPCPluginTransport):
        pass

    with pytest.raises(TypeError):
        IncompleteTransport()  # type: ignore[abstract]

# 📞🔌🔚
