
# tests/transport/test_transport_base.py

import pytest

from pyvider.rpcplugin.transport.base import RPCPluginTransport


class TestTransport(RPCPluginTransport):
    """Concrete implementation of RPCPluginTransport for testing."""

    def __init__(self, endpoint=None):
        self.endpoint = endpoint
        self._listen_called = False
        self._connect_called = False
        self._close_called = False

    async def listen(self):
        self._listen_called = True
        return "test://endpoint"

    async def connect(self, endpoint):
        self._connect_called = True
        self.endpoint = endpoint

    async def close(self):
        self._close_called = True


def test_transport_init():
    """Test transport initialization."""
    transport = TestTransport()
    assert transport.endpoint is None

    transport = TestTransport(endpoint="test://preset")
    assert transport.endpoint == "test://preset"


@pytest.mark.asyncio
async def test_transport_listen():
    """Test transport listen method."""
    transport = TestTransport()
    endpoint = await transport.listen()

    assert transport._listen_called
    assert endpoint == "test://endpoint"


@pytest.mark.asyncio
async def test_transport_connect():
    """Test transport connect method."""
    transport = TestTransport()
    await transport.connect("test://target")

    assert transport._connect_called
    assert transport.endpoint == "test://target"


@pytest.mark.asyncio
async def test_transport_close():
    """Test transport close method."""
    transport = TestTransport()
    await transport.close()

    assert transport._close_called


@pytest.mark.asyncio
async def test_abstract_transport_methods():
    """Test that abstract transport methods raise NotImplementedError."""
    # Create a transport with missing implementation
    class IncompleteTransport(RPCPluginTransport):
        pass

    with pytest.raises(TypeError):
        transport = IncompleteTransport()

### 🐍🏗🧪️
