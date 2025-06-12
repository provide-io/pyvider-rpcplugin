# tests/transport/test_transport_base_direct.py

import pytest

from pyvider.rpcplugin.transport.base import RPCPluginTransport


# Test the abstract methods using a concrete subclass with missing methods
def test_transport_abc_listen() -> None:
    """Test abstract listen method (line 13)."""

    class PartialTransport(RPCPluginTransport):
        async def connect(self, endpoint):
            pass

        async def close(self):
            pass

    # Should fail because listen is not implemented
    with pytest.raises(TypeError) as excinfo:
        PartialTransport()

    assert "Can't instantiate abstract class" in str(excinfo.value)
    assert "listen" in str(excinfo.value)


def test_transport_abc_connect() -> None:
    """Test abstract connect method (line 16)."""

    class PartialTransport(RPCPluginTransport):
        async def listen(self):
            pass

        async def close(self):
            pass

    # Should fail because connect is not implemented
    with pytest.raises(TypeError) as excinfo:
        PartialTransport()

    assert "Can't instantiate abstract class" in str(excinfo.value)
    assert "connect" in str(excinfo.value)


def test_transport_abc_close() -> None:
    """Test abstract close method (line 19)."""

    class PartialTransport(RPCPluginTransport):
        async def listen(self):
            pass

        async def connect(self, endpoint):
            pass

    # Should fail because close is not implemented
    with pytest.raises(TypeError) as excinfo:
        PartialTransport()

    assert "Can't instantiate abstract class" in str(excinfo.value)
    assert "close" in str(excinfo.value)


### 🐍🏗🧪️
