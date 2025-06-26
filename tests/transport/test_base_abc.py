# tests/transport/test_base_abc.py

import pytest
from pyvider.rpcplugin.transport.base import RPCPluginTransport


def test_transport_base_abstract_methods() -> None:
    """Test the abstract methods of RPCPluginTransport."""

    # Cannot instantiate the abstract base class
    with pytest.raises(TypeError) as excinfo:
        RPCPluginTransport()  # type: ignore[abstract]

    error_message = str(excinfo.value)
    assert "Can't instantiate abstract class" in error_message

    # Must implement all three abstract methods
    assert "listen" in error_message
    assert "connect" in error_message
    assert "close" in error_message

    # Test partial implementation
    class PartialTransport(RPCPluginTransport):
        async def listen(self):
            return "endpoint"

        async def connect(self, endpoint):
            pass

        # Missing close method

    with pytest.raises(TypeError) as excinfo:
        PartialTransport()  # type: ignore[abstract]

    assert "close" in str(excinfo.value)


### 🐍🏗🧪️
