# tests/transport/test_transport_types_direct.py

import pytest

from pyvider.rpcplugin.transport.types import (
    TransportType
)
from pyvider.rpcplugin.transport.base import RPCPluginTransport


def test_transport_type_enum():
    """Test the TransportType enum members."""
    assert TransportType.TCP == "tcp"
    assert TransportType.UNIX == "unix"


def test_rpc_plugin_transport_is_abc():
    """Test that RPCPluginTransport is an abstract base class."""
    with pytest.raises(TypeError):
        RPCPluginTransport()
