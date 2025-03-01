
# tests/protocol/test_protocol_base.py

import pytest
from unittest.mock import MagicMock

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class TestConcreteProtocol(RPCPluginProtocol):
    """Concrete implementation of RPCPluginProtocol for testing."""

    def get_grpc_descriptors(self):
        return (MagicMock(), "TestService")

    async def add_to_server(self, handler, server):
        # Just a mock implementation
        pass

def test_protocol_get_grpc_descriptors():
    """Test get_grpc_descriptors returns the expected values."""
    protocol = TestConcreteProtocol()
    descriptors, service_name = protocol.get_grpc_descriptors()

    assert isinstance(descriptors, MagicMock)
    assert service_name == "TestService"

@pytest.mark.asyncio
async def test_protocol_add_to_server():
    """Test add_to_server method implementation."""
    protocol = TestConcreteProtocol()
    mock_server = MagicMock()
    mock_handler = MagicMock()

    await protocol.add_to_server(mock_handler, mock_server)
    # Since our implementation is empty, we just verify it doesn't raise an exception

### 🐍🏗🧪️
