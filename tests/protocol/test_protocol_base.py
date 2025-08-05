# tests/protocol/test_protocol_base.py

import pytest
from unittest.mock import MagicMock

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from typing import Tuple


class TestConcreteProtocol(RPCPluginProtocol):
    """Concrete implementation of RPCPluginProtocol for testing."""

    async def get_grpc_descriptors(self) -> Tuple[MagicMock, str]:  # Made async
        return (MagicMock(), "TestService")

    async def add_to_server(self, server, handler) -> None:  # Corrected param order
        # Just a mock implementation
        pass


@pytest.mark.asyncio # Made async for await
async def test_protocol_get_grpc_descriptors() -> None:
    """Test get_grpc_descriptors returns the expected values."""
    protocol = TestConcreteProtocol()
    descriptors, service_name = await protocol.get_grpc_descriptors() # Added await

    assert isinstance(descriptors, MagicMock)
    assert service_name == "TestService"


@pytest.mark.asyncio
async def test_protocol_add_to_server() -> None:
    """Test add_to_server method implementation."""
    protocol = TestConcreteProtocol()
    mock_server = MagicMock()
    mock_handler = MagicMock()

    await protocol.add_to_server(mock_server, mock_handler) # Corrected param order
    # Since our implementation is empty, we just verify it doesn't raise an exception


### 🐍🏗🧪️
