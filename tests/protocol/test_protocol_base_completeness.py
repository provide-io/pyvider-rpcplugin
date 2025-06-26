# tests/protocol/test_protocol_base_completeness.py

import pytest
from typing import Any
from unittest.mock import MagicMock

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import HandlerT, ServerT


class PartialTestProtocol(RPCPluginProtocol):
    """A partial implementation missing the add_to_server method."""

    async def get_grpc_descriptors(self) -> tuple[Any, str]:  # Made async
        """Implemented method."""
        return MagicMock(), "TestService"

    # Missing add_to_server implementation


class CompleteTestProtocol(RPCPluginProtocol):
    """A complete implementation with all methods."""

    async def get_grpc_descriptors(self) -> tuple[Any, str]:  # Made async
        """Returns mock descriptors and service name."""
        return MagicMock(), "TestService"

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        """Adds the handler to the server."""
        pass


def test_abstract_base_cannot_instantiate() -> None:
    """Test that RPCPluginProtocol cannot be instantiated directly."""
    with pytest.raises(TypeError):
        RPCPluginProtocol()  # type: ignore[abstract]


def test_partial_implementation_cannot_instantiate() -> None:
    """Test that a partial implementation cannot be instantiated."""
    with pytest.raises(TypeError):
        PartialTestProtocol()  # type: ignore[abstract]


def test_complete_implementation_can_instantiate() -> None:
    """Test that a complete implementation can be instantiated."""
    protocol = CompleteTestProtocol()
    assert isinstance(protocol, RPCPluginProtocol)


@pytest.mark.asyncio
async def test_complete_implementation_methods() -> None:
    """Test that methods of a complete implementation work."""
    protocol = CompleteTestProtocol()

    # Test get_grpc_descriptors
    descriptors, service_name = await protocol.get_grpc_descriptors() # Added await
    assert service_name == "TestService"
    assert descriptors is not None

    # Test add_to_server
    mock_server = MagicMock()
    mock_handler = MagicMock()
    await protocol.add_to_server(mock_server, mock_handler)


### 🐍🏗🧪️
