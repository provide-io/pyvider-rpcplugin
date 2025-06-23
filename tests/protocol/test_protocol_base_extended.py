# tests/protocol/test_protocol_base_extended.py

import pytest
from unittest.mock import MagicMock

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import ServerT, HandlerT
from typing import Tuple


class IncompleteProtocol(RPCPluginProtocol):
    """A protocol implementation that doesn't implement all abstract methods."""

    async def get_grpc_descriptors(self) -> Tuple[MagicMock, str]: # Made async
        return (MagicMock(), "TestService")

    # Missing add_to_server implementation


class ConcreteProtocol(RPCPluginProtocol):
    """A concrete implementation of the protocol with all methods."""

    async def get_grpc_descriptors(self) -> Tuple[MagicMock, str]: # Made async
        descriptors = MagicMock()
        service_name = "TestService"
        return descriptors, service_name

    async def add_to_server(self, server, handler) -> None:
        # Implementation for add_to_server
        pass


def test_abstract_protocol_instantiation() -> None:
    """Test that abstract class cannot be instantiated directly."""
    with pytest.raises(TypeError):
        RPCPluginProtocol()  # type: ignore[abstract]


def test_incomplete_protocol_instantiation() -> None:
    """Test that incomplete implementations cannot be instantiated."""
    with pytest.raises(TypeError):
        IncompleteProtocol()  # type: ignore[abstract]


def test_concrete_protocol_instantiation() -> None:
    """Test that concrete implementations can be instantiated."""
    protocol = ConcreteProtocol()
    assert isinstance(protocol, RPCPluginProtocol)


def test_protocol_type_annotations() -> None:
    """Test that type annotations are correctly used."""
    # This test doesn't instantiate but checks the class structure
    assert hasattr(RPCPluginProtocol, "get_grpc_descriptors")
    assert hasattr(RPCPluginProtocol, "add_to_server")

    # Check if the class is properly generic
    import inspect

    signature = inspect.signature(RPCPluginProtocol.add_to_server)
    params = signature.parameters
    assert "server" in params
    assert "handler" in params


@pytest.mark.asyncio
async def test_concrete_protocol_add_to_server() -> None:
    """Test add_to_server method with mocked server and handler."""
    protocol = ConcreteProtocol()
    server_mock = MagicMock(spec=ServerT)
    handler_mock = MagicMock(spec=HandlerT)

    # Should not raise any exceptions
    await protocol.add_to_server(server_mock, handler_mock)


### 🐍🏗🧪️
