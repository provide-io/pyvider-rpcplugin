
# tests/protocol/test_protocol_base_extended.py

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import ServerT, HandlerT


class IncompleteProtocol(RPCPluginProtocol):
    """A protocol implementation that doesn't implement all abstract methods."""

    def get_grpc_descriptors(self):
        return (MagicMock(), "TestService")

    # Missing add_to_server implementation


class ConcreteProtocol(RPCPluginProtocol):
    """A concrete implementation of the protocol with all methods."""

    def get_grpc_descriptors(self):
        descriptors = MagicMock()
        service_name = "TestService"
        return descriptors, service_name

    async def add_to_server(self, server, handler):
        # Implementation for add_to_server
        pass


def test_abstract_protocol_instantiation():
    """Test that abstract class cannot be instantiated directly."""
    with pytest.raises(TypeError):
        RPCPluginProtocol()


def test_incomplete_protocol_instantiation():
    """Test that incomplete implementations cannot be instantiated."""
    with pytest.raises(TypeError):
        IncompleteProtocol()


def test_concrete_protocol_instantiation():
    """Test that concrete implementations can be instantiated."""
    protocol = ConcreteProtocol()
    assert isinstance(protocol, RPCPluginProtocol)


def test_protocol_type_annotations():
    """Test that type annotations are correctly used."""
    # This test doesn't instantiate but checks the class structure
    assert hasattr(RPCPluginProtocol, 'get_grpc_descriptors')
    assert hasattr(RPCPluginProtocol, 'add_to_server')

    # Check if the class is properly generic
    import inspect
    signature = inspect.signature(RPCPluginProtocol.add_to_server)
    params = signature.parameters
    assert 'server' in params
    assert 'handler' in params


@pytest.mark.asyncio
async def test_concrete_protocol_add_to_server():
    """Test add_to_server method with mocked server and handler."""
    protocol = ConcreteProtocol()
    server_mock = MagicMock(spec=ServerT)
    handler_mock = MagicMock(spec=HandlerT)

    # Should not raise any exceptions
    await protocol.add_to_server(server_mock, handler_mock)

def test_abstract_get_grpc_descriptors():
    """Directly test the abstract get_grpc_descriptors method (line 22)."""
    # Create a minimal subclass but don't implement get_grpc_descriptors
    class MinimalProtocol(RPCPluginProtocol):
        async def add_to_server(self, server, handler):
            pass
    
    # Try to instantiate it - should fail
    with pytest.raises(TypeError) as excinfo:
        MinimalProtocol()
    
    assert "Can't instantiate abstract class" in str(excinfo.value)
    assert "get_grpc_descriptors" in str(excinfo.value)

def test_abstract_add_to_server():
    """Directly test the abstract add_to_server method (line 32)."""
    # Create a minimal subclass but don't implement add_to_server
    class MinimalProtocol(RPCPluginProtocol):
        def get_grpc_descriptors(self):
            return MagicMock(), "TestService"
    
    # Try to instantiate it - should fail 
    with pytest.raises(TypeError) as excinfo:
        MinimalProtocol()
    
    assert "Can't instantiate abstract class" in str(excinfo.value)
    assert "add_to_server" in str(excinfo.value)

### 🐍🏗🧪️
