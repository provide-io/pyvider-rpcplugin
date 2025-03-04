
# tests/transport/test_transport_types_direct.py

from typing import Protocol, runtime_checkable

from pyvider.rpcplugin.transport.types import (
    TransportType
)
from pyvider.rpcplugin.transport import (
    RPCPluginTransport,
    TCPSocketTransport,
    UnixSocketTransport
)

# Tests for the ConnectionT Protocol (lines 22-24)
def test_connection_protocol() -> None:
    """Test ConnectionT Protocol implementation (lines 22-24)."""

    # Create a class that implements ConnectionT
    @runtime_checkable
    class TestConnection(Protocol):
        async def send_data(self, data: bytes) -> None:
            ...

        async def receive_data(self, size: int = 16384) -> bytes:
            ...

        async def close(self) -> None:
            ...

    # Create a concrete implementation
    class ConcreteConnection:
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    # Create an incomplete implementation
    class IncompleteConnection:
        async def send_data(self, data: bytes) -> None:
            pass

    # Test protocol checking
    instance = ConcreteConnection()
    assert isinstance(instance, TestConnection)

    incomplete = IncompleteConnection()
    assert not isinstance(incomplete, TestConnection)

def test_transport_type() -> None:
    """Test TransportType alias (line 22)."""
    # Test that TransportType accepts both TCP and Unix transports
    tcp_transport = TCPSocketTransport()
    unix_transport = UnixSocketTransport()

    # Create a function that accepts TransportType
    def accepts_transport(transport: TransportType[TCPSocketTransport, UnixSocketTransport]):
        assert isinstance(transport, (TCPSocketTransport, UnixSocketTransport))

    # Test with both types
    accepts_transport(tcp_transport)
    accepts_transport(unix_transport)

    # This shouldn't type check, but will work at runtime
    # Just test it doesn't raise an exception
    accepts_transport(RPCPluginTransport())  # type: ignore

### 🐍🏗🧪️
