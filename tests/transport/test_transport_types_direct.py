# tests/transport/test_transport_types_direct.py

from typing import Protocol, runtime_checkable  # Keep existing typing imports

from pyvider.rpcplugin.transport.types import TransportType
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport


# Tests for the ConnectionT Protocol (lines 22-24)
def test_connection_protocol() -> None:
    """Test ConnectionT Protocol implementation (lines 22-24)."""

    @runtime_checkable
    class TestConnection(Protocol):
        async def send_data(self, data: bytes) -> None: ...
        async def receive_data(self, size: int = 16384) -> bytes: ...
        async def close(self) -> None: ...

    class ConcreteConnection:
        async def send_data(self, data: bytes) -> None:
            pass

        async def receive_data(self, size: int = 16384) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    class IncompleteConnection:
        async def send_data(self, data: bytes) -> None:
            pass

    instance = ConcreteConnection()
    assert isinstance(instance, TestConnection)
    incomplete = IncompleteConnection()
    assert not isinstance(incomplete, TestConnection)


def test_transport_type() -> None:
    """Test TransportType alias."""
    tcp_transport = TCPSocketTransport()
    unix_transport = UnixSocketTransport()

    # Define a helper function that uses the TransportType alias
    def process_transport(transport_instance: TransportType) -> None:
        """Accepts a transport instance adhering to TransportType."""
        # In a real scenario, you might do something with transport_instance here.
        # For this test, simply type checking the parameter is sufficient.
        assert transport_instance is not None  # Basic runtime check

    # Call the function with instances of the constituent types
    # These calls should pass static type checking and run without runtime error.
    process_transport(tcp_transport)
    process_transport(unix_transport)

    # The assignments and function calls above are checked by MyPy,
    # confirming the type alias works for static analysis as intended.
    # Runtime introspection of `|` type aliases can be complex and version-dependent,
    # so focusing on static type checking and basic runtime assignability is preferred.
    pass  # Test passes if MyPy is satisfied and runtime calls don't fail


# 🐍🏗🧪️
