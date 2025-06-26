#
# src/pyvider/rpcplugin/transport/base.py
#

"""
Base Abstract Class for RPC Plugin Transports.

This module defines `RPCPluginTransport`, an abstract base class (ABC)
that outlines the contract for all transport implementations within the
Pyvider RPC Plugin system. Concrete transport classes (e.g., for TCP or Unix sockets)
must inherit from this class and implement its abstract methods.
"""

import abc

from attrs import define, field


@define(frozen=False, slots=False)
class RPCPluginTransport(abc.ABC):
    """
    Abstract base class defining the interface for all transport implementations.

    This class defines the contract that concrete transport implementations
    must fulfill to provide network communication for plugins. The interface
    supports both client-side (connect) and server-side (listen) operations.

    Implementations must handle:
    - Connection setup and teardown
    - Socket lifecycle management
    - Error handling and reporting
    - Resource cleanup

    Custom transports can be implemented by subclassing this class and
    implementing the required abstract methods.
    """

    endpoint: str | None = field(init=False, default=None)

    @abc.abstractmethod
    async def listen(self) -> str:  # pragma: no cover
        """
        Start listening for connections.

        Implementations should bind to an appropriate socket or address and
        begin accepting connections. This is typically used by server components.

        Returns:
            The endpoint address as a string (e.g., "127.0.0.1:50051" or
            "/tmp/socket.sock")

        Raises:
            TransportError: If binding or listening fails
        """
        ...

    @abc.abstractmethod
    async def connect(self, endpoint: str) -> None:  # pragma: no cover
        """
        Connect to a remote endpoint.

        Implementations should establish a connection to the specified endpoint
        address. This is typically used by client components.

        Args:
            endpoint: The target endpoint address string.

        Raises:
            TransportError: If the connection cannot be established.
        """
        ...

    @abc.abstractmethod
    async def close(self) -> None:  # pragma: no cover
        """
        Close the transport and release any associated resources.

        Implementations should ensure that all network resources (like sockets)
        are properly closed and cleaned up. This method should be idempotent.

        Raises:
            TransportError: If an error occurs during closing.
        """
        ...


# 🐍🏗️🔌
