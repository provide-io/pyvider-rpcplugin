#
# pyvider/rpcplugin/transport/base.py
#

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
    async def listen(self) -> str:                            # pragma: no cover
        """
        Start listening for connections.

        Implementations should bind to an appropriate socket or address and
        begin accepting connections. This is typically used by server components.

        Returns:
            The endpoint address as a string (e.g., "127.0.0.1:50051" or "/tmp/socket.sock")

        Raises:
            TransportError: If binding or listening fails
        """
        ...

    @abc.abstractmethod
    async def connect(self, endpoint: str) -> None: ...       # pragma: no cover

    @abc.abstractmethod
    async def close(self) -> None: ...                       # proagma: no cover

# 🐍🏗️🔌
