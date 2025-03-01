
# pyvider/rpcplugin/handler.py

# pragma: no cover

from typing import Protocol, runtime_checkable


@runtime_checkable
class RPCPluginHandler(Protocol): # pragma: no cover
    """
    Base protocol that all RPC handlers must implement.
    The actual methods required will be defined by the specific gRPC service.
    """

    pass
