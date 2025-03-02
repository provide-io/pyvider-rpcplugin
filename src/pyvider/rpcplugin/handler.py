# pyvider/rpcplugin/handler.py

from typing import Protocol, runtime_checkable


@runtime_checkable # pragma: no cover
class RPCPluginHandler(Protocol): # pragma: no cover
    """
    Base protocol that all RPC handlers must implement.
    The actual methods required will be defined by the specific gRPC service.
    """

    pass
