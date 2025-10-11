#
# pyvider/rpcplugin/server/__init__.py
#
"""
Pyvider RPC Plugin Server Package.

This package provides the core components for creating RPC plugin servers,
including the main `RPCPluginServer` class and network handling components.
"""

# Import additional items from other modules that were previously in server.py
from grpc.aio import server as GRPCServer
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

from pyvider.rpcplugin.handshake import validate_magic_cookie
from pyvider.rpcplugin.server.core import (
    HandlerT,
    RateLimitingInterceptor,
    RPCPluginServer,
    ServerT,
    TransportT,
    _HandlerT,
    _ServerT,
    _TransportT,
)
from pyvider.rpcplugin.server.network import ServerNetworkMixin

__all__ = [
    "GRPCServer",
    "HandlerT",
    "RPCPluginServer",
    "RateLimitingInterceptor",
    "ServerNetworkMixin",
    "ServerT",
    "TransportT",
    "_HandlerT",
    "_ServerT",
    "_TransportT",
    "logger",
    "validate_magic_cookie",
]

# 🐍🏗️🔌
