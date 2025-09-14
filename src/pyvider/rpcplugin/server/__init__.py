#
# pyvider/rpcplugin/server/__init__.py
#
"""
Pyvider RPC Plugin Server Package.

This package provides the core components for creating RPC plugin servers,
including the main `RPCPluginServer` class and network handling components.
"""

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

# Import additional items from other modules that were previously in server.py
from grpc.aio import server as GRPCServer
from pyvider.rpcplugin.handshake import validate_magic_cookie
from provide.foundation import logger

__all__ = [
    "RPCPluginServer",
    "RateLimitingInterceptor",
    "ServerNetworkMixin",
    "_ServerT",
    "_HandlerT",
    "_TransportT",
    "ServerT",
    "HandlerT",
    "TransportT",
    "GRPCServer",
    "validate_magic_cookie",
    "logger",
]

# 🐍🏗️🔌