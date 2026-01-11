#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Pyvider RPC Plugin Server Package.

This package provides the core components for creating RPC plugin servers,
including the main `RPCPluginServer` class and network handling components."""

from grpc.aio import server as GRPCServer
from provide.foundation.logger import get_logger

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

logger = get_logger(__name__)

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

# 🐍🔌📞🔚
