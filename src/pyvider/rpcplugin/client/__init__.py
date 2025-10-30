#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Pyvider RPC Plugin Client Package.

This package provides the core components for creating RPC plugin clients,
including the main `RPCPluginClient` class, connection handling, and associated types."""

from pyvider.rpcplugin.client.connection import ClientConnection
from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.client.types import (
    ClientT,
    GrpcChannelType,
    GrpcCredentialsType,
    RpcConfigType,
    SecureRpcClientT,
)

__all__ = [
    "ClientConnection",
    "ClientT",
    "GrpcChannelType",
    "GrpcCredentialsType",
    "RPCPluginClient",
    "RpcConfigType",
    "SecureRpcClientT",
]

# 🔌📞🔚
