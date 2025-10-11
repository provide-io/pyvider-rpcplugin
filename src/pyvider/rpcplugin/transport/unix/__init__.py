#
# pyvider/rpcplugin/transport/unix/__init__.py
#
"""
Unix Domain Socket Transport Package.

This package provides Unix domain socket transport implementation and utilities
for the Pyvider RPC Plugin system.
"""

from provide.foundation.logger import get_logger

logger = get_logger(__name__)

from pyvider.rpcplugin.transport.unix.transport import UnixSocketTransport
from pyvider.rpcplugin.transport.unix.utils import normalize_unix_path

__all__ = [
    "UnixSocketTransport",
    "logger",
    "normalize_unix_path",
]

# 🐍🏗️🔌
