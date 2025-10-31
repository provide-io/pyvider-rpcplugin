# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Unix Domain Socket Transport Package.

This package provides Unix domain socket transport implementation and utilities
for the Pyvider RPC Plugin system."""

from provide.foundation.logger import get_logger

from pyvider.rpcplugin.transport.unix.transport import UnixSocketTransport
from pyvider.rpcplugin.transport.unix.utils import normalize_unix_path

logger = get_logger(__name__)

__all__ = [
    "UnixSocketTransport",
    "logger",
    "normalize_unix_path",
]

# 🔌📞🔚
