#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A minimal plugin server, launched as a real subprocess by the e2e tests.

This is deliberately not a ``test_*`` module: pytest must not collect it. It is
executed with ``python -m tests.goplugin._plugin_main`` by ``harness.spawn``.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer


class _E2EProtocol(RPCPluginProtocol[Any, Any]):
    """A protocol that registers nothing but names a service, like a real one."""

    def __init__(self, service_name: str) -> None:
        self._service_name = service_name

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return None, self._service_name

    async def add_to_server(self, server: Any, handler: Any) -> None:
        return None


async def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-name", default="tfplugin6.Provider")
    args = parser.parse_args()

    server = RPCPluginServer(protocol=_E2EProtocol(args.service_name), handler=object())
    await server.serve()


if __name__ == "__main__":
    asyncio.run(_main())
