#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Server with health check enabled (20 lines).

Demonstrates enabling the gRPC health check service."""

import asyncio

from provide.foundation import logger

from pyvider.rpcplugin import configure, plugin_protocol, plugin_server


async def main() -> None:
    """Run server with health checks."""
    # Enable health check service
    configure(health_service_enabled=True)

    protocol = plugin_protocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting server with health checks enabled...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔌📞🔚
