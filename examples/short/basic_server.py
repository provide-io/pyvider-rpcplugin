#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Minimal plugin server example (15 lines).

Shows the absolute basics of creating a plugin server."""

import asyncio

from provide.foundation import logger

from pyvider.rpcplugin import plugin_protocol, plugin_server


async def main():
    """Run minimal plugin server."""
    protocol = plugin_protocol()  # Basic protocol
    handler = object()  # Dummy handler
    server = plugin_server(protocol=protocol, handler=handler)

    logger.info("Starting minimal server...")
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())

# 🔌📞🔚
