#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Server Setup Examples - Various server configuration patterns."""

import asyncio
from pathlib import Path
import tempfile
from typing import Any  # Moved to top, tuple is built-in for 3.9+ for this usage.

from example_utils import (  # type: ignore[import-not-found]
    configure_for_example,
    get_example_port,
)

from pyvider.rpcplugin.server import RPCPluginServer  # For return type hint

configure_for_example()

# from typing import Any  # Already at top

from provide.foundation import logger  # noqa: E402

from pyvider.rpcplugin import plugin_server  # noqa: E402
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # noqa: E402


class BasicProtocol(RPCPluginProtocol):
    """Basic protocol for demonstration."""

    # from typing import Any # Add Any # Not needed if using built-in tuple
    # from typing import Tuple # Not needed, using built-in tuple

    async def get_grpc_descriptors(
        self,
    ) -> tuple[Any | None, str]:  # Using built-in tuple
        # For a real service, this would return actual gRPC descriptors
        # (e.g., your_pb2_grpc) and the service name string
        # as defined in your .proto file.
        # Example: return your_pb2_grpc, "YourServiceName"
        return None, "BasicService"  # Placeholder for concept demonstration

    async def add_to_server(self, server: Any, handler: Any) -> None:
        # For a real service, this would typically call a function like:
        # your_pb2_grpc.add_YourServiceServicer_to_server(handler, server)
        # The service_name is derived from get_grpc_descriptors.
        _, _service_name = await self.get_grpc_descriptors()
        logger.info(f"registered with handler: {type(handler).__name__}")


class BasicHandler:
    """Basic handler for demonstration."""



async def tcp_server_example() -> RPCPluginServer:
    """Example: TCP server configuration."""
    logger.info("🌐 TCP Server Configuration Example")

    # Import for type casting
    from typing import cast

    from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol

    proto_instance: RPCPluginProtocol = BasicProtocol()
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, proto_instance),
        handler=BasicHandler(),
        transport="tcp",
        host="127.0.0.1",
        port=get_example_port(),
        # The 'config' param here can override global settings.
        # For gRPC specific options like max_workers, these are typically
        # passed directly to the grpc.aio.server. pyvider.rpcplugin.plugin_server
        # might not directly map all arbitrary keys to gRPC options.
        # Standard pyvider.rpcplugin config keys are PLUGIN_ prefixed.
        # This example assumes 'max_workers' might be handled by a custom server
        # or is illustrative for general config passing.
        # If targeting a standard gRPC option, it might need to be
        # PLUGIN_GRPC_OPTIONS='[("grpc.max_concurrent_streams", 100)]' or similar.
        # For this example, we'll assume it's illustrative or for a custom handler.
        config={"APP_MAX_WORKERS": 4},  # Using APP_ prefix for clarity
    )

    return server


async def unix_server_example() -> RPCPluginServer:
    """Example: Unix socket server configuration."""

    from typing import cast

    # Import for type casting
    from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol

    # Use tempfile for a safer temporary socket path
    socket_path = str(Path(tempfile.gettempdir()) / "pyvider_example.sock")

    proto_instance_unix: RPCPluginProtocol = BasicProtocol()
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, proto_instance_unix),
        handler=BasicHandler(),
        transport="unix",
        transport_path=socket_path,  # nosec B108
        # See comment in tcp_server_example regarding the 'config' dict.
        config={"APP_MAX_WORKERS": 2},  # Using APP_ prefix for clarity
    )

    return server


async def main() -> None:
    """Run server setup examples."""
    logger.info("🚀 Server Setup Examples")

    # TCP example
    await tcp_server_example()

    # Unix socket example
    await unix_server_example()


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔌📞🔚
