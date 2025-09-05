# Chapter 3: Basic Server Setup

At the heart of a `pyvider.rpcplugin` server are three main components:

1.  **`RPCPluginServer`**: This is the main class that manages the plugin server's lifecycle. It handles:
    *   Performing the server-side of the handshake protocol (validating magic cookies, negotiating protocol versions and transports).
    *   Setting up the chosen transport (Unix socket or TCP).
    *   Starting and stopping the underlying gRPC server.
    *   Managing graceful shutdown.
    You typically create an instance of this using the `plugin_server` factory function.

2.  **`RPCPluginProtocol`**: This is an abstract base class that you implement to tell `RPCPluginServer` how to handle your specific gRPC service(s). Your implementation will:
    *   Provide the gRPC service descriptors (generated from your `.proto` file).
    *   Specify the name of your service.
    *   Define how to add your service implementation (your handler/servicer) to the gRPC server.
    The `plugin_protocol` factory can provide a basic implementation if you don't have custom gRPC services yet.

3.  **Handler (gRPC Servicer)**: This is the class where you write the actual logic for your RPC methods. It inherits from the gRPC-generated `YourServiceServicer` class (e.g., `EchoServiceServicer`). Each method in your handler corresponds to an RPC method defined in your `.proto` file.

## Example: Server Configuration (`examples/ch03_server_setup_concepts.py`)

The `ch03_server_setup_concepts.py` example illustrates how to configure an `RPCPluginServer` instance, though it doesn't run a fully operational server that waits for connections. Instead, it demonstrates the configuration options.

```python
#!/usr/bin/env python3
# examples/ch03_server_setup_concepts.py
"""
Server Setup Examples - Various server configuration patterns.
"""

import asyncio
from typing import Any # Moved to top, tuple is built-in for 3.9+ for this usage.

from example_utils import (  # type: ignore[import-not-found]
    configure_for_example,
    get_example_port,
)

from pyvider.rpcplugin.server import RPCPluginServer  # For return type hint

configure_for_example()

# from typing import Any  # Already at top

from pyvider.rpcplugin import plugin_server  # noqa: E402
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # noqa: E402
from provide.foundation import logger  # noqa: E402


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
        _, service_name = await self.get_grpc_descriptors()
        logger.info(
            f"🔌 Service '{service_name}' (conceptual) would be "
            f"registered with handler: {type(handler).__name__}"
        )


class BasicHandler:
    """Basic handler for demonstration."""

    pass


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

    # Log the configured endpoint
    endpoint_info = server.transport.endpoint if server.transport else "No transport"
    logger.info(f"✅ TCP server configured: {endpoint_info}")
    return server


async def unix_server_example() -> RPCPluginServer:
    """Example: Unix socket server configuration."""
    logger.info("🔌 Unix Socket Server Configuration Example")

    import os
    import tempfile
    from typing import cast

    # Import for type casting
    from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol

    # Use tempfile for a safer temporary socket path
    socket_path = os.path.join(tempfile.gettempdir(), "pyvider_example.sock")

    proto_instance_unix: RPCPluginProtocol = BasicProtocol()
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, proto_instance_unix),
        handler=BasicHandler(),
        transport="unix",
        transport_path=socket_path,  # nosec B108
        # See comment in tcp_server_example regarding the 'config' dict.
        config={"APP_MAX_WORKERS": 2},  # Using APP_ prefix for clarity
    )

    # Log the configured endpoint
    endpoint_info = server.transport.endpoint if server.transport else "No transport"
    logger.info(f"✅ Unix socket server configured: {endpoint_info}")
    return server


async def main() -> None:
    """Run server setup examples."""
    logger.info("🚀 Server Setup Examples")

    # TCP example
    await tcp_server_example()

    # Unix socket example
    await unix_server_example()

    logger.info("✅ All server setup examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍⚙️
```

Key takeaways from `ch03_server_setup_concepts.py`:
*   The `plugin_server` factory function is used to instantiate `RPCPluginServer`.
*   You provide your `RPCPluginProtocol` implementation and your handler instance.
*   The `transport` parameter can be set to `"tcp"` or `"unix"`.
    *   For TCP, `host` and `port` can be specified. If `port` is 0 (or omitted), an ephemeral port is chosen.
    *   For Unix, `transport_path` specifies the socket file path.
*   An optional `config` dictionary can be passed.
    *   Keys in this dictionary that match `PLUGIN_` prefixed variables (e.g., `PLUGIN_LOG_LEVEL`) will override the global `pyvider.rpcplugin` configurations for this specific server instance.
    *   Other keys can be used for application-specific settings that your server might use, as demonstrated with `APP_MAX_WORKERS` in the example.
