#!/usr/bin/env python3
# examples/02_server_setup.py
"""Advanced server configuration and setup patterns with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path
from typing import Any  # For type hints

import grpc  # For ServicerContext
from attrs import define, field

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from example_utils import configure_for_example, clear_plugin_env_vars # noqa: E402
from pyvider.rpcplugin import (  # noqa: E402
    # configure, # No longer needed directly, use example_utils
    plugin_protocol,
    plugin_server,
)
from pyvider.rpcplugin.config import rpcplugin_config # Use this for reading if needed, not RPCPluginConfig directly for examples
from pyvider.telemetry import logger  # noqa: E402


@define(frozen=True, slots=True)
class EchoReply:
    """A structured reply for the Echo service."""

    response: str = field()


class EchoServiceHandler:
    """Handler implementing an echo service for demonstration."""

    def __init__(self, service_name: str = "EchoService") -> None:
        self.service_name = service_name
        self.request_count = 0

    async def Echo(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> EchoReply:
        """Echo back the received message with metadata."""
        self.request_count += 1

        message = getattr(request, "message", "empty")
        response_data = f"Echo[{self.request_count}]: {message}"

        logger.info(
            "Echo request processed",
            domain="service",
            action="echo",
            status="success",
            service_name=self.service_name,
            request_count=self.request_count,
            message_length=len(message),
        )

        return EchoReply(response=response_data)


async def example_2_unix_socket_server() -> None:
    """
    Example 2A: Demonstrates Unix socket server configuration.

    Shows how to set up a server using Unix domain sockets for
    high-performance local inter-process communication.
    """
    print("\n" + "=" * 60)
    print("🔗 Example 2A: Unix Socket Server Configuration")
    print(" Demonstrates: Unix domain socket transport setup")
    print("=" * 60)

    # Configure for Unix socket communication using example_utils
    clear_plugin_env_vars() # Ensure clean environment
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="example-unix-cookie-02a", # Unique cookie for this sub-example
        PLUGIN_SERVER_TRANSPORTS=["unix"],
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_HANDSHAKE_TIMEOUT=10.0,
        PLUGIN_CONNECTION_TIMEOUT=60.0,
    )

    # Create protocol and handler
    protocol = plugin_protocol()  # Changed
    handler = EchoServiceHandler("UnixEchoService")

    # Create server with Unix socket transport
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",
        transport_path="/tmp/example_echo.sock",  # nosec B108 # Example code, /tmp is acceptable here. # Custom socket path
    )

    logger.info(
        "Starting Unix socket server",
        domain="server",
        action="startup",
        status="starting",
        transport="unix",
        socket_path="/tmp/example_echo.sock",  # nosec B108 # Example code, /tmp is acceptable here.
    )

    # Start server and let it initialize
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)  # Added wait

    logger.info(
        "Unix socket server running",
        domain="server",
        action="startup",
        status="success",
        performance_note="Unix sockets provide ~2x faster IPC than TCP",
    )

    # Graceful shutdown
    await server.stop()
    await server_task

    logger.info(
        "Unix socket server stopped",
        domain="server",
        action="shutdown",
        status="success",
    )


async def example_2_tcp_server() -> None:
    """
    Example 2B: Demonstrates TCP server configuration.

    Shows how to set up a TCP server for network communication
    with custom host and port binding.
    """
    print("\n" + "=" * 60)
    print("🌐 Example 2B: TCP Server Configuration")
    print(" Demonstrates: TCP transport with custom host/port")
    print("=" * 60)

    # Configure for TCP communication using example_utils
    clear_plugin_env_vars()
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="example-tcp-cookie-02b", # Unique cookie
        PLUGIN_SERVER_TRANSPORTS=["tcp"],
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_HANDSHAKE_TIMEOUT=15.0,
        PLUGIN_CONNECTION_TIMEOUT=120.0,
    )

    # Create protocol and handler
    protocol = plugin_protocol()  # Changed
    handler = EchoServiceHandler("TcpEchoService")

    # Create server with TCP transport
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        host="127.0.0.1",  # Bind to localhost
        port=0,  # Use any available port
    )

    logger.info(
        "Starting TCP server",
        domain="server",
        action="startup",
        status="starting",
        transport="tcp",
        host="127.0.0.1",
        port="auto-assigned",
    )

    # Start server and let it initialize
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)  # Added wait

    # Get the actual port assigned
    actual_port = getattr(server, "_port", "unknown")  # Changed to server._port

    logger.info(
        "TCP server running",
        domain="server",
        action="startup",
        status="success",
        host="127.0.0.1",
        port=actual_port,
        network_note="TCP allows remote client connections",
    )

    # Graceful shutdown
    await server.stop()
    await server_task

    logger.info(
        "TCP server stopped", domain="server", action="shutdown", status="success"
    )


async def example_2_dual_transport_server() -> None:
    """
    Example 2C: Demonstrates dual transport configuration.

    Shows how to configure a server to support both Unix sockets
    and TCP transports with automatic negotiation.
    """
    print("\n" + "=" * 60)
    print("🔄 Example 2C: Dual Transport Server Configuration")
    print(" Demonstrates: Unix + TCP transport with auto-negotiation")
    print("=" * 60)

    # Configure for dual transport support using example_utils
    clear_plugin_env_vars()
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="example-dual-cookie-02c", # Unique cookie
        PLUGIN_SERVER_TRANSPORTS=["unix", "tcp"], # Server will try unix first, then tcp
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_HANDSHAKE_TIMEOUT=20.0,
        PLUGIN_CONNECTION_TIMEOUT=180.0,
    )

    # Create protocol and handler
    protocol = plugin_protocol()  # Changed
    handler = EchoServiceHandler("DualTransportEchoService")

    # Create server with dual transport support
    # For dual transport, we let the server negotiate by passing transport=None
    # The `configure()` call above set PLUGIN_SERVER_TRANSPORTS = ['unix', 'tcp']
    # which will be used by RPCPluginServer's negotiation logic.
    # We also pass the config dictionary that plugin_server would have created.

    # Note: The plugin_server factory is not used here because it expects
    # a single string for the transport argument.
    from pyvider.rpcplugin.server import RPCPluginServer  # Import directly

    server_config = {
        # host and port are not directly used by RPCPluginServer constructor
        # if transport is None. They are used by the factory to create a specific
        # TCPSocketTransport. For negotiation, these might be picked up from
        # global config or defaults if not specified in transport objects.
        # For this example, relying on PLUGIN_SERVER_ENDPOINT or defaults.
    }

    server = RPCPluginServer(
        protocol=protocol,
        handler=handler,
        transport=None,  # Crucial for negotiation based on config
        config=server_config,
    )

    logger.info(
        "Starting dual transport server",
        domain="server",
        action="startup",
        status="starting",
        transport=["unix", "tcp"],
        strategy="auto-negotiation",
    )

    # Start server and let it initialize
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)  # Added wait

    logger.info(
        "Dual transport server running",
        domain="server",
        action="startup",
        status="success",
        unix_socket="available",
        tcp_endpoint="0.0.0.0:50051",
        client_note="Clients can connect via either transport",
    )

    # Graceful shutdown
    await server.stop()
    await server_task

    logger.info(
        "Dual transport server stopped",
        domain="server",
        action="shutdown",
        status="success",
    )


async def example_2_advanced_configuration() -> None:
    """
    Example 2D: Demonstrates advanced server configuration options.

    Shows how to use configuration files, environment variables,
    and programmatic configuration for production deployments.
    """
    print("\n" + "=" * 60)
    print("⚙️ Example 2D: Advanced Configuration Options")
    print(" Demonstrates: Config files, env vars, and programmatic setup")
    print("=" * 60)

    # Method 1: Programmatic configuration using example_utils
    logger.info(
        "Configuring via programmatic API (using example_utils)",
        domain="config",
        action="setup",
        status="starting",
        method="programmatic_via_utils",
    )
    clear_plugin_env_vars()
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="advanced-config-cookie-02d", # Unique cookie
        PLUGIN_LOG_LEVEL="DEBUG",
        PLUGIN_HANDSHAKE_TIMEOUT=30.0,
        PLUGIN_CONNECTION_TIMEOUT=300.0,
        PLUGIN_SERVER_TRANSPORTS=["unix", "tcp"], # Example of setting it
        PLUGIN_AUTO_MTLS=False, # Example of setting it
    )
    # rpcplugin_config is now set by configure_for_example

    # Method 2: Environment variable configuration (less emphasized now with utils)
    # For demonstration, one could still set os.environ vars *before* calling
    # configure_for_example if they are not PLUGIN_ prefixed, or rely on
    # configure_for_example to set the PLUGIN_ ones.
    # The example_utils.clear_plugin_env_vars() is important if mixing.

    logger.info(
        "Configuration methods demonstrated (primarily via configure_for_example)",
        domain="config",
        action="setup",
        status="success",
        methods=["programmatic_via_utils"],
        production_note="Use config files or well-defined env vars for production",
    )

    # Create server with advanced configuration
    # The plugin_server will pick up settings from rpcplugin_config
    # which was populated by configure_for_example.
    protocol = plugin_protocol()
    handler = EchoServiceHandler("AdvancedConfigService")

    # Custom non-PLUGIN_ prefixed config can still be passed if your app uses it.
    server_adv = plugin_server(
        protocol=protocol,
        handler=handler,
        config={
            "custom_app_option_1": "advanced_value_app",
            "custom_app_option_2": 100,
        },
    )
    # Start server, let it initialize briefly, then stop it for cleanup
    server_task_adv = asyncio.create_task(server_adv.serve())
    await server_adv.wait_for_server_ready(
        timeout=5.0
    )

    logger.info(
        "Advanced configuration server created",
        domain="server",
        action="create",
        status="success",
        config_source="configure_for_example",
        custom_app_options_passed=True,
    )

    # No need to manually cleanup PLUGIN_ env vars if clear_plugin_env_vars was used prior.
    # Graceful shutdown for the advanced config server
    await server_adv.stop()
    await server_task_adv
    logger.info(
        "Advanced configuration server stopped",
        domain="server",
        action="shutdown",
        status="success",
    )


async def main() -> None:
    """Run all server setup examples."""
    print("🛎️ pyvider-rpcplugin Server Setup Examples")
    print("===========================================")

    try:
        # Run each server configuration example
        await example_2_unix_socket_server()
        await example_2_tcp_server()
        await example_2_dual_transport_server()
        await example_2_advanced_configuration()

        print("\n" + "=" * 60)
        print("✅ All Server Setup Examples Completed Successfully!")
        print("=" * 60)
        print("\n🎯 Key Takeaways:")
        print("  • Unix sockets: Fastest for local IPC (~50K+ req/s)")
        print("  • TCP sockets: Required for network communication")
        print("  • Dual transport: Automatic client-server negotiation")
        print("  • Configuration: Multiple methods for different environments")
        print("\n📖 Next Steps:")
        print("  • Try example 03_client_connection.py for client patterns")
        print("  • See example 04_transport_options.py for transport comparison")
        print("  • Check example 05_security_mtls.py for production security")

    except Exception as e:
        logger.error(
            "Server setup example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e),
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
