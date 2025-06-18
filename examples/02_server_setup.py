#!/usr/bin/env python3
# examples/02_server_setup.py
"""Demonstrates advanced server configuration and setup patterns with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    configure,
    create_basic_protocol,
    plugin_server,
)
from pyvider.rpcplugin.config import RPCPluginConfig  # noqa: E402
from pyvider.telemetry import logger  # noqa: E402


class EchoServiceHandler:
    """Handler implementing an echo service for demonstration."""

    def __init__(self, service_name: str = "EchoService"):
        self.service_name = service_name
        self.request_count = 0

    async def Echo(self, request, context):
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

        return type("EchoReply", (), {"response": response_data})()


async def example_2_unix_socket_server():
    """
    Example 2A: Demonstrates Unix socket server configuration.

    Shows how to set up a server using Unix domain sockets for
    high-performance local inter-process communication.
    """
    print("\n" + "=" * 60)
    print("🔗 Example 2A: Unix Socket Server Configuration")
    print(" Demonstrates: Unix domain socket transport setup")
    print("=" * 60)

    # Configure for Unix socket communication
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="example-unix-cookie",
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_SERVER_TRANSPORTS=["unix"],
        PLUGIN_AUTO_MTLS=False,  # Disable mTLS for local communication
        PLUGIN_HANDSHAKE_TIMEOUT=10.0,
        PLUGIN_CONNECTION_TIMEOUT=60.0,  # Corrected key
    )

    # Create protocol and handler
    protocol = create_basic_protocol()
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
    await asyncio.sleep(0.5)

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


async def example_2_tcp_server():
    """
    Example 2B: Demonstrates TCP server configuration.

    Shows how to set up a TCP server for network communication
    with custom host and port binding.
    """
    print("\n" + "=" * 60)
    print("🌐 Example 2B: TCP Server Configuration")
    print(" Demonstrates: TCP transport with custom host/port")
    print("=" * 60)

    # Configure for TCP communication
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="example-tcp-cookie",
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_SERVER_TRANSPORTS=["tcp"],
        PLUGIN_AUTO_MTLS=False,  # Will enable mTLS in security example
        PLUGIN_HANDSHAKE_TIMEOUT=15.0,
        PLUGIN_CONNECTION_TIMEOUT=120.0,  # Corrected key
    )

    # Create protocol and handler
    protocol = create_basic_protocol()
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
    await asyncio.sleep(0.5)

    # Get the actual port assigned
    actual_port = getattr(server._transport, "port", "unknown")

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


async def example_2_dual_transport_server():
    """
    Example 2C: Demonstrates dual transport configuration.

    Shows how to configure a server to support both Unix sockets
    and TCP transports with automatic negotiation.
    """
    print("\n" + "=" * 60)
    print("🔄 Example 2C: Dual Transport Server Configuration")
    print(" Demonstrates: Unix + TCP transport with auto-negotiation")
    print("=" * 60)

    # Configure for dual transport support
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="example-dual-cookie",
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_SERVER_TRANSPORTS=["unix", "tcp"],
        PLUGIN_AUTO_MTLS=False,
        PLUGIN_HANDSHAKE_TIMEOUT=20.0,
        PLUGIN_CONNECTION_TIMEOUT=180.0,  # Corrected key
    )

    # Create protocol and handler
    protocol = create_basic_protocol()
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
    await asyncio.sleep(0.5)

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


async def example_2_advanced_configuration():
    """
    Example 2D: Demonstrates advanced server configuration options.

    Shows how to use configuration files, environment variables,
    and programmatic configuration for production deployments.
    """
    print("\n" + "=" * 60)
    print("⚙️ Example 2D: Advanced Configuration Options")
    print(" Demonstrates: Config files, env vars, and programmatic setup")
    print("=" * 60)

    # Method 1: Programmatic configuration
    logger.info(
        "Configuring via programmatic API",
        domain="config",
        action="setup",
        status="starting",
        method="programmatic",
    )

    config = RPCPluginConfig()
    config.set("PLUGIN_MAGIC_COOKIE_VALUE", "production-cookie-2024")
    config.set("PLUGIN_LOG_LEVEL", "DEBUG")
    config.set("PLUGIN_HANDSHAKE_TIMEOUT", 30.0)
    config.set("PLUGIN_CONNECTION_TIMEOUT", 300.0)

    # Method 2: Environment variable configuration
    import os

    os.environ["PLUGIN_SERVER_TRANSPORTS"] = "unix,tcp"
    os.environ["PLUGIN_AUTO_MTLS"] = "false"

    logger.info(
        "Configuration methods demonstrated",
        domain="config",
        action="setup",
        status="success",
        methods=["programmatic", "environment_variables"],
        production_note="Use config files for complex production setups",
    )

    # Create server with advanced configuration
    protocol = create_basic_protocol()
    handler = EchoServiceHandler("AdvancedConfigService")

    server_adv = plugin_server(
        protocol=protocol,
        handler=handler,
        config={
            "custom_option_1": "advanced_value",
            "custom_option_2": 42,
            "performance_mode": "high_throughput",
        },
    )
    # Start server, let it initialize briefly, then stop it for cleanup
    server_task_adv = asyncio.create_task(server_adv.serve())
    await asyncio.sleep(0.1)  # Brief pause for server to initialize

    logger.info(
        "Advanced configuration server created",
        domain="server",
        action="create",
        status="success",
        config_complexity="advanced",
        ready_for="production",
    )

    # Cleanup environment variables
    if "PLUGIN_SERVER_TRANSPORTS" in os.environ:
        del os.environ["PLUGIN_SERVER_TRANSPORTS"]
    if "PLUGIN_AUTO_MTLS" in os.environ:
        del os.environ["PLUGIN_AUTO_MTLS"]

    # Graceful shutdown for the advanced config server
    await server_adv.stop()
    await server_task_adv
    logger.info(
        "Advanced configuration server stopped",
        domain="server",
        action="shutdown",
        status="success",
    )


async def main():
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
