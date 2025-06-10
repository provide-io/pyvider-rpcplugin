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
    plugin_server,
    plugin_protocol, 
    create_basic_protocol,
    configure,
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
        
        message = getattr(request, 'message', 'empty')
        response_data = f"Echo[{self.request_count}]: {message}"
        
        logger.info(
            "Echo request processed",
            domain="service",
            action="echo",
            status="success",
            service_name=self.service_name,
            request_count=self.request_count,
            message_length=len(message)
        )
        
        return type('EchoReply', (), {'response': response_data})()


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
        magic_cookie="example-unix-cookie",
        protocol_version=1,
        transport=["unix"],  # Unix socket only
        auto_mtls=False,  # Disable mTLS for local communication
        handshake_timeout=10.0,
        connection_timeout=60.0
    )
    
    # Create protocol and handler
    protocol = create_basic_protocol()
    handler = EchoServiceHandler("UnixEchoService")
    
    # Create server with Unix socket transport
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",
        transport_path="/tmp/example_echo.sock"  # Custom socket path
    )
    
    logger.info(
        "Starting Unix socket server",
        domain="server",
        action="startup",
        status="starting",
        transport="unix",
        socket_path="/tmp/example_echo.sock"
    )
    
    # Start server and let it initialize
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    logger.info(
        "Unix socket server running",
        domain="server", 
        action="startup",
        status="success",
        performance_note="Unix sockets provide ~2x faster IPC than TCP"
    )
    
    # Graceful shutdown
    await server.stop()
    await server_task
    
    logger.info(
        "Unix socket server stopped",
        domain="server",
        action="shutdown", 
        status="success"
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
        magic_cookie="example-tcp-cookie",
        protocol_version=1,
        transport=["tcp"],  # TCP only
        auto_mtls=False,  # Will enable mTLS in security example
        handshake_timeout=15.0,
        connection_timeout=120.0
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
        port=0  # Use any available port
    )
    
    logger.info(
        "Starting TCP server",
        domain="server",
        action="startup",
        status="starting",
        transport="tcp",
        host="127.0.0.1",
        port="auto-assigned"
    )
    
    # Start server and let it initialize
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    # Get the actual port assigned
    actual_port = getattr(server._transport, 'port', 'unknown')
    
    logger.info(
        "TCP server running",
        domain="server",
        action="startup", 
        status="success",
        host="127.0.0.1",
        port=actual_port,
        network_note="TCP allows remote client connections"
    )
    
    # Graceful shutdown
    await server.stop()
    await server_task
    
    logger.info(
        "TCP server stopped",
        domain="server",
        action="shutdown",
        status="success"
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
        magic_cookie="example-dual-cookie",
        protocol_version=1,
        transport=["unix", "tcp"],  # Support both transports
        auto_mtls=False,
        handshake_timeout=20.0,
        connection_timeout=180.0
    )
    
    # Create protocol and handler
    protocol = create_basic_protocol()
    handler = EchoServiceHandler("DualTransportEchoService")
    
    # Create server with dual transport support
    # The server will automatically choose the best transport
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport=["unix", "tcp"],  # Accept both transport types
        host="0.0.0.0",  # Accept connections from any IP
        port=50051  # Standard gRPC port
    )
    
    logger.info(
        "Starting dual transport server",
        domain="server",
        action="startup",
        status="starting",
        transport=["unix", "tcp"],
        strategy="auto-negotiation"
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
        client_note="Clients can connect via either transport"
    )
    
    # Graceful shutdown
    await server.stop()
    await server_task
    
    logger.info(
        "Dual transport server stopped",
        domain="server",
        action="shutdown",
        status="success"
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
        method="programmatic"
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
        production_note="Use config files for complex production setups"
    )
    
    # Create server with advanced configuration
    protocol = create_basic_protocol()
    handler = EchoServiceHandler("AdvancedConfigService")
    
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        config={
            "custom_option_1": "advanced_value",
            "custom_option_2": 42,
            "performance_mode": "high_throughput"
        }
    )
    
    logger.info(
        "Advanced configuration server created",
        domain="server",
        action="create",
        status="success",
        config_complexity="advanced",
        ready_for="production"
    )
    
    # Cleanup environment variables
    if "PLUGIN_SERVER_TRANSPORTS" in os.environ:
        del os.environ["PLUGIN_SERVER_TRANSPORTS"]
    if "PLUGIN_AUTO_MTLS" in os.environ:
        del os.environ["PLUGIN_AUTO_MTLS"]


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
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
