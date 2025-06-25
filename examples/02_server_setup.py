#!/usr/bin/env python3
"""
Server Setup Examples - Various server configuration patterns.
"""

import asyncio
from example_utils import configure_for_example, get_example_port
configure_for_example()

from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.telemetry import logger

class BasicProtocol(RPCPluginProtocol):
    """Basic protocol for demonstration."""
    
    async def get_grpc_descriptors(self):
        return None, "BasicService"
    
    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"
    
    async def add_to_server(self, server, handler):
        logger.info("🔌 Basic service registered")

class BasicHandler:
    """Basic handler for demonstration."""
    pass

async def tcp_server_example():
    """Example: TCP server configuration."""
    logger.info("🌐 TCP Server Configuration Example")
    
    server = plugin_server(
        protocol=BasicProtocol(),
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
        config={"APP_MAX_WORKERS": 4} # Using APP_ prefix for clarity
    )
    
    logger.info("✅ TCP server configured")
    return server

async def unix_server_example():
    """Example: Unix socket server configuration."""
    logger.info("🔌 Unix Socket Server Configuration Example")
    
    server = plugin_server(
        protocol=BasicProtocol(),
        handler=BasicHandler(),
        transport="unix",
        transport_path="/tmp/pyvider_example.sock",
        # See comment in tcp_server_example regarding the 'config' dict.
        config={"APP_MAX_WORKERS": 2} # Using APP_ prefix for clarity
    )
    
    logger.info("✅ Unix socket server configured")
    return server

async def main():
    """Run server setup examples."""
    logger.info("🚀 Server Setup Examples")
    
    # TCP example
    tcp_server = await tcp_server_example()
    
    # Unix socket example  
    unix_server = await unix_server_example()
    
    logger.info("✅ All server setup examples completed")

if __name__ == "__main__":
    asyncio.run(main())

# 🐍⚙️
