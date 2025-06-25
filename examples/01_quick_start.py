#!/usr/bin/env python3
"""
Quick Start Example - Basic server/client setup with pyvider-rpcplugin.
This is the featured example from the README.
"""

import asyncio
from pathlib import Path
import sys

# Setup example environment
from example_utils import configure_for_example, get_example_port
configure_for_example()

from pyvider.rpcplugin import plugin_server, plugin_protocol
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.telemetry import logger

class EchoHandler:
    """Simple echo service handler."""
    
    async def Echo(self, request, context):
        """Echo the request back."""
        logger.info(f"🔄 Echo received: {request}")
        return request

class EchoProtocol(RPCPluginProtocol):
    """Basic echo protocol implementation."""
    
    async def get_grpc_descriptors(self):
        return None, "Echo"
    
    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"
    
    async def add_to_server(self, server, handler):
        logger.info("🔌 Echo service registered")

async def main():
    """Run the quick start example."""
    logger.info("🚀 Starting pyvider-rpcplugin Quick Start Example")
    
    # Create protocol and handler
    protocol = EchoProtocol()
    handler = EchoHandler()
    
    # Create server with TCP transport
    port = get_example_port()
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        port=port
    )
    
    logger.info(f"🌐 Echo server starting on port {port}")
    
    # Start server (this would normally run indefinitely)
    try:
        await asyncio.wait_for(server.serve(), timeout=1.0)
    except asyncio.TimeoutError:
        logger.info("✅ Quick start example completed successfully")
    except Exception as e:
        logger.error(f"❌ Example failed: {e}")
    finally:
        await server.stop()

if __name__ == "__main__":
    asyncio.run(main())

# 🐍🚀
