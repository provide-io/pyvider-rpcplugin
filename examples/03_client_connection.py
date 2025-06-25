#!/usr/bin/env python3
"""
Client Connection Examples - Various client implementation patterns.
"""

import asyncio
from example_utils import configure_for_example
configure_for_example()

from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import TransportError, HandshakeError
from pyvider.telemetry import logger

async def basic_client_example():
    """Example: Basic client connection."""
    logger.info("🔗 Basic Client Connection Example")
    
    # Note: This is conceptual - real usage requires an executable plugin
    client_config = {
        "timeout": 10.0,
        "max_retries": 3
    }
    
    logger.info("💡 Client configuration prepared")
    logger.info(f"📋 Config: {client_config}")
    
    # In real usage:
    # client = plugin_client(
    #     command=["./path/to/plugin/executable"],
    #     config=client_config
    # )
    # await client.start()
    
    logger.info("✅ Basic client example completed (conceptual)")

async def error_handling_example():
    """Example: Client error handling patterns."""
    logger.info("⚠️  Client Error Handling Example")
    
    try:
        # Simulate client operations
        logger.info("🔄 Attempting client connection...")
        
        # This would be real client code:
        # await client.start()
        
        logger.info("✅ Connection successful")
        
    except TransportError as e:
        logger.error(f"🚫 Transport error: {e}")
        # Handle transport-specific errors
    except HandshakeError as e:
        logger.error(f"🤝 Handshake error: {e}")
        # Handle authentication/handshake errors
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        # Handle other errors
    
    logger.info("✅ Error handling example completed")

async def main():
    """Run client connection examples."""
    logger.info("🚀 Client Connection Examples")
    
    await basic_client_example()
    await error_handling_example()
    
    logger.info("✅ All client examples completed")

if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔗
