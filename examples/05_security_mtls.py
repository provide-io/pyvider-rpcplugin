#!/usr/bin/env python3
"""
Security and mTLS Configuration - Production security patterns.
"""

import asyncio
import os
from pathlib import Path
from example_utils import configure_for_example
configure_for_example()

from pyvider.rpcplugin.exception import SecurityError, CertificateError
from pyvider.telemetry import logger

async def mtls_configuration_example():
    """Example: mTLS configuration for production."""
    logger.info("🔒 mTLS Configuration Example")
    
    # Example certificate paths (would be real in production)
    cert_config = {
        "ca_cert": "/path/to/ca.crt",
        "server_cert": "/path/to/server.crt", 
        "server_key": "/path/to/server.key",
        "client_cert": "/path/to/client.crt",
        "client_key": "/path/to/client.key"
    }
    
    logger.info("🔑 Certificate configuration:")
    for key, path in cert_config.items():
        logger.info(f"  {key}: {path}")
    
    # Validate certificate configuration
    try:
        validate_certificate_config(cert_config)
        logger.info("✅ Certificate configuration valid")
    except SecurityError as e:
        logger.error(f"🚫 Security error: {e}")
    
    logger.info("✅ mTLS example completed")

def validate_certificate_config(config):
    """Validate certificate configuration."""
    required_keys = ["ca_cert", "server_cert", "server_key"]
    
    for key in required_keys:
        if key not in config:
            raise CertificateError(f"Missing required certificate: {key}")
        
        # In real implementation, would check file existence and validity
        # if not Path(config[key]).exists():
        #     raise CertificateError(f"Certificate file not found: {config[key]}")

async def security_best_practices():
    """Demonstrate security best practices."""
    logger.info("🛡️  Security Best Practices")
    
    practices = [
        "🔐 Always use mTLS in production",
        "🔑 Rotate certificates regularly", 
        "📋 Validate certificate chains",
        "🚫 Never commit certificates to version control",
        "📁 Use secure certificate storage (e.g., HashiCorp Vault)",
        "⚠️  Monitor certificate expiration",
        "🔒 Use strong cipher suites",
        "📊 Audit security configurations"
    ]
    
    for practice in practices:
        logger.info(f"  {practice}")
    
    logger.info("✅ Security practices review completed")

async def main():
    """Run security examples."""
    logger.info("🚀 Security and mTLS Examples")
    
    await mtls_configuration_example()
    await security_best_practices()
    
    logger.info("✅ All security examples completed")

if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔒
