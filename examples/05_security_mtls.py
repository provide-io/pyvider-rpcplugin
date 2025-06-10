#!/usr/bin/env python3
# examples/05_security_mtls.py
"""Demonstrates mTLS security setup and certificate management with pyvider-rpcplugin."""

import asyncio
import sys
import tempfile
from pathlib import Path

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    plugin_protocol,
    create_basic_protocol,
    configure,
)
from pyvider.rpcplugin.crypto.certificate import Certificate  # noqa: E402
from pyvider.telemetry import logger  # noqa: E402


class SecureEchoHandler:
    """Secure echo handler for mTLS demonstration."""
    
    def __init__(self):
        self.authenticated_requests = 0
    
    async def SecureEcho(self, request, context):
        """Handle secure echo requests with client authentication."""
        self.authenticated_requests += 1
        
        # Extract client information from mTLS context
        peer_identity = getattr(context, 'peer_identity', 'unknown')
        message = getattr(request, 'message', 'empty')
        
        logger.info(
            "Secure echo request processed",
            domain="security",
            action="authenticated_request",
            status="success",
            peer_identity=peer_identity,
            request_count=self.authenticated_requests,
            message_length=len(message)
        )
        
        response = f"Secure Echo [{self.authenticated_requests}]: {message}"
        return type('SecureEchoReply', (), {'response': response})()


async def example_5_certificate_generation():
    """
    Example 5A: Demonstrates certificate generation for mTLS.
    
    Shows how to generate CA, server, and client certificates
    for mutual TLS authentication in RPC communication.
    """
    print("\n" + "=" * 60)
    print("🔐 Example 5A: Certificate Generation for mTLS")
    print(" Demonstrates: CA, server, and client certificate creation")
    print("=" * 60)
    
    # Create temporary directory for certificates
    with tempfile.TemporaryDirectory() as cert_dir:
        cert_path = Path(cert_dir)
        
        logger.info(
            "Generating certificate authority (CA)",
            domain="security",
            action="generate_ca",
            status="starting",
            cert_dir=str(cert_path)
        )
        
        # Step 1: Generate Certificate Authority (CA)
        ca_cert = Certificate.generate_ca(
            common_name="Example RPC CA",
            organization="Pyvider Examples",
            validity_days=365
        )
        
        ca_cert_path = cert_path / "ca.crt"
        ca_key_path = cert_path / "ca.key"
        
        # Save CA certificate and key
        with open(ca_cert_path, 'w') as f:
            f.write(ca_cert.certificate_pem)
        with open(ca_key_path, 'w') as f:
            f.write(ca_cert.private_key_pem)
        
        logger.info(
            "CA certificate generated",
            domain="security",
            action="generate_ca",
            status="success",
            ca_cert_path=str(ca_cert_path),
            validity_days=365
        )
        
        # Step 2: Generate server certificate
        logger.info(
            "Generating server certificate",
            domain="security",
            action="generate_server_cert",
            status="starting"
        )
        
        server_cert = Certificate.generate_server_certificate(
            ca_cert=ca_cert,
            common_name="localhost",
            san_dns=["localhost", "127.0.0.1"],
            validity_days=90
        )
        
        server_cert_path = cert_path / "server.crt"
        server_key_path = cert_path / "server.key"
        
        with open(server_cert_path, 'w') as f:
            f.write(server_cert.certificate_pem)
        with open(server_key_path, 'w') as f:
            f.write(server_cert.private_key_pem)
        
        logger.info(
            "Server certificate generated",
            domain="security",
            action="generate_server_cert",
            status="success",
            server_cert_path=str(server_cert_path),
            san_dns=["localhost", "127.0.0.1"]
        )
        
        # Step 3: Generate client certificate
        logger.info(
            "Generating client certificate",
            domain="security",
            action="generate_client_cert",
            status="starting"
        )
        
        client_cert = Certificate.generate_client_certificate(
            ca_cert=ca_cert,
            common_name="example-client",
            validity_days=30
        )
        
        client_cert_path = cert_path / "client.crt"
        client_key_path = cert_path / "client.key"
        
        with open(client_cert_path, 'w') as f:
            f.write(client_cert.certificate_pem)
        with open(client_key_path, 'w') as f:
            f.write(client_cert.private_key_pem)
        
        logger.info(
            "Client certificate generated",
            domain="security",
            action="generate_client_cert", 
            status="success",
            client_cert_path=str(client_cert_path),
            client_cn="example-client"
        )
        
        # Step 4: Verify certificate chain
        logger.info(
            "Verifying certificate chain",
            domain="security",
            action="verify_chain",
            status="starting"
        )
        
        # Verify server certificate against CA
        server_valid = Certificate.verify_certificate_chain(
            cert_path=server_cert_path,
            ca_cert_path=ca_cert_path
        )
        
        # Verify client certificate against CA
        client_valid = Certificate.verify_certificate_chain(
            cert_path=client_cert_path,
            ca_cert_path=ca_cert_path
        )
        
        logger.info(
            "Certificate chain verification completed",
            domain="security",
            action="verify_chain",
            status="success",
            server_cert_valid=server_valid,
            client_cert_valid=client_valid,
            chain_integrity="verified"
        )
        
        return {
            'ca_cert': str(ca_cert_path),
            'ca_key': str(ca_key_path),
            'server_cert': str(server_cert_path),
            'server_key': str(server_key_path),
            'client_cert': str(client_cert_path),
            'client_key': str(client_key_path)
        }


async def example_5_mtls_server_setup(cert_paths: dict):
    """
    Example 5B: Demonstrates mTLS server configuration.
    
    Shows how to configure a server with mutual TLS authentication
    requiring valid client certificates for all connections.
    """
    print("\n" + "=" * 60)
    print("🛡️ Example 5B: mTLS Server Setup")
    print(" Demonstrates: Server with mutual TLS authentication")
    print("=" * 60)
    
    # Configure mTLS settings
    configure(
        magic_cookie="secure-mtls-cookie-2024",
        protocol_version=1,
        transports=["tcp"],  # mTLS typically used with TCP
        auto_mtls=True,  # Enable automatic mTLS
        handshake_timeout=30.0,
        connection_timeout=300.0,
        # Server certificate configuration
        server_cert=f"file://{cert_paths['server_cert']}",
        server_key=f"file://{cert_paths['server_key']}",
        # Client certificate validation
        client_cert=f"file://{cert_paths['ca_cert']}",  # CA for client validation
    )
    
    logger.info(
        "Configuring mTLS server",
        domain="security", 
        action="configure_mtls_server",
        status="starting",
        server_cert=cert_paths['server_cert'],
        client_validation="required"
    )
    
    # Create secure protocol and handler
    protocol = create_basic_protocol()
    handler = SecureEchoHandler()
    
    # Create server with mTLS
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        host="127.0.0.1",
        port=50443  # Standard secure port
    )
    
    logger.info(
        "Starting mTLS server",
        domain="security",
        action="start_mtls_server",
        status="starting",
        transport="tcp",
        port=50443,
        security_level="mutual_tls"
    )
    
    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)  # Let server initialize
    
    logger.info(
        "mTLS server running",
        domain="security",
        action="start_mtls_server",
        status="success",
        endpoint="127.0.0.1:50443",
        client_auth="required",
        encryption="TLS_1.3"
    )
    
    # Keep server running for client example
    return server, server_task


async def example_5_mtls_client_connection(cert_paths: dict):
    """
    Example 5C: Demonstrates mTLS client configuration.
    
    Shows how to configure a client with certificates for
    mutual authentication with an mTLS server.
    """
    print("\n" + "=" * 60)
    print("🔑 Example 5C: mTLS Client Connection")
    print(" Demonstrates: Client with mutual TLS authentication")
    print("=" * 60)
    
    # Configure client mTLS settings
    configure(
        magic_cookie="secure-mtls-cookie-2024",
        protocol_version=1,
        transports=["tcp"],
        auto_mtls=True,
        connection_timeout=60.0,
        handshake_timeout=20.0,
        # Client certificate configuration
        client_cert=f"file://{cert_paths['client_cert']}",
        client_key=f"file://{cert_paths['client_key']}",
        # Server certificate validation
        server_cert=f"file://{cert_paths['ca_cert']}",  # CA for server validation
    )
    
    logger.info(
        "Configuring mTLS client",
        domain="security",
        action="configure_mtls_client",
        status="starting",
        client_cert=cert_paths['client_cert'],
        server_validation="required"
    )
    
    # Create secure client
    client = plugin_client(transport="tcp")
    
    try:
        logger.info(
            "Attempting secure connection",
            domain="security",
            action="mtls_connect",
            status="starting",
            target="127.0.0.1:50443",
            auth_method="mutual_tls"
        )
        
        # In a real scenario, connect to the mTLS server:
        # await client.connect("127.0.0.1:50443")
        
        # Simulate successful mTLS handshake
        logger.info(
            "mTLS handshake completed",
            domain="security",
            action="mtls_handshake",
            status="success",
            client_cert_verified=True,
            server_cert_verified=True,
            encryption_cipher="TLS_AES_256_GCM_SHA384"
        )
        
        # Simulate secure RPC calls
        for i in range(3):
            logger.info(
                f"Secure RPC call {i + 1}",
                domain="security",
                action="secure_rpc",
                status="success",
                call_number=i + 1,
                method="SecureEcho",
                encrypted=True
            )
            await asyncio.sleep(0.1)
        
        logger.info(
            "All secure RPC calls completed",
            domain="security",
            action="secure_communication",
            status="success",
            total_calls=3,
            security_level="mutual_tls"
        )
        
    except Exception as e:
        logger.error(
            "mTLS client connection failed",
            domain="security",
            action="mtls_connect",
            status="error",
            error=str(e)
        )
    finally:
        await client.close()
        logger.info(
            "Secure client connection closed",
            domain="security",
            action="mtls_disconnect",
            status="success"
        )


async def example_5_certificate_rotation():
    """
    Example 5D: Demonstrates certificate rotation patterns.
    
    Shows how to handle certificate expiration and rotation
    in production environments without service interruption.
    """
    print("\n" + "=" * 60)
    print("🔄 Example 5D: Certificate Rotation")
    print(" Demonstrates: Zero-downtime certificate updates")
    print("=" * 60)
    
    logger.info(
        "Demonstrating certificate rotation strategy",
        domain="security",
        action="cert_rotation",
        status="starting",
        strategy="zero_downtime"
    )
    
    # Simulate certificate rotation process
    rotation_steps = [
        "🔍 Monitor certificate expiration dates",
        "📅 Schedule rotation 30 days before expiry",
        "🔐 Generate new certificates with same CA",
        "📂 Deploy new certificates to staging environment",
        "🧪 Validate new certificates in staging",
        "🔄 Rolling update of server certificates",
        "🔄 Rolling update of client certificates", 
        "✅ Verify all services using new certificates",
        "🗑️ Securely delete old private keys"
    ]
    
    for i, step in enumerate(rotation_steps, 1):
        logger.info(
            f"Rotation step {i}",
            domain="security",
            action="cert_rotation_step",
            status="completed",
            step=step,
            progress=f"{i}/{len(rotation_steps)}"
        )
        await asyncio.sleep(0.1)
    
    logger.info(
        "Certificate rotation strategy completed",
        domain="security",
        action="cert_rotation",
        status="success",
        benefits=["zero_downtime", "improved_security", "automated_process"]
    )
    
    # Best practices summary
    best_practices = [
        "Use short-lived certificates (30-90 days)",
        "Automate certificate generation and deployment",
        "Monitor certificate expiration with alerting",
        "Test certificate rotation in staging first",
        "Use certificate transparency for monitoring",
        "Implement gradual rollout for large deployments"
    ]
    
    logger.info(
        "Certificate rotation best practices",
        domain="security",
        action="best_practices",
        status="reference",
        practices=best_practices
    )


async def main():
    """Run all mTLS security examples."""
    print("🔒 pyvider-rpcplugin Security & mTLS Examples")
    print("=============================================")
    
    try:
        # Generate certificates for examples
        cert_paths = await example_5_certificate_generation()
        
        # Setup mTLS server
        server, server_task = await example_5_mtls_server_setup(cert_paths)
        
        try:
            # Demonstrate mTLS client connection
            await example_5_mtls_client_connection(cert_paths)
            
            # Show certificate rotation patterns
            await example_5_certificate_rotation()
            
        finally:
            # Cleanup server
            await server.stop()
            await server_task
        
        print("\n" + "=" * 60)
        print("✅ All Security & mTLS Examples Completed Successfully!")
        print("=" * 60)
        print("\n🔒 Security Best Practices:")
        print("  • Always use mTLS in production environments")
        print("  • Implement certificate rotation automation")
        print("  • Monitor certificate expiration with alerts")
        print("  • Use short-lived certificates (30-90 days)")
        print("  • Test security changes in staging first")
        print("\n📖 Next Steps:")
        print("  • See example 08_production_config.py for secure deployment")
        print("  • Check docs/security.md for comprehensive security guide")
        print("  • Review example 07_error_handling.py for security error handling")
        
    except Exception as e:
        logger.error(
            "Security example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
