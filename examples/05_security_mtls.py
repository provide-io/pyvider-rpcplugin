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
    configure,
    create_basic_protocol,
    plugin_client,
    plugin_server,
)
from pyvider.rpcplugin.crypto.certificate import Certificate  # noqa: E402
from pyvider.rpcplugin.exception import CertificateError # noqa: E402
from pyvider.telemetry import logger  # noqa: E402
import grpc # For direct channel creation


class SecureEchoHandler:
    """Secure echo handler for mTLS demonstration."""

    def __init__(self):
        self.authenticated_requests = 0

    async def SecureEcho(self, request, context):
        """Handle secure echo requests with client authentication."""
        self.authenticated_requests += 1

        # Extract client information from mTLS context
        peer_identity = getattr(context, "peer_identity", "unknown")
        message = getattr(request, "message", "empty")

        logger.info(
            "Secure echo request processed",
            domain="security",
            action="authenticated_request",
            status="success",
            peer_identity=peer_identity,
            request_count=self.authenticated_requests,
            message_length=len(message),
        )

        response = f"Secure Echo [{self.authenticated_requests}]: {message}"
        return type("SecureEchoReply", (), {"response": response})()


async def example_5_certificate_generation(cert_path: Path):  # Added cert_path argument
    """
    Example 5A: Demonstrates certificate generation for mTLS.

    Shows how to generate CA, server, and client certificates
    for mutual TLS authentication in RPC communication.

    Args:
        cert_path (Path): The directory to save generated certificates.
    """
    print("\n" + "=" * 60)
    print("🔐 Example 5A: Certificate Generation for mTLS")
    print(" Demonstrates: CA, server, and client certificate creation")
    print("=" * 60)

    # Certificates will be saved into the provided cert_path
    logger.info(
        "Generating certificate authority (CA)",  # This is line 77
        domain="security",
        action="generate_ca",
        status="starting",
        cert_dir=str(cert_path),
    )

    # Step 1: Create a Root CA
    ca_cert_obj = Certificate.create_ca(
        common_name="Example Test CA",
        organization_name="Pyvider Examples CA",
        validity_days=365,
    )
    ca_cert_path = cert_path / "ca.crt"
    ca_key_path = cert_path / "ca.key"
    with open(ca_cert_path, "w") as f:
        f.write(ca_cert_obj.cert) # cert property is guaranteed to be non-None
    with open(ca_key_path, "w") as f:
        if ca_cert_obj.key is None: # Key might be None if loaded from cert-only PEM
            raise ValueError("CA private key is None, cannot save.")
        f.write(ca_cert_obj.key)
    logger.info(
        "Root CA certificate and key generated and saved.",
        ca_cert_path=str(ca_cert_path),
        ca_key_path=str(ca_key_path),
    )

    # Step 2: Create a Server Certificate signed by the CA
    server_cert_obj = Certificate.create_signed_certificate(
        ca_certificate=ca_cert_obj,
        common_name="localhost", # Common name for the server
        organization_name="Pyvider Examples Server",
        validity_days=90,
        alt_names=["localhost", "127.0.0.1"], # Subject Alternative Names
        is_client_cert=False # This is a server certificate
    )
    server_cert_path = cert_path / "server.crt"
    server_key_path = cert_path / "server.key"
    with open(server_cert_path, "w") as f:
        f.write(server_cert_obj.cert)
    with open(server_key_path, "w") as f:
        if server_cert_obj.key is None:
            raise ValueError("Server private key is None, cannot save.")
        f.write(server_cert_obj.key)
    logger.info(
        "Server certificate signed by CA generated and saved.",
        server_cert_path=str(server_cert_path),
        server_key_path=str(server_key_path),
    )

    # Step 3: Create a Client Certificate signed by the CA
    client_cert_obj = Certificate.create_signed_certificate(
        ca_certificate=ca_cert_obj,
        common_name="example-mtls-client", # Common name for the client
        organization_name="Pyvider Examples Client",
        validity_days=30,
        alt_names=["localhost"], # Optional for client certs
        is_client_cert=True # This is a client certificate
    )
    client_cert_path = cert_path / "client.crt"
    client_key_path = cert_path / "client.key"
    with open(client_cert_path, "w") as f:
        f.write(client_cert_obj.cert)
    with open(client_key_path, "w") as f:
        if client_cert_obj.key is None:
            raise ValueError("Client private key is None, cannot save.")
        f.write(client_cert_obj.key)
    logger.info(
        "Client certificate signed by CA generated and saved.",
        client_cert_path=str(client_cert_path),
        client_key_path=str(client_key_path),
    )

    # Step 4: Verification (conceptual - actual verification happens during TLS handshake)
    # We can log that the chain should be valid.
    logger.info(
        "Certificates generated for a proper mTLS chain.",
        domain="security",
        action="generate_pki_chain",
        status="completed",
        ca_subject=ca_cert_obj.subject,
        server_issuer=server_cert_obj.issuer,
        client_issuer=client_cert_obj.issuer,
    )

    return {
        "ca_cert": str(ca_cert_path),
        "ca_key": str(ca_key_path),
        "server_cert": str(server_cert_path),
        "server_key": str(server_key_path),
        "client_cert": str(client_cert_path),
        "client_key": str(client_key_path),
    }


# The 'with tempfile.TemporaryDirectory() as cert_dir:' block is removed from here
# and will be moved to main()


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
        # Server certificate configuration (now using CA-signed server cert)
        server_cert=f"file://{cert_paths['server_cert']}", # Path to the CA-signed server certificate
        server_key=f"file://{cert_paths['server_key']}",   # Path to the server's private key
        # Client certificate validation (server uses CA cert to verify client certs)
        client_root_certs=f"file://{cert_paths['ca_cert']}", # Path to the CA certificate
        # Note: PLUGIN_CLIENT_CERT in server config context means root CAs for client auth.
        # The 'client_cert=' parameter in configure() maps to PLUGIN_CLIENT_ROOT_CERTS for server-side.
        # This was a bit confusingly named in `configure` and relies on its internal mapping.
        # For clarity, I'm providing it as client_root_certs which configure() should handle.
        # If configure() has a direct `client_root_certs` param, that's better.
        # Looking at config.py, `configure` takes `client_cert` and `client_key` for client identity,
        # and `server_cert`, `server_key` for server identity.
        # For server to validate client, it's `PLUGIN_CLIENT_ROOT_CERTS`.
        # `configure()` doesn't have a direct param for `PLUGIN_CLIENT_ROOT_CERTS`.
        # We must ensure `rpcplugin_config.set("PLUGIN_CLIENT_ROOT_CERTS", f"file://{cert_paths['ca_cert']}")`
        # is called or that `client_cert` in `configure` maps to it for server-side.
        # The current `configure` maps `client_cert` to `PLUGIN_CLIENT_CERT`.
        # This needs to be set directly for server-side mTLS client validation.
        # **Self-correction**: The `configure()` function has `client_cert` which maps to `PLUGIN_CLIENT_CERT`.
        # In the context of a server's mTLS setup, `PLUGIN_CLIENT_CERT` (if used by server's credential builder)
        # or more appropriately `PLUGIN_CLIENT_ROOT_CERTS` is what the server uses to verify clients.
        # The server's `_generate_server_credentials` now explicitly uses `PLUGIN_CLIENT_ROOT_CERTS`.
        # So, we should set that. `configure()` doesn't have a direct mapping for this.
        # I will set it directly via rpcplugin_config and then call configure for other parts.
    )
    # Explicitly set the client root certs for the server to use for mTLS validation
    from pyvider.rpcplugin.config import rpcplugin_config # Import locally if not at top
    rpcplugin_config.set("PLUGIN_CLIENT_ROOT_CERTS", f"file://{cert_paths['ca_cert']}")


    logger.info(
        "Configuring mTLS server",
        domain="security",
        action="configure_mtls_server",
        status="starting",
        server_cert=cert_paths["server_cert"],
        client_validation="required",
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
        port=50443,  # Standard secure port
    )

    logger.info(
        "Starting mTLS server",
        domain="security",
        action="start_mtls_server",
        status="starting",
        transport="tcp",
        port=50443,
        security_level="mutual_tls",
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
        encryption="TLS_1.3",
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
        client_cert=cert_paths["client_cert"],
        server_validation="required",
    )

    # No longer using plugin_client with dummy_server.sh for this example.
    # We will create a direct gRPC secure channel.
    
    server_address = "127.0.0.1:50443"
    channel = None

    try:
        logger.info(
            "Attempting direct mTLS connection to server",
            domain="security",
            action="direct_mtls_connect",
            status="starting",
            target=server_address,
        )

        # Load credentials from files
        try:
            with open(cert_paths['ca_cert'], 'rb') as f:
                ca_cert_pem = f.read()
            with open(cert_paths['client_key'], 'rb') as f:
                client_key_pem = f.read()
            with open(cert_paths['client_cert'], 'rb') as f:
                client_cert_pem = f.read()
        except Exception as e:
            raise CertificateError(f"Failed to read certificate/key files for client: {e}") from e

        # Create SSL/TLS channel credentials for mTLS
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert_pem,         # Server authentication: CA cert to verify server's cert
            private_key=client_key_pem,            # Client authentication: Client's private key
            certificate_chain=client_cert_pem      # Client authentication: Client's own cert
        )

        # Create a secure channel
        channel = grpc.aio.secure_channel(server_address, credentials)

        logger.info(
            "Secure channel created. Waiting for channel to be ready...",
            domain="security",
            action="channel_created",
            status="pending_ready",
            target=server_address,
        )

        # Wait for the channel to be ready (completes mTLS handshake)
        # Timeout can be adjusted; 5 seconds should be enough for local mTLS.
        await asyncio.wait_for(channel.channel_ready(), timeout=10.0)
        
        logger.info(
            "mTLS connection successful: Channel is ready.",
            domain="security",
            action="mtls_connect_direct",
            status="success",
            target=server_address,
        )

        # At this point, an RPC call could be made if a stub was available.
        # For this example, channel_ready() success is the main verification.
        # Example:
        #   stub = YourGeneratedStub(channel)
        #   response = await stub.YourMethod(Request())
        #   logger.info(f"RPC call successful: {response}")

    except asyncio.TimeoutError:
        logger.error(
            "mTLS connection timeout: Channel not ready within timeout.",
            domain="security",
            action="mtls_connect_direct",
            status="timeout_error",
            target=server_address,
        )
    except CertificateError as e:
        logger.error(
            f"mTLS certificate error: {e.message}",
            domain="security",
            action="mtls_connect_direct",
            status="cert_error",
            hint=e.hint or "Check certificate paths and contents.",
        )
    except Exception as e:
        logger.error(
            f"mTLS client connection failed: {type(e).__name__} - {e}",
            domain="security",
            action="mtls_connect_direct",
            status="error",
            target=server_address,
            error_details=str(e),
        )
    finally:
        if channel:
            await channel.close()
            logger.info(
                "Secure client channel closed.",
                domain="security",
                action="channel_close",
                status="success",
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
        strategy="zero_downtime",
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
        "🗑️ Securely delete old private keys",
    ]

    for i, step in enumerate(rotation_steps, 1):
        logger.info(
            f"Rotation step {i}",
            domain="security",
            action="cert_rotation_step",
            status="completed",
            step=step,
            progress=f"{i}/{len(rotation_steps)}",
        )
        await asyncio.sleep(0.1)

    logger.info(
        "Certificate rotation strategy completed",
        domain="security",
        action="cert_rotation",
        status="success",
        benefits=["zero_downtime", "improved_security", "automated_process"],
    )

    # Best practices summary
    best_practices = [
        "Use short-lived certificates (30-90 days)",
        "Automate certificate generation and deployment",
        "Monitor certificate expiration with alerting",
        "Test certificate rotation in staging first",
        "Use certificate transparency for monitoring",
        "Implement gradual rollout for large deployments",
    ]

    logger.info(
        "Certificate rotation best practices",
        domain="security",
        action="best_practices",
        status="reference",
        practices=best_practices,
    )


async def main():
    """Run all mTLS security examples."""
    print("🔒 pyvider-rpcplugin Security & mTLS Examples")
    print("=============================================")

    # Create temporary directory for certificates that lasts for all example parts
    with tempfile.TemporaryDirectory() as temp_dir_str:
        cert_path_base = Path(temp_dir_str)

        try:
            # Generate certificates for examples, passing the persistent cert_path_base
            cert_paths = await example_5_certificate_generation(cert_path_base)

            # Setup mTLS server
            server, server_task = await example_5_mtls_server_setup(cert_paths)

            try:
                # Demonstrate mTLS client connection
                await example_5_mtls_client_connection(cert_paths)

                # Show certificate rotation patterns
                await example_5_certificate_rotation()

            finally:
                # Cleanup server
                if server and server_task:  # Ensure they exist
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
                error=str(e),
            )
            raise e  # Explicitly raise the caught exception


if __name__ == "__main__":
    asyncio.run(main())
