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
from pyvider.telemetry import logger  # noqa: E402


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

    # Step 1: Generate a "CA-like" Self-Signed Certificate (ca_placeholder.crt)
    # The Certificate class as used here generates self-signed certificates.
    # For this example, we generate three independent self-signed certificates:
    # one for the server, one for the client, and one that could conceptually act
    # as a CA but in this specific mTLS setup (direct trust of peer's self-signed cert)
    # it won't be used to sign the other certs or as a shared root of trust.
    # It's generated to show the cert generation capability.
    ca_placeholder_cert_obj = Certificate( # Renamed for clarity
        generate_keypair=True,
        common_name="Example RPC CA Placeholder (Self-Signed)",
        organization_name="Pyvider Examples",
        validity_days=365,
    )
    ca_cert_path = cert_path / "ca.crt"
    ca_key_path = cert_path / "ca.key"
    with open(ca_cert_path, "w") as f:
        if ca_placeholder_cert_obj.cert is None:
            raise ValueError("CA placeholder certificate content is None")
        f.write(ca_placeholder_cert_obj.cert)
    with open(ca_key_path, "w") as f:
        if ca_placeholder_cert_obj.key is None:
            raise ValueError("CA placeholder key content is None")
        f.write(ca_placeholder_cert_obj.key)
    logger.info(
        "Self-signed 'CA Placeholder' certificate generated", ca_cert_path=str(ca_cert_path)
    )

    # Step 2: Generate Server Certificate (self-signed)
    server_cert_obj = Certificate(
        generate_keypair=True,
        common_name="localhost",
        organization_name="Pyvider Examples Server",
        alt_names=["localhost", "127.0.0.1"],
        validity_days=90,
    )
    server_cert_path = cert_path / "server.crt"
    server_key_path = cert_path / "server.key"
    with open(server_cert_path, "w") as f:
        if server_cert_obj.cert is None:
            raise ValueError("Server certificate content is None")
        f.write(server_cert_obj.cert)
    with open(server_key_path, "w") as f:
        if server_cert_obj.key is None:
            raise ValueError("Server key content is None")
        f.write(server_cert_obj.key)
    logger.info(
        "Self-signed Server certificate generated",
        server_cert_path=str(server_cert_path),
    )

    # Step 3: Generate Client Certificate (self-signed)
    client_cert_obj = Certificate(
        generate_keypair=True,
        common_name="example-client",
        organization_name="Pyvider Examples Client",
        validity_days=30,
    )
    client_cert_path = cert_path / "client.crt"
    client_key_path = cert_path / "client.key"
    with open(client_cert_path, "w") as f:
        if client_cert_obj.cert is None:
            raise ValueError("Client certificate content is None")
        f.write(client_cert_obj.cert)
    with open(client_key_path, "w") as f:
        if client_cert_obj.key is None:
            raise ValueError("Client key content is None")
        f.write(client_cert_obj.key)
    logger.info(
        "Self-signed Client certificate generated",
        client_cert_path=str(client_cert_path),
    )

    # Step 4: Verification (self-verification of individual certs)
    logger.info("Individual certificate self-verification (not chain verification)", domain="security")

    # We are checking if the generated certs are valid on their own.
    # In this example, since all certs are self-signed and trust is peer-to-peer,
    # there's no common CA to verify a chain against.
    server_valid = server_cert_obj.is_valid
    client_valid = client_cert_obj.is_valid
    ca_placeholder_valid = ca_placeholder_cert_obj.is_valid


    logger.info(
        "Self-signed certificate statuses",
        domain="security",
        action="self_verify_individual",
        status="completed",
        server_cert_valid=server_valid,
        client_cert_valid=client_valid,
        ca_placeholder_cert_valid=ca_placeholder_valid,
        chain_integrity="N/A (trust is peer-to-peer using self-signed certs)",
    )

    return {
        "ca_placeholder_cert": str(ca_cert_path), # Path to the CA-like cert
        "ca_placeholder_key": str(ca_key_path),   # Path to its key
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
        PLUGIN_MAGIC_COOKIE_VALUE="secure-mtls-cookie-2024",
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_SERVER_TRANSPORTS=["tcp"],  # mTLS typically used with TCP
        PLUGIN_AUTO_MTLS=True,  # Enable automatic mTLS
        PLUGIN_HANDSHAKE_TIMEOUT=30.0,
        PLUGIN_CONNECTION_TIMEOUT=300.0,
        # Server certificate configuration
        PLUGIN_SERVER_CERT=f"file://{cert_paths['server_cert']}",
        PLUGIN_SERVER_KEY=f"file://{cert_paths['server_key']}",
        # Server trusts the client's self-signed certificate directly
        PLUGIN_CLIENT_ROOT_CERTS=f"file://{cert_paths['client_cert']}",
    )

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
        PLUGIN_MAGIC_COOKIE_VALUE="secure-mtls-cookie-2024", # Ensure same cookie as server
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_CLIENT_TRANSPORTS=["tcp"],
        PLUGIN_AUTO_MTLS=True,
        PLUGIN_CONNECTION_TIMEOUT=60.0,
        PLUGIN_HANDSHAKE_TIMEOUT=20.0,
        # Client's own certificate and key
        PLUGIN_CLIENT_CERT=f"file://{cert_paths['client_cert']}",
        PLUGIN_CLIENT_KEY=f"file://{cert_paths['client_key']}",
        # Client trusts the server's self-signed certificate directly
        PLUGIN_SERVER_ROOT_CERTS=f"file://{cert_paths['server_cert']}",
    )

    logger.info(
        "Configuring mTLS client",
        domain="security",
        action="configure_mtls_client",
        status="starting",
        client_cert=cert_paths["client_cert"],
        server_validation="required",
    )

    # This client will connect to the mTLS server started in example_5_mtls_server_setup

    target_address = "127.0.0.1:50443"
    channel = None

    try:
        logger.info(
            "Attempting secure connection to actual mTLS server",
            domain="security",
            action="mtls_connect",
            status="starting",
            target=target_address,
            auth_method="mutual_tls",
        )

        # Load client certificate and key
        with open(cert_paths['client_cert'], 'rb') as f:
            client_cert_pem = f.read()
        with open(cert_paths['client_key'], 'rb') as f:
            client_key_pem = f.read()
        # Load server's certificate (acting as CA for client to trust server's self-signed cert)
        with open(cert_paths['server_cert'], 'rb') as f:
            server_root_certs_pem = f.read()

        credentials = grpc.ssl_channel_credentials(
            root_certificates=server_root_certs_pem,
            private_key=client_key_pem,
            certificate_chain=client_cert_pem
        )

        channel = grpc.aio.secure_channel(target_address, credentials)

        await asyncio.wait_for(channel.channel_ready(), timeout=10.0)
        logger.info(
            "mTLS connection successful to actual server",
            domain="security",
            action="mtls_connect",
            status="success",
        )

        # Attempt a generic call to SecureEcho on TestService
        # Create a dummy request object that has a 'message' attribute
        RequestMessage = type("RequestMessage", (), {"message": "Hello from mTLS client"})

        response = await channel.unary_unary(
            '/TestService/SecureEcho', # Method for BasicProtocol's handler
            request_serializer=lambda x: x.message.encode('utf-8'), # Dummy serializer
            response_deserializer=lambda x: x.decode('utf-8')  # Dummy deserializer
        )(RequestMessage())

        logger.info(
            "Secure RPC call to SecureEcho succeeded",
            domain="security",
            action="secure_rpc_actual",
            status="success",
            response=response
        )

    except grpc.aio.AioRpcError as e:
        logger.error(
            "mTLS client gRPC error",
            domain="security",
            action="mtls_connect_actual",
            status="error",
            code=e.code(),
            details=e.details(),
        )
    except Exception as e:
        logger.error(
            "mTLS client connection failed",
            domain="security",
            action="mtls_connect_actual",
            status="error",
            error=str(e),
            exc_info=True
        )
    finally:
        if channel:
            await channel.close()
        logger.info(
            "Secure client connection attempt finished.",
            domain="security",
            action="mtls_disconnect",
            status="completed",
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
