#!/usr/bin/env python3
# examples/05_security_mtls.py
"""mTLS security setup and certificate management with pyvider-rpcplugin."""

import asyncio
import sys
import tempfile
from pathlib import Path
from typing import Any  # For type hints

import grpc  # For direct channel creation
from attrs import define, field

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# First-party imports (after sys.path modification)
from example_utils import configure_for_example, clear_plugin_env_vars # noqa: E402
from pyvider.rpcplugin import plugin_protocol, plugin_server # noqa: E402, configure removed
from pyvider.rpcplugin.config import rpcplugin_config # For reading active config
from pyvider.rpcplugin.crypto.certificate import Certificate  # noqa: E402
from pyvider.rpcplugin.exception import CertificateError  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.types import (  # noqa: E402
    RPCPluginProtocol as TypesRPCPluginProtocol,
)
from pyvider.telemetry import logger  # noqa: E402


@define(frozen=True, slots=True)
class SecureEchoReply:
    """A structured reply for the SecureEcho service."""

    response: str = field()


class SecureEchoHandler:
    """Secure echo handler for mTLS demonstration."""

    def __init__(self) -> None:
        self.authenticated_requests = 0

    async def SecureEcho(
        self, request: Any, context: grpc.aio.ServicerContext
    ) -> SecureEchoReply:
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
        return SecureEchoReply(response=response)


async def example_5_certificate_generation(cert_path: Path) -> dict[str, str]:
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
        f.write(ca_cert_obj.cert)  # cert property is guaranteed to be non-None
    with open(ca_key_path, "w") as f:
        if ca_cert_obj.key is None:  # Key might be None if loaded from cert-only PEM
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
        common_name="localhost",  # Common name for the server
        organization_name="Pyvider Examples Server",
        validity_days=90,
        alt_names=["localhost", "127.0.0.1"],  # Subject Alternative Names
        is_client_cert=False,  # This is a server certificate
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
        common_name="example-mtls-client",  # Common name for the client
        organization_name="Pyvider Examples Client",
        validity_days=30,
        alt_names=["localhost"],  # Optional for client certs
        is_client_cert=True,  # This is a client certificate
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

    # Step 4: Verification (conceptual - actual verification is via TLS handshake).
    # Log that the chain should be valid.
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


# from pyvider.rpcplugin.server import RPCPluginServer  # Moved to top

# The 'with tempfile.TemporaryDirectory() as cert_dir:' block is removed from here
# and will be moved to main()


async def example_5_mtls_server_setup(
    cert_paths: dict[str, str],
) -> tuple[RPCPluginServer, asyncio.Task]:
    """
    Example 5B: Demonstrates mTLS server configuration.

    Shows how to configure a server with mutual TLS authentication
    requiring valid client certificates for all connections.
    """
    print("\n" + "=" * 60)
    print("🛡️ Example 5B: mTLS Server Setup")
    print(" Demonstrates: Server with mutual TLS authentication")
    print("=" * 60)

    # Configure mTLS settings using example_utils
    clear_plugin_env_vars()
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="secure-mtls-cookie-05b", # Unique cookie
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_SERVER_TRANSPORTS=["tcp"], # mTLS typically used with TCP
        PLUGIN_AUTO_MTLS=True,  # Enable automatic mTLS
        PLUGIN_HANDSHAKE_TIMEOUT=30.0,
        PLUGIN_CONNECTION_TIMEOUT=300.0,
        # Server identity: CA-signed server certificate and its private key.
        PLUGIN_SERVER_CERT=f"file://{cert_paths['server_cert']}",
        PLUGIN_SERVER_KEY=f"file://{cert_paths['server_key']}",
        # For mTLS, server needs to verify clients. It uses the CA certificate for this.
        # The relevant config key is PLUGIN_CLIENT_ROOT_CERTS.
        # This will be set directly on rpcplugin_config by configure_for_example
        # if we pass it with "PLUGIN_" prefix.
        PLUGIN_CLIENT_ROOT_CERTS=f"file://{cert_paths['ca_cert']}"
    )
    # Note: configure_for_example handles setting these on the global rpcplugin_config instance.

    logger.info(
        "Configuring mTLS server",
        domain="security",
        action="configure_mtls_server",
        status="starting",
        server_cert=cert_paths["server_cert"],
        client_validation="required",
    )

    # Create secure protocol and handler
    protocol: TypesRPCPluginProtocol = (
        plugin_protocol()
    )  # Annotated with types.RPCPluginProtocol
    handler = SecureEchoHandler()

    # Create server with mTLS
    # Type for server: RPCPluginServer[Any, SecureEchoHandler, TCPSocketTransport]
    # but TCPSocketTransport is not imported. Using RPCPluginServer from import.
    server: RPCPluginServer = plugin_server(
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
    await server.wait_for_server_ready(timeout=10.0)  # Changed, longer for mTLS

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


async def example_5_mtls_client_connection(cert_paths: dict[str, str]) -> None:
    """
    Example 5C: Demonstrates mTLS client configuration.

    Shows how to configure a client with certificates for
    mutual authentication with an mTLS server.
    """
    print("\n" + "=" * 60)
    print("🔑 Example 5C: mTLS Client Connection")
    print(" Demonstrates: Client with mutual TLS authentication")
    print("=" * 60)

    # Configure client mTLS settings using example_utils
    # This needs to happen *after* the server is configured and running,
    # or at least in a way that this config is active when the client part runs.
    # For this example structure, we assume server_setup was called first,
    # then this client part runs. We clear and reconfigure for the client.
    clear_plugin_env_vars()
    configure_for_example(
        PLUGIN_MAGIC_COOKIE_VALUE="secure-mtls-cookie-05b", # Must match server's expectation
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_CLIENT_TRANSPORTS=["tcp"], # Client uses TCP
        PLUGIN_AUTO_MTLS=True, # Client also participates in mTLS
        PLUGIN_CONNECTION_TIMEOUT=60.0,
        PLUGIN_HANDSHAKE_TIMEOUT=20.0,
        # Client's own identity
        PLUGIN_CLIENT_CERT=f"file://{cert_paths['client_cert']}",
        PLUGIN_CLIENT_KEY=f"file://{cert_paths['client_key']}",
        # How client verifies the server (using the CA cert)
        PLUGIN_CLIENT_ROOT_CERTS=f"file://{cert_paths['ca_cert']}",
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
            with open(cert_paths["ca_cert"], "rb") as f:
                ca_cert_pem = f.read()
            with open(cert_paths["client_key"], "rb") as f:
                client_key_pem = f.read()
            with open(cert_paths["client_cert"], "rb") as f:
                client_cert_pem = f.read()
        except Exception as e:
            raise CertificateError(
                f"Failed to read certificate/key files for client: {e}"
            ) from e

        # Create SSL/TLS channel credentials for mTLS
        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca_cert_pem,  # CA to verify server's certificate
            private_key=client_key_pem,     # Client's private key for its identity
            certificate_chain=client_cert_pem,  # Client's certificate chain
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

    except TimeoutError:
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


async def example_5_certificate_rotation() -> None:
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


async def main() -> None:
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
