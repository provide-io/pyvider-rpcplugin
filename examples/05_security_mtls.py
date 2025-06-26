#!/usr/bin/env python3
"""
Security and mTLS Configuration - Functional Example.
This example demonstrates a working mTLS setup between a client and a server
plugin launched as a subprocess.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

# First-party imports (project-specific)
from example_utils import configure_for_example

from pyvider.rpcplugin import (
    RPCPluginClient,  # For type hinting
    RPCPluginError,
    configure,
    plugin_client,
)
from pyvider.rpcplugin.crypto import Certificate
from pyvider.telemetry import logger

# Apply base configuration for examples (paths, logging)
configure_for_example()


async def functional_mtls_example() -> None:
    """Functional example of mTLS configuration and operation."""
    logger.info("🔒🐍 Functional mTLS Configuration Example")

    temp_dir_obj = tempfile.TemporaryDirectory(prefix="pyvider_mtls_example_")
    temp_dir_path = Path(temp_dir_obj.name)
    logger.info(f"🔑 Created temporary directory for certificates: {temp_dir_path}")

    try:
        # 1. Generate Certificates
        logger.info("🔑 Generating CA, Server, and Client certificates...")
        ca_cert = Certificate.create_ca(
            common_name="Example Corp CA",
            organization_name="Pyvider Example Corp",
            validity_days=1,
        )
        server_cert = Certificate.create_signed_certificate(
            ca_certificate=ca_cert,
            common_name="mtls-server.example.com",
            organization_name="Pyvider Example Corp Servers",
            alt_names=["localhost", "127.0.0.1"],
            is_client_cert=False,
            validity_days=1,
        )
        client_cert = Certificate.create_signed_certificate(
            ca_certificate=ca_cert,
            common_name="mtls-client.example.com",
            organization_name="Pyvider Example Corp Clients",
            is_client_cert=True,
            validity_days=1,
        )

        # Save certificates to temporary files
        ca_cert_path = temp_dir_path / "ca.crt"
        server_cert_path = temp_dir_path / "server.crt"
        server_key_path = temp_dir_path / "server.key"
        client_cert_path = temp_dir_path / "client.crt"
        client_key_path = temp_dir_path / "client.key"

        with open(ca_cert_path, "w") as f:
            f.write(ca_cert.cert)
        with open(server_cert_path, "w") as f:
            f.write(server_cert.cert)
        assert server_cert.key is not None, "Server key should have been generated"  # nosec B101
        with open(server_key_path, "w") as f:
            f.write(server_cert.key)
        with open(client_cert_path, "w") as f:
            f.write(client_cert.cert)
        assert client_cert.key is not None, "Client key should have been generated"  # nosec B101
        with open(client_key_path, "w") as f:
            f.write(client_cert.key)
        logger.info(f"🔑 Certificates saved to {temp_dir_path}")

        # 2. Configure Client-Side mTLS (for this script's RPCPluginClient instance)
        client_magic_cookie_key = "PYVIDER_MTLS_EXAMPLE_COOKIE"
        client_magic_cookie_value = "mtls-is-super-secure-123"

        configure(
            auto_mtls=True,
            client_cert_path=f"file://{client_cert_path}",
            client_key_path=f"file://{client_key_path}",
            server_root_certs_path=f"file://{ca_cert_path}",
            magic_cookie_key=client_magic_cookie_key,
            magic_cookie=client_magic_cookie_value,
        )
        logger.info("🔧 Client-side mTLS configured programmatically.")

        # 3. Prepare Environment for Server Subprocess
        server_env_vars = {
            "PLUGIN_AUTO_MTLS": "True",
            "PLUGIN_SERVER_CERT": f"file://{server_cert_path}",
            "PLUGIN_SERVER_KEY": f"file://{server_key_path}",
            "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_cert_path}",
            client_magic_cookie_key: client_magic_cookie_value,
            "PLUGIN_LOG_LEVEL": "INFO",
            "PLUGIN_HANDSHAKE_TIMEOUT": "20.0",
        }

        # 4. Launch Server and Connect Client
        example_dir = Path(__file__).resolve().parent
        dummy_server_executable = example_dir / "00_dummy_server.py"
        dummy_server_command = [sys.executable, str(dummy_server_executable)]

        client: RPCPluginClient | None = None
        try:
            logger.info(
                f"🚀 Launching mTLS-enabled dummy server: "
                f"{' '.join(dummy_server_command)}"
            )
            client = plugin_client(
                command=dummy_server_command, config={"env": server_env_vars}
            )

            await client.start()
            logger.info("✅ Successfully connected to mTLS-enabled server!")

            if client._controller_stub:
                logger.info(
                    "✅ Controller stub available, basic connection seems okay."
                )
            else:
                logger.error("❌ Controller stub not available after connect.")

        except RPCPluginError as e:
            logger.error(f"❌ mTLS Client RPCPluginError: {e.message}", exc_info=True)
            if e.hint:
                logger.error(f"   Hint: {e.hint}")
        except Exception as e:
            logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)
        finally:
            if client:
                logger.info("🔌 Shutting down client and mTLS-enabled server...")
                await client.close()
                logger.info("🔌 Client and server shut down.")

    finally:
        # 5. Cleanup
        logger.info(f"🔑 Cleaning up temporary certificate directory: {temp_dir_path}")
        temp_dir_obj.cleanup()
        logger.info("🔑 Cleanup complete.")


async def main() -> None:
    """Run mTLS example."""
    await functional_mtls_example()


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔒✨
