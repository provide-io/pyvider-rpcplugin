#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Security and mTLS Configuration - Functional Example.
This example demonstrates a working mTLS setup between a client and a server
plugin launched as a subprocess."""

import asyncio
import os
from pathlib import Path
import sys
import tempfile

# First-party imports (project-specific)
from example_utils import configure_for_example  # type: ignore[import-not-found]

# Apply base configuration for examples (paths, logging)
# Client context, clear its own env before specific mTLS config.
configure_for_example(clear_env=True)

from provide.foundation import logger  # noqa: E402
from provide.foundation.crypto import Certificate  # noqa: E402

from pyvider.rpcplugin import (  # noqa: E402
    RPCPluginClient,
    RPCPluginError,
    configure,
    plugin_client,
)


async def functional_mtls_example() -> None:  # noqa: C901
    """Functional example of mTLS configuration and operation."""

    temp_dir_obj = tempfile.TemporaryDirectory(prefix="pyvider_mtls_example_")
    temp_dir_path = Path(temp_dir_obj.name)
    logger.info(f"🔑 Created temporary directory for certificates: {temp_dir_path}")

    # Store original env vars to restore them later
    original_env = {}
    env_keys_to_manage = [
        "PLUGIN_AUTO_MTLS",
        "PLUGIN_CLIENT_CERT",
        "PLUGIN_CLIENT_KEY",
        "PLUGIN_SERVER_ROOT_CERTS",
        "PLUGIN_MAGIC_COOKIE_KEY",
        "PLUGIN_MAGIC_COOKIE_VALUE",
    ]
    for key in env_keys_to_manage:
        if key in os.environ:
            original_env[key] = os.environ[key]

    try:
        # 1. Generate Certificates
        logger.info("🔑 Generating CA, Server, and Client certificates...")
        ca_cert_obj = Certificate.create_ca(
            common_name="Example Corp CA",
            organization_name="Pyvider Example Corp",
            validity_days=1,
        )
        server_cert_obj = Certificate.create_signed_certificate(
            ca_certificate=ca_cert_obj,
            common_name="mtls-server.example.com",
            organization_name="Pyvider Example Corp Servers",
            alt_names=["localhost", "127.0.0.1"],
            is_client_cert=False,
            validity_days=1,
        )
        client_cert_obj = Certificate.create_signed_certificate(
            ca_certificate=ca_cert_obj,
            common_name="mtls-client.example.com",
            organization_name="Pyvider Example Corp Clients",
            is_client_cert=True,
            validity_days=1,
        )

        # Get PEM strings directly
        ca_cert_pem = ca_cert_obj.cert_pem
        client_cert_pem = client_cert_obj.cert_pem
        client_key_pem = client_cert_obj.key_pem
        server_cert_pem = server_cert_obj.cert_pem
        server_key_pem = server_cert_obj.key_pem

        assert client_key_pem is not None, "Client key PEM is None"  # nosec B101
        assert server_key_pem is not None, "Server key PEM is None"  # nosec B101

        # Save to temp files primarily for the server subprocess
        server_cert_file_path = temp_dir_path / "server.crt"
        server_key_file_path = temp_dir_path / "server.key"
        ca_cert_file_path = (
            temp_dir_path / "ca_for_server_to_verify_client.crt"
        )  # Server uses this to verify client

        server_cert_file_path.write_text(server_cert_pem)
        server_key_file_path.write_text(server_key_pem)
        ca_cert_file_path.write_text(ca_cert_pem)  # This CA is for server to verify client
        logger.info(f"🔑 Server-related certificates saved to {temp_dir_path}")

        # 2. Configure Client-Side mTLS (for this script's RPCPluginClient instance)
        #    using direct PEM strings.
        client_magic_cookie_key = "PYVIDER_MTLS_EXAMPLE_COOKIE"
        client_magic_cookie_value = "mtls-is-super-secure-123"

        configure(
            auto_mtls=True,
            client_cert=client_cert_pem,  # Pass PEM string
            client_key=client_key_pem,  # Pass PEM string
            server_root_certs=ca_cert_pem,  # Pass CA PEM string
            # (for client to verify server)
            magic_cookie_key=client_magic_cookie_key,
            magic_cookie=client_magic_cookie_value,
            handshake_timeout=30.0,  # Increased timeouts
            connection_timeout=25.0,
            channel_ready_timeout=25.0,  # Increased from default 10s
        )

        # No need to set os.environ for client-side certs if configure() is
        # respected and not reset before client use. The main issue is ensuring
        # the configure() call's effect persists until RPCPluginClient reads it.
        # The autouse fixture in conftest.py might reset it. Forcing it into
        # env is one way, but direct PEM should be more robust if the config
        # object isn't swapped out.

        # 3. Prepare Environment for Server Subprocess
        # Server subprocess will need file paths.
        server_env_vars = {
            "PLUGIN_AUTO_MTLS": "True",
            "PLUGIN_SERVER_CERT": f"file://{server_cert_file_path}",
            "PLUGIN_SERVER_KEY": f"file://{server_key_file_path}",
            # Server uses this CA to verify client cert
            "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_cert_file_path}",
            client_magic_cookie_key: client_magic_cookie_value,  # Actual cookie env
            # var for server
            # Server's config for which key to read
            "PLUGIN_MAGIC_COOKIE_KEY": client_magic_cookie_key,
            # Server's config for expected value
            "PLUGIN_MAGIC_COOKIE_VALUE": client_magic_cookie_value,
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "PLUGIN_HANDSHAKE_TIMEOUT": "25.0",
            "PLUGIN_CONNECTION_TIMEOUT": "20.0",
        }

        # 4. Launch Server and Connect Client
        example_dir = Path(__file__).resolve().parent
        dummy_server_executable = example_dir / "dummy_server.py"
        dummy_server_command = [sys.executable, str(dummy_server_executable)]

        client: RPCPluginClient | None = None
        try:
            logger.info(f"🚀 Launching mTLS-enabled dummy server: {' '.join(dummy_server_command)}")
            client = plugin_client(command=dummy_server_command, config={"env": server_env_vars})

            await client.start()

            if client._controller_stub:  # Accessing private member for example check
                logger.info("✅ mTLS handshake successful, controller stub available.")
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
                await client.close()

    finally:
        # 5. Cleanup
        logger.info(f"🔑 Cleaning up temporary certificate directory: {temp_dir_path}")
        temp_dir_obj.cleanup()
        logger.info("🔑 Cleanup complete.")

        # Restore original environment variables
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:  # Check if key exists before trying to delete
                del os.environ[key]
        # Also remove keys that were added if they weren't in original_env
        for key in env_keys_to_manage:
            if key not in original_env and key in os.environ:
                del os.environ[key]


async def main() -> None:
    """Run mTLS example."""
    await functional_mtls_example()


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔌📞🔚
