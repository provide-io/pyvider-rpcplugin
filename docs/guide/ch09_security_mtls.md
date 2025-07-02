# Chapter 9: Security with mTLS

Mutual TLS (mTLS) is a critical security feature for plugin architectures, ensuring that both the client (host application) and the server (plugin) authenticate each other before any communication occurs. This prevents unauthorized processes from interacting with your plugins and ensures data integrity and confidentiality through encryption.

`pyvider.rpcplugin` provides built-in support for mTLS, simplifying its setup and management.

## Key Concepts for mTLS

*   **CA (Certificate Authority)**: An entity that issues digital certificates. In a typical mTLS setup, both the client and server certificates are signed by the same CA, or by CAs that trust each other. For development and testing, you can create your own self-signed CA.
*   **Server Certificate & Key**: The plugin server uses its certificate to prove its identity to the client. It also has a corresponding private key, which must be kept secret.
*   **Client Certificate & Key**: The host application (client) uses its certificate to prove its identity to the server. It also has a corresponding private key.
*   **Root Certificates (Trust Store)**:
    *   The **client** needs a copy of the CA certificate(s) that signed the **server's certificate**. This is used to verify the server's identity. Configured via `PLUGIN_SERVER_ROOT_CERTS`.
    *   The **server** needs a copy of the CA certificate(s) that signed the **client's certificate**. This is used to verify the client's identity. Configured via `PLUGIN_CLIENT_ROOT_CERTS`.
    If a single CA signs both client and server certificates, then both `PLUGIN_SERVER_ROOT_CERTS` and `PLUGIN_CLIENT_ROOT_CERTS` would point to the same CA certificate file.

## Configuration for mTLS

`pyvider.rpcplugin` uses several configuration variables (typically set as environment variables or programmatically via `configure()`) to enable and manage mTLS:

*   **`PLUGIN_AUTO_MTLS`**: Set to `"true"` (or boolean `True`) to enable mTLS. If this is true, the following certificate/key paths become essential.
*   **Server-Side (for `RPCPluginServer` in your plugin executable):**
    *   `PLUGIN_SERVER_CERT`: Path to the server's own certificate PEM file (e.g., `file:///path/to/server.crt`).
    *   `PLUGIN_SERVER_KEY`: Path to the server's own private key PEM file (e.g., `file:///path/to/server.key`).
    *   `PLUGIN_CLIENT_ROOT_CERTS`: Path to the CA certificate(s) PEM file that the server will use to verify incoming client certificates.
*   **Client-Side (for `RPCPluginClient` in your host application):**
    *   `PLUGIN_CLIENT_CERT`: Path to the client's own certificate PEM file (e.g., `file:///path/to/client.crt`).
    *   `PLUGIN_CLIENT_KEY`: Path to the client's own private key PEM file (e.g., `file:///path/to/client.key`).
    *   `PLUGIN_SERVER_ROOT_CERTS`: Path to the CA certificate(s) PEM file that the client will use to verify the server's certificate.

**Certificate Generation:**
The `pyvider.rpcplugin.crypto.Certificate` class provides helper methods like `Certificate.create_ca()`, `Certificate.create_signed_certificate()`, and `Certificate.create_self_signed_server_cert()` to assist in generating the necessary PEM-encoded certificates and keys.

## Example: mTLS Setup (`examples/ch09_security_mtls_example.py`)

This example provides a functional demonstration of setting up an mTLS-secured connection between a client and a plugin server (the `ch02_dummy_server.py` example). It programmatically generates all necessary certificates (CA, server, client) and configures both the client and the server subprocess to use them.

```python
#!/usr/bin/env python3
# examples/ch09_security_mtls_example.py
import asyncio
import sys
import tempfile
from pathlib import Path
from example_utils import configure_for_example # Base config for paths
from pyvider.rpcplugin import RPCPluginClient, RPCPluginError, configure, plugin_client
from pyvider.rpcplugin.crypto import Certificate
from pyvider.telemetry import logger

# Apply base configuration for examples (paths, logging)
# Client context, clear its own env before specific mTLS config.
configure_for_example(clear_env=True)


async def functional_mtls_example() -> None:
    """Functional example of mTLS configuration and operation."""
    logger.info("🔒🐍 Functional mTLS Configuration Example")

    temp_dir_obj = tempfile.TemporaryDirectory(prefix="pyvider_mtls_example_")
    temp_dir_path = Path(temp_dir_obj.name)
    logger.info(f"🔑 Created temporary directory for certificates: {temp_dir_path}")

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
        ca_cert_pem = ca_cert_obj.cert
        client_cert_pem = client_cert_obj.cert
        client_key_pem = client_cert_obj.key
        server_cert_pem = server_cert_obj.cert
        server_key_pem = server_cert_obj.key

        assert client_key_pem is not None, "Client key PEM is None"
        assert server_key_pem is not None, "Server key PEM is None"

        # Save to temp files primarily for the server subprocess
        server_cert_file_path = temp_dir_path / "server.crt"
        server_key_file_path = temp_dir_path / "server.key"
        # This CA is for server to verify client, and client to verify server
        ca_file_path_for_server_to_verify_client = temp_dir_path / "ca_for_server.crt"

        server_cert_file_path.write_text(server_cert_pem)
        server_key_file_path.write_text(server_key_pem)
        ca_file_path_for_server_to_verify_client.write_text(ca_cert_pem)
        logger.info(f"🔑 Server-related certificates saved to {temp_dir_path}")

        # 2. Configure Client-Side mTLS (for this script's RPCPluginClient instance)
        #    using direct PEM strings.
        client_magic_cookie_key = "PYVIDER_MTLS_EXAMPLE_COOKIE"
        client_magic_cookie_value = "mtls-is-super-secure-123"

        configure(
            auto_mtls=True,
            client_cert=client_cert_pem,  # Pass PEM string
            client_key=client_key_pem,  # Pass PEM string
            server_root_certs=ca_cert_pem, # Client trusts this CA for server cert
            magic_cookie_key=client_magic_cookie_key,
            magic_cookie=client_magic_cookie_value,
            handshake_timeout=30.0,
            connection_timeout=25.0,
        )
        logger.info(
            "🔧 Client-side mTLS configured programmatically using PEM strings via configure()."
        )

        # 3. Prepare Environment for Server Subprocess
        # Server subprocess will need file paths.
        server_env_vars = {
            "PLUGIN_AUTO_MTLS": "True",
            "PLUGIN_SERVER_CERT": f"file://{server_cert_file_path}",
            "PLUGIN_SERVER_KEY": f"file://{server_key_file_path}",
            "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_file_path_for_server_to_verify_client}", # Server trusts this CA for client cert
            client_magic_cookie_key: client_magic_cookie_value, # Actual cookie env var for server
            "PLUGIN_MAGIC_COOKIE_KEY": client_magic_cookie_key, # Server's config for which key to read
            "PLUGIN_MAGIC_COOKIE_VALUE": client_magic_cookie_value, # Server's config for expected value
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "PLUGIN_HANDSHAKE_TIMEOUT": "25.0", # Server handshake timeout
            "PLUGIN_CONNECTION_TIMEOUT": "20.0", # Server connection timeout
        }

        # 4. Launch Server and Connect Client
        example_dir = Path(__file__).resolve().parent
        dummy_server_executable = example_dir / "ch02_dummy_server.py"
        dummy_server_command = [sys.executable, str(dummy_server_executable)]

        client: RPCPluginClient | None = None
        try:
            logger.info(f"🚀 Launching mTLS-enabled dummy server: {' '.join(dummy_server_command)}")
            client = plugin_client(
                command=dummy_server_command,
                config={"env": server_env_vars} # Pass prepared env to the subprocess
            )
            await client.start() # This performs launch, handshake (including mTLS), and connection
            logger.info("✅ Successfully connected to mTLS-enabled dummy server!")

            # A simple check: if connected, the controller stub should be available
            assert client._controller_stub is not None, "Controller stub should be initialized on successful connection."
            logger.info("   Basic check: Controller stub is available, indicating connection success.")
            await asyncio.sleep(1) # Keep connection alive briefly

        except RPCPluginError as e:
            logger.error(f"❌ mTLS Client RPCPluginError: {e.message} (Hint: {e.hint})", exc_info=True)
        except Exception as e:
            logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)
        finally:
            if client:
                logger.info("🔌 Shutting down client and mTLS-enabled server...")
                await client.close() # This will also terminate the server subprocess
                logger.info("🔌 Client and server shut down.")
    finally:
        logger.info(f"🔑 Cleaning up temporary certificate directory: {temp_dir_path}")
        temp_dir_obj.cleanup()

if __name__ == "__main__":
    asyncio.run(functional_mtls_example())
```

**Explanation of the mTLS Example:**

1.  **Certificate Generation**:
    *   A new Certificate Authority (CA) is created using `Certificate.create_ca()`.
    *   A server certificate (`server_cert_obj`) is generated and signed by this CA. It includes `localhost` and `127.0.0.1` in its Subject Alternative Names (SANs), which is important for successful TLS validation when connecting to `localhost`.
    *   A client certificate (`client_cert_obj`) is also generated and signed by the same CA.
    *   All certificates and their private keys are saved to temporary files.
2.  **Client-Side mTLS Configuration**:
    *   The `pyvider.rpcplugin.configure()` function is used to set up the global `rpcplugin_config` for the *current* Python process (which is acting as the client launching the plugin).
    *   `auto_mtls=True` enables mTLS.
    *   `client_cert` and `client_key` are set to the paths of the generated client certificate and key.
    *   `server_root_certs` is set to the path of the CA certificate. This tells the client to trust server certificates signed by this CA.
    *   Magic cookie variables are also configured.
3.  **Server Subprocess Environment**:
    *   A dictionary `server_env_vars` is prepared. These environment variables will be passed to the `ch02_dummy_server.py` subprocess when it's launched by `RPCPluginClient`.
    *   `PLUGIN_AUTO_MTLS="True"` tells the dummy server to enable mTLS.
    *   `PLUGIN_SERVER_CERT` and `PLUGIN_SERVER_KEY` point to the server's certificate and key.
    *   `PLUGIN_CLIENT_ROOT_CERTS` points to the CA certificate, which the server will use to verify the client's certificate during the mTLS handshake.
    *   The magic cookie key and value are also included.
4.  **Launch and Connect**:
    *   `plugin_client()` creates an `RPCPluginClient`. The `config={"env": server_env_vars}` argument ensures the server subprocess gets the mTLS settings.
    *   `client.start()` initiates the process. The `RPCPluginClient` (using its global mTLS config) and the `RPCPluginServer` (using the environment variables) will both attempt an mTLS handshake.
    *   If all certificates, keys, and CA trusts are set up correctly, the connection will be established securely.

This example demonstrates a robust mTLS setup. In a real production scenario, you would typically use certificates issued by a recognized CA or a well-managed internal PKI (Public Key Infrastructure) rather than generating them on the fly for each session.
