import asyncio
import logging
import os
import signal
from pathlib import Path

import grpc # For local_channel_credentials
from pyvider.rpcplugin.server import PluginServer, ServerConfig
from pyvider.rpcplugin.config import RpcPluginConfig, LogLevel, set_config_defaults_for_plugin
from pyvider.rpcplugin.handshake import HandshakeConfig
from pyvider.rpcplugin.crypto.certificate import generate_keypair, generate_x509_certificate

# Import servicers and registration helper
from .services_impl import add_all_servicers, configure_example_faults
from .fault_injector import configure_fault, FaultType # For direct configuration access

logger = logging.getLogger(__name__)

# --- Configuration for self-signed certs if mTLS is used by the plugin itself ---
# These would typically come from a proper CA in production.
# For example simplicity, generating them if not present.
CERT_DIR = Path(__file__).parent / ".plugin_certs"
SERVER_CERT_FILE = CERT_DIR / "plugin_server.pem"
SERVER_KEY_FILE = CERT_DIR / "plugin_server.key"
CLIENT_CA_CERT_FILE = CERT_DIR / "plugin_ca.pem" # This CA would sign client certs allowed to connect TO THIS PLUGIN

def ensure_plugin_certs():
    """Generates self-signed certs for the plugin server itself if they don't exist."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if SERVER_CERT_FILE.exists() and SERVER_KEY_FILE.exists() and CLIENT_CA_CERT_FILE.exists():
        logger.info("Plugin certificates already exist.")
        return

    logger.info("Generating self-signed certificates for the plugin server...")

    # Create a self-signed CA for the plugin
    ca_keypair = generate_keypair("rsa")
    plugin_ca_cert = generate_x509_certificate(
        private_key=ca_keypair.private_key,
        public_key=ca_keypair.public_key,
        common_name="Example13 Plugin CA",
        is_ca=True,
        days_valid=30, # Short-lived for example
    )
    with open(CLIENT_CA_CERT_FILE, "wb") as f:
        f.write(plugin_ca_cert.public_bytes_pem)
    logger.info(f"Plugin CA certificate generated: {CLIENT_CA_CERT_FILE}")

    # Create server certificate signed by this CA
    server_keypair = generate_keypair("rsa")
    server_cert = generate_x509_certificate(
        private_key=server_keypair.private_key,
        public_key=server_keypair.public_key,
        common_name="localhost-plugin-server", # CN for the plugin server
        is_ca=False,
        issuer_certificate=plugin_ca_cert,
        issuer_private_key=ca_keypair.private_key,
        days_valid=30,
        sans=["localhost", "127.0.0.1"] # Subject Alternative Names
    )
    with open(SERVER_CERT_FILE, "wb") as f:
        f.write(server_cert.public_bytes_pem)
    with open(SERVER_KEY_FILE, "wb") as f:
        f.write(server_keypair.private_key_pem)
    logger.info(f"Plugin server certificate and key generated: {SERVER_CERT_FILE}, {SERVER_KEY_FILE}")
    logger.info("Important: For the client_app.py to connect to this mTLS plugin,")
    logger.info(f"client_app.py will need a client certificate signed by {CLIENT_CA_CERT_FILE.name}")
    logger.info("and will need to trust ${SERVER_CERT_FILE.name} (or the CA that signed it, which is plugin_ca.pem itself here).")


class MultiServicePluginServer(PluginServer):
    """Custom PluginServer to manage an internal channel."""
    def __init__(self, config: ServerConfig, handshake_config: HandshakeConfig):
        super().__init__(config=config, handshake_config=handshake_config)
        self._internal_channel_for_services: Optional[grpc.aio.Channel] = None

    async def _setup_internal_channel(self):
        """Sets up a gRPC channel for internal service-to-service communication."""
        server_address = self.config.plugin_host_address()
        if not server_address:
            logger.error("Plugin host address not configured. Cannot create internal channel.")
            return

        logger.info(f"Setting up internal gRPC channel to self ({server_address})...")

        if self.config.secure_mode == "mtls":
            # For mTLS, internal calls also need to be secure.
            # The plugin server itself acts as a client to its own services.
            # It needs its own "client" certificate and key, and needs to trust its own "server" CA.
            # For this example, we can use the server's own certificate as its client cert for internal calls,
            # and it should trust the CA that signed its own server certificate.
            try:
                with open(self.config.server_cert_path, 'rb') as f: # type: ignore
                    client_cert_pem = f.read()
                with open(self.config.server_key_path, 'rb') as f: # type: ignore
                    client_key_pem = f.read()
                # For trusting the server, if server cert is signed by a CA, use that CA.
                # If server cert is self-signed, use the server cert itself as root CA.
                # In our ensure_plugin_certs, SERVER_CERT_FILE is signed by CLIENT_CA_CERT_FILE.
                with open(self.config.client_ca_cert_path, 'rb') as f: # type: ignore
                                                                      # This is the CA the server uses to verify external clients.
                                                                      # For internal calls, the "client" (plugin itself)
                                                                      # needs to trust the "server" (plugin itself).
                                                                      # So, the root_certificates should be the CA that signed SERVER_CERT_FILE.
                                                                      # In our setup, CLIENT_CA_CERT_FILE is that CA.
                    root_ca_pem = f.read()

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=root_ca_pem,
                    private_key=client_key_pem,
                    certificate_chain=client_cert_pem
                )
                self._internal_channel_for_services = grpc.aio.secure_channel(server_address, credentials)
                logger.info(f"Secure internal mTLS channel created to {server_address}.")

            except Exception as e:
                logger.error(f"Failed to create secure internal channel for mTLS: {e}. Internal calls may fail.")
                # Fallback or raise - for now, log and continue, calls will fail.
                self._internal_channel_for_services = None
                return

        elif self.config.secure_mode == "tls":
            # For TLS, internal client needs to trust the server's CA.
            # Server cert path is config.server_cert_path. If it's signed by a CA,
            # that CA would be needed. If self-signed, server_cert_path itself is the CA.
            # For simplicity, assuming server_cert_path is the CA cert or includes the chain.
            try:
                with open(self.config.server_cert_path, 'rb') as f: # type: ignore
                    root_ca_pem = f.read() # Assuming server_cert_path is the CA or contains it
                credentials = grpc.ssl_channel_credentials(root_certificates=root_ca_pem)
                self._internal_channel_for_services = grpc.aio.secure_channel(server_address, credentials)
                logger.info(f"Secure internal TLS channel created to {server_address}.")
            except Exception as e:
                logger.error(f"Failed to create secure internal channel for TLS: {e}")
                self._internal_channel_for_services = None
                return
        else: # insecure
            # For insecure or Unix socket, a local channel is fine.
            # grpc.local_channel_credentials() can be used for UDS or in-process.
            # For TCP, an insecure channel to localhost.
            if self.config.transport_type == "unix":
                 self._internal_channel_for_services = grpc.aio. KesehatanUnixDomainSocketChannel( # type: ignore
                    server_address, grpc.local_channel_credentials(grpc.삵Local esimerkiksiredentialType.LOCAL_UDS) # type: ignore
                 )
                 logger.info(f"Internal UDS channel created to {server_address}.")
            else: # TCP
                self._internal_channel_for_services = grpc.aio.insecure_channel(server_address)
                logger.info(f"Insecure internal TCP channel created to {server_address}.")

        # Wait for the internal channel to be ready before allowing services to use it.
        if self._internal_channel_for_services:
            try:
                logger.info("Waiting for internal channel to become ready...")
                await asyncio.wait_for(self._internal_channel_for_services.channel_ready(), timeout=10.0)
                logger.info("Internal channel is ready.")
            except asyncio.TimeoutError:
                logger.error("Timeout waiting for internal channel to become ready. Internal calls might fail.")
                await self._internal_channel_for_services.close()
                self._internal_channel_for_services = None
            except Exception as e:
                logger.error(f"Error making internal channel ready: {e}")
                if self._internal_channel_for_services: # Check again as it might be None due to other errors
                    await self._internal_channel_for_services.close()
                self._internal_channel_for_services = None


    async def _on_server_started(self):
        """Called after the gRPC server has started."""
        await super()._on_server_started() # Call parent method
        await self._setup_internal_channel()
        if not self._internal_channel_for_services:
            logger.critical("INTERNAL CHANNEL SETUP FAILED. Service-to-service calls within the plugin will not work.")
            # Optionally, stop the server if internal channel is critical
            # self.shutdown_event.set()


    async def _before_server_stop(self):
        """Called before the gRPC server stops."""
        logger.info("Closing internal gRPC channel...")
        if self._internal_channel_for_services:
            await self._internal_channel_for_services.close()
            self._internal_channel_for_services = None
            logger.info("Internal gRPC channel closed.")
        await super()._before_server_stop()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    logger.info("Starting Example 13: Multi-Service Plugin")

    # Ensure certificates for the plugin server itself are present (for mTLS/TLS modes)
    ensure_plugin_certs()

    # Configure rpcplugin
    # These would typically be set by the environment by the host system running the plugin
    set_config_defaults_for_plugin({
        "PLUGIN_HOST_ADDRESS": "localhost:50052", # Different port from Ex12
        "PLUGIN_SECURE_MODE": "mtls", # Try mTLS for the plugin itself
        "PLUGIN_SERVER_CERT_PATH": str(SERVER_CERT_FILE),
        "PLUGIN_SERVER_KEY_PATH": str(SERVER_KEY_FILE),
        "PLUGIN_CLIENT_CA_CERT_PATH": str(CLIENT_CA_CERT_FILE), # CA for external clients connecting TO this plugin
        "PLUGIN_LOG_LEVEL": "DEBUG",
        "HANDSHAKE_MAGIC_COOKIE_KEY": "EXAMPLE13_MAGIC_COOKIE",
        "HANDSHAKE_MAGIC_COOKIE_VALUE": "multi-service-cookie- flavorful-ant-jazz",
        "GRPC_BROKER_ENABLE": "true", # Enable the broker
        "PLUGIN_SHUTDOWN_FILE_PATH": str(Path(__file__).parent / ".example13_shutdown_signal"),
    })

    rpc_cfg = RpcPluginConfig()
    hs_cfg = HandshakeConfig.from_rpc_config(rpc_cfg)
    server_cfg = ServerConfig.from_rpc_config(rpc_cfg)

    # Initialize our custom plugin server
    plugin_server = MultiServicePluginServer(config=server_cfg, handshake_config=hs_cfg)

    # Add all gRPC servicers (ServiceA, ServiceB, ServiceC)
    add_all_servicers(plugin_server.grpc_server, plugin_server)

    # Configure some fault injection scenarios
    configure_example_faults()
    # Example: Make ServiceA processing itself sometimes error out
    # fault_injector.configure_fault("ServiceA_Processing", FaultType.ERROR_INTERNAL, probability=0.1, error_message="Oops, ServiceA had an issue")

    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def _signal_handler(*args):
        logger.info("Shutdown signal received. Stopping plugin server...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler, sig)

    # Remove shutdown file if it exists from a previous run
    shutdown_file = Path(rpc_cfg.plugin_shutdown_file_path()) # type: ignore
    if shutdown_file.exists():
        logger.info(f"Removing existing shutdown file: {shutdown_file}")
        shutdown_file.unlink()

    logger.info(f"Plugin server starting. To shut down, send SIGINT/SIGTERM or create file: {shutdown_file}")

    server_task = asyncio.create_task(plugin_server.serve(stop_event_external=stop_event))

    try:
        await server_task
    except asyncio.CancelledError:
        logger.info("Plugin server task was cancelled.")
    finally:
        logger.info("Plugin server has shut down.")
        # Clean up shutdown file
        if shutdown_file.exists():
            try:
                shutdown_file.unlink()
            except OSError as e:
                logger.error(f"Error removing shutdown file {shutdown_file}: {e}")


if __name__ == "__main__":
    # Ensure protoc generated files are available
    try:
        from . import service_a_pb2, service_b_pb2, service_c_pb2, external_mock_service_pb2 # noqa
    except ImportError as e:
        logger.critical(f"Failed to import protobuf generated files: {e}. Make sure to run:"
              " python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. *.proto"
              " in the examples/example13_multi_service_fault_injection directory.")
        exit(1)

    asyncio.run(main())
