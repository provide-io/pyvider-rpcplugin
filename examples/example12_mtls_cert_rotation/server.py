import asyncio
import logging
import os
import signal
import threading
import time
from pathlib import Path
from typing import Optional

import grpc
from pyvider.rpcplugin.server import PluginServer, ServerConfig
from pyvider.rpcplugin.config import RpcPluginConfig, LogLevel
from pyvider.rpcplugin.crypto import Certificate, KeyPair, load_pem_certificate
from pyvider.rpcplugin.handshake import HandshakeConfig

# Import generated protobuf code
from . import service_pb2, service_pb2_grpc

# Import certificate generation utilities
from .certs import (
    BASE_CERT_DIR,
    generate_ca,
    generate_server_cert,
    get_ca_cert_pem_path,
    get_server_cert_pem_path,
    get_server_key_pem_path,
    clear_certs,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")


class GreeterServicer(service_pb2_grpc.GreeterServicer):
    def __init__(self, server_instance):
        self.server_instance: "RotatingCertServer" = server_instance
        self._lock = threading.Lock() # For thread-safe access to shared server state if needed

    async def SayHello(self, request: service_pb2.HelloRequest, context: grpc.aio.ServicerContext) -> service_pb2.HelloReply:
        peer = context.peer()
        logger.info(f"SayHello called by {request.name} from {peer}")

        # You can inspect client cert details if needed:
        # auth_context = context.auth_context()
        # for key, value in auth_context:
        #    logger.debug(f"Auth context: {key} = {value}")
        # client_cn = next((v.decode() for k,v in auth_context if k == 'x509_common_name'), "Unknown CN")
        # logger.info(f"Client CN: {client_cn}")

        return service_pb2.HelloReply(message=f"Hello, {request.name}! (Server cert: {self.server_instance.current_server_cert_common_name})")

    async def RotateCert(self, request: service_pb2.RotateCertRequest, context: grpc.aio.ServicerContext) -> service_pb2.RotateCertReply:
        logger.info("RotateCert RPC called. Initiating certificate rotation...")
        try:
            new_server_cert_pem_path, new_server_key_pem_path, new_ca_for_clients_pem_path = await self.server_instance.rotate_server_certificate()

            # Read the new server cert to send back to client (optional, client might get it via new CA)
            with open(new_server_cert_pem_path, 'r') as f:
                new_server_cert_pem = f.read()

            status_message = f"Server certificate rotated successfully. Now using: {self.server_instance.current_server_cert_common_name}."
            if new_ca_for_clients_pem_path:
                status_message += f" CA for client validation might have changed. New CA for clients: {new_ca_for_clients_pem_path.name}"

            logger.info(status_message)
            return service_pb2.RotateCertReply(status_message=status_message, new_server_cert_pem=new_server_cert_pem)
        except Exception as e:
            logger.exception("Failed to rotate server certificate")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Error during certificate rotation: {e}")
            return service_pb2.RotateCertReply(status_message=f"Error: {e}")

    async def GetNewCACert(self, request: service_pb2.GetNewCACertRequest, context: grpc.aio.ServicerContext) -> service_pb2.GetNewCACertReply:
        logger.info("GetNewCACert RPC called.")
        if self.server_instance.current_ca_for_clients_pem_path:
            try:
                with open(self.server_instance.current_ca_for_clients_pem_path, 'r') as f:
                    ca_cert_pem = f.read()
                logger.info(f"Providing CA cert: {self.server_instance.current_ca_for_clients_pem_path.name}")
                return service_pb2.GetNewCACertReply(new_ca_cert_pem=ca_cert_pem)
            except Exception as e:
                logger.exception("Failed to read current CA cert for client")
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details(f"Error reading CA cert: {e}")
                return service_pb2.GetNewCACertReply()
        else:
            logger.warning("No CA certificate path configured to provide.")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("No new CA certificate available.")
            return service_pb2.GetNewCACertReply()


class RotatingCertServer:
    def __init__(self, host: str = "localhost", port: int = 50051):
        self.host = host
        self.port = port
        self.grpc_server: Optional[grpc.aio.Server] = None
        self._stop_event = asyncio.Event()
        self._current_cert_version = 1 # Start with v1 certs

        # Initial certificate setup
        self.ca_v1_cert: Optional[Certificate] = None
        self.ca_v1_key: Optional[KeyPair] = None
        self.server_v1_cert: Optional[Certificate] = None
        self.server_v1_key: Optional[KeyPair] = None

        self.ca_v2_cert: Optional[Certificate] = None
        self.ca_v2_key: Optional[KeyPair] = None

        self.current_server_cert_pem_path: Optional[Path] = None
        self.current_server_key_pem_path: Optional[Path] = None
        self.current_ca_for_clients_pem_path: Optional[Path] = None # CA used to verify client certs
        self.current_server_cert_common_name: str = "UNKNOWN"

        self._prepare_initial_certificates()

        # Configure rpcplugin (minimal, will override cert paths)
        self.rpc_config = RpcPluginConfig()
        self.rpc_config.configure(
            PLUGIN_HOST_ADDRESS=f"{self.host}:{self.port}",
            PLUGIN_SERVER_CERT_PATH=str(self.current_server_cert_pem_path),
            PLUGIN_SERVER_KEY_PATH=str(self.current_server_key_pem_path),
            PLUGIN_CLIENT_CA_CERT_PATH=str(self.current_ca_for_clients_pem_path),
            PLUGIN_SECURE_MODE="mtls",
            PLUGIN_LOG_LEVEL=LogLevel.DEBUG, # Enable debug for more insight
            HANDSHAKE_TIMEOUT_SECONDS=10,
        )
        # Set handshake config based on rpc_config
        self.handshake_cfg = HandshakeConfig.from_rpc_config(self.rpc_config)


    def _prepare_initial_certificates(self):
        logger.info("Preparing initial (v1) certificates...")
        clear_certs() # Clean slate for the demo

        self.ca_v1_cert, self.ca_v1_key = generate_ca(version=1)
        # Make server cert v1 expire quickly for testing rotation
        self.server_v1_cert, self.server_v1_key = generate_server_cert(self.ca_v1_cert, self.ca_v1_key, version=1, days_valid=1)

        # Also pre-generate CA v2 and server v2 (signed by CA v2) for rotation
        self.ca_v2_cert, self.ca_v2_key = generate_ca(version=2)
        generate_server_cert(self.ca_v2_cert, self.ca_v2_key, version=2, days_valid=90) # server_v2.pem, server_v2.key
        # Pre-generate server v3 (signed by CA v1)
        generate_server_cert(self.ca_v1_cert, self.ca_v1_key, version=3, days_valid=90) # server_v3.pem, server_v3.key

        self.current_server_cert_pem_path = get_server_cert_pem_path(1)
        self.current_server_key_pem_path = get_server_key_pem_path(1)
        self.current_ca_for_clients_pem_path = get_ca_cert_pem_path(1) # Initially, server trusts clients signed by CA v1
        self.current_server_cert_common_name = self.server_v1_cert.subject_common_name

        logger.info(f"Initial server cert: {self.current_server_cert_pem_path.name} (CN: {self.current_server_cert_common_name})")
        logger.info(f"Initial CA for client validation: {self.current_ca_for_clients_pem_path.name}")


    async def rotate_server_certificate(self) -> Tuple[Path, Path, Optional[Path]]:
        """
        Rotates the server's certificate.
        This example demonstrates two scenarios:
        1. Rotate to server_v3 (signed by original CA_v1). Client doesn't need CA update.
        2. Rotate to server_v2 (signed by new CA_v2). Client WILL need CA update.
        """
        logger.info(f"Current server cert version: {self._current_cert_version}")

        if self._current_cert_version == 1: # Initial state is server_v1 (signed by ca_v1)
            # Scenario 1: Rotate to server_v3 (signed by ca_v1)
            # Client CA trust does not need to change yet.
            new_server_cert_path = get_server_cert_pem_path(3)
            new_server_key_path = get_server_key_pem_path(3)
            # CA for client validation remains ca_v1
            new_ca_for_clients_path = get_ca_cert_pem_path(1)
            self._current_cert_version = 3
            new_cn = f"localhost_server_v{self._current_cert_version}"
            logger.info("Rotating to Server v3 (signed by CA v1). Client CA trust unchanged.")

        elif self._current_cert_version == 3: # Currently server_v3 (signed by ca_v1)
            # Scenario 2: Rotate to server_v2 (signed by new ca_v2)
            # Now, the CA for client validation MUST also change to ca_v2 if we want clients signed by ca_v2
            # For simplicity in this step, we'll assume clients are still using certs from CA_v1,
            # but the server is now presenting a cert from CA_v2.
            # A more complex scenario would involve the client also rotating its cert and the server trusting CA_v2 for clients.
            # For this example, let's say the server now *only* trusts clients from CA_v2.
            new_server_cert_path = get_server_cert_pem_path(2)
            new_server_key_path = get_server_key_pem_path(2)
            new_ca_for_clients_path = get_ca_cert_pem_path(2) # Server now expects clients to be signed by CA v2
            self._current_cert_version = 2
            new_cn = f"localhost_server_v{self._current_cert_version}"
            logger.info("Rotating to Server v2 (signed by CA v2). Server will now validate clients against CA v2.")

        elif self._current_cert_version == 2: # Currently server_v2 (signed by ca_v2)
            # Scenario 3: Rotate back to server_v1 (signed by ca_v1) for demo purposes
            new_server_cert_path = get_server_cert_pem_path(1)
            new_server_key_path = get_server_key_pem_path(1)
            new_ca_for_clients_path = get_ca_cert_pem_path(1) # Server back to validating clients against CA v1
            self._current_cert_version = 1
            new_cn = f"localhost_server_v{self._current_cert_version}"
            logger.info("Rotating back to Server v1 (signed by CA v1). Server will now validate clients against CA v1.")
        else:
            raise RuntimeError(f"Unknown current cert version: {self._current_cert_version}")

        # Update server's state
        self.current_server_cert_pem_path = new_server_cert_path
        self.current_server_key_pem_path = new_server_key_path
        self.current_ca_for_clients_pem_path = new_ca_for_clients_path
        self.current_server_cert_common_name = new_cn # Update CN based on new cert version

        # Update RpcPluginConfig with new paths
        self.rpc_config.set("PLUGIN_SERVER_CERT_PATH", str(self.current_server_cert_pem_path))
        self.rpc_config.set("PLUGIN_SERVER_KEY_PATH", str(self.current_server_key_pem_path))
        self.rpc_config.set("PLUGIN_CLIENT_CA_CERT_PATH", str(self.current_ca_for_clients_pem_path))

        # The PluginServer doesn't have a built-in dynamic credential update method.
        # A real-world high-availability server might need to:
        # 1. Start a new gRPC server instance on a different port with new creds.
        # 2. Signal clients to reconnect to the new port.
        # 3. Gracefully shut down the old server.
        # Or, use gRPC features like SO_REUSEPORT and careful fd handling if available and supported
        # by the Python gRPC library for true zero-downtime updates on the same port.
        #
        # For this example, we'll simulate by stopping and restarting the gRPC server component.
        # This WILL drop existing connections.
        logger.info("Stopping current gRPC server to apply new certificates...")
        if self.grpc_server:
            await self.grpc_server.stop(grace=1.0) # Grace period of 1 second
            logger.info("gRPC server stopped.")

        logger.info("Restarting gRPC server with new certificates...")
        await self._start_grpc_server() # This will use the updated paths in rpc_config
        logger.info(f"gRPC server restarted with cert {self.current_server_cert_pem_path.name} and CA {self.current_ca_for_clients_pem_path.name}")

        return self.current_server_cert_pem_path, self.current_server_key_pem_path, self.current_ca_for_clients_pem_path


    async def _start_grpc_server(self):
        """Starts the gRPC server with current certificate configuration."""
        if self.grpc_server:
             logger.warning("gRPC server already running or not fully stopped. This should not happen.")
             # Ensure it's fully stopped before creating a new one.
             await self.grpc_server.stop(grace=0)

        self.grpc_server = grpc.aio.server()

        # Regenerate server credentials using the (potentially updated) PluginServer logic
        # This assumes PluginServer can generate credentials from the current rpc_config
        # For mTLS, PluginServer.generate_server_credentials needs the CA path for client auth.

        # Directly load credentials for grpc.aio.server
        # This bypasses some PluginServer abstractions but gives direct control for example
        try:
            with open(self.current_server_key_pem_path, 'rb') as f:
                private_key = f.read()
            with open(self.current_server_cert_pem_path, 'rb') as f:
                certificate_chain = f.read()
            with open(self.current_ca_for_clients_pem_path, 'rb') as f: # CA for client auth
                root_certificates = f.read()
        except FileNotFoundError as e:
            logger.error(f"Certificate file not found during server start: {e}")
            raise

        server_credentials = grpc.ssl_server_credentials(
            private_key_certificate_chains=[(private_key, certificate_chain)],
            root_certificates=root_certificates, # For mTLS, server needs CA to verify client certs
            require_client_auth=True
        )

        service_pb2_grpc.add_GreeterServicer_to_server(GreeterServicer(self), self.grpc_server)

        listen_addr = f"{self.host}:{self.port}"
        self.grpc_server.add_secure_port(listen_addr, server_credentials)

        await self.grpc_server.start()
        logger.info(f"gRPC Server started on {listen_addr}, using server cert: {self.current_server_cert_pem_path.name} (CN: {self.current_server_cert_common_name}), client CA: {self.current_ca_for_clients_pem_path.name}")


    async def serve(self):
        await self._start_grpc_server() # Start with initial certs

        # Periodically check server cert v1 for expiration (visual aid)
        # A real server would have more robust monitoring
        async def check_cert_expiry_task():
            while not self._stop_event.is_set():
                try:
                    if self.current_server_cert_pem_path == get_server_cert_pem_path(1): # only check original v1 cert
                        server_v1_disk_cert = load_pem_certificate(get_server_cert_pem_path(1))
                        if server_v1_disk_cert.is_expired:
                            logger.warning(f"CERT WATCHER: Server certificate {get_server_cert_pem_path(1).name} HAS EXPIRED at {server_v1_disk_cert.not_valid_after_datetime}. Rotation required.")
                        else:
                            logger.info(f"CERT WATCHER: Server certificate {get_server_cert_pem_path(1).name} is still valid. Expires: {server_v1_disk_cert.not_valid_after_datetime}")
                except Exception as e:
                    logger.error(f"CERT WATCHER: Error checking cert expiry: {e}")
                await asyncio.sleep(60) # Check every 60 seconds

        expiry_check_task = asyncio.create_task(check_cert_expiry_task())

        try:
            await self._stop_event.wait()
        finally:
            logger.info("Shutting down server...")
            expiry_check_task.cancel()
            try:
                await expiry_check_task
            except asyncio.CancelledError:
                logger.info("Expiry check task cancelled.")

            if self.grpc_server:
                await self.grpc_server.stop(grace=5.0) # Grace period for shutdown
                logger.info("gRPC server stopped gracefully.")
            # Cleanup certs dir for next run
            # clear_certs()


    def _handle_sigterm(self, signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self._stop_event.set()


async def main():
    server_instance = RotatingCertServer()

    # Register signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, server_instance._handle_sigterm, sig, None)

    logger.info("Starting RotatingCertServer...")
    await server_instance.serve()
    logger.info("RotatingCertServer has shut down.")


if __name__ == "__main__":
    # This example does not use the PluginServer's main serve() method directly
    # as it needs more control over the gRPC server instance for rotation.
    # We are essentially building a gRPC server that *could* be part of a plugin.

    # Setup for running this file directly (e.g. for testing the server logic)
    # In a real plugin, the PluginServer would manage the lifecycle.

    # Ensure protoc generated files are available
    # This should be handled by the build system or run separately
    # For this example, assume they are in the same directory or python path
    try:
        from . import service_pb2, service_pb2_grpc # noqa
    except ImportError:
        logger.error("Failed to import protobuf generated files. Make sure to run:"
              " python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. service.proto"
              " in the examples/example12_mtls_cert_rotation directory.")
        exit(1)

    if not BASE_CERT_DIR.exists():
        logger.info(f"Certificates directory {BASE_CERT_DIR} does not exist. Running certs.py to generate them...")
        import subprocess
        script_dir = Path(__file__).parent
        try:
            subprocess.run(["python", str(script_dir / "certs.py")], check=True, cwd=script_dir)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate certificates using certs.py: {e}")
            exit(1)
        except FileNotFoundError:
            logger.error("certs.py not found or python not in PATH.")
            exit(1)


    asyncio.run(main())
