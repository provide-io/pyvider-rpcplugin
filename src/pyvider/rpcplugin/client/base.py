
# pyvider/rpcplugin/client/base.py

import asyncio
import contextlib  # Needed to suppress asyncio.CancelledError during task cleanup.
import os
import subprocess
import sys
from typing import Any, Optional

import attrs
import grpc

# Import the new Certificate API and key generation function.
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.handshake import (
    HandshakeConfig,
    parse_handshake_response,
)
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport

from pyvider.rpcplugin.client.types import (
    SecureRpcClientT,
    GrpcChannelType,
)

from pyvider.rpcplugin.transport.types import (
    TransportT,
)

@attrs.define
class RPCPluginClient(SecureRpcClientT):
    """
    RPCPluginClient implements the client‐side logic for the RPCPlugin protocol.
    It is responsible for launching the server process (if needed), performing the handshake,
    setting up mTLS credentials using the new Certificate API, establishing a secure gRPC channel,
    and creating stubs for communication.
    """
    command: list[str] = attrs.field()
    config: Optional[dict[str, Any]] = attrs.field(default=None)
    _process: Optional[subprocess.Popen] = attrs.field(init=False, default=None)
    _transport: Optional[TransportT] = attrs.field(init=False, default=None)
    _protocol_version: Optional[int] = attrs.field(init=False, default=None)
    _handshake_config: HandshakeConfig = attrs.field(init=False)
    _server_cert: Optional[str] = attrs.field(init=False, default=None)
    _channel: Optional[GrpcChannelType] = attrs.field(init=False, default=None)
    client_cert: Optional[str] = attrs.field(init=False, default=None)
    client_key_pem: Optional[str] = attrs.field(init=False, default=None)
    stderr_task: Optional[Any] = attrs.field(init=False, default=None)
    stdout_task: Optional[Any] = attrs.field(init=False, default=None)

    def __attrs_post_init__(self):
        # Initialize handshake configuration with default settings.
        logger.debug("🔧 Initializing handshake configuration for client.")
        self._handshake_config = HandshakeConfig(
            magic_cookie_key="PLUGIN_MAGIC_COOKIE_VALUE",  # Default; can be overridden via rpcplugin_config
            magic_cookie_value="hello",
            protocol_versions=rpcplugin_config.get("SUPPORTED_PROTOCOL_VERSIONS"),
            supported_transports=["unix", "tcp"],
        )

    def _relay_stderr(self) -> None:
        """
        Launches a background thread that continuously reads stderr from the server
        process and writes it to our stderr.
        """
        import threading

        def read_stderr():
            for line in iter(self._process.stderr.readline, ''):
                sys.stderr.write(line)
            self._process.stderr.close()

        threading.Thread(target=read_stderr, daemon=True).start()

    async def _perform_handshake(self) -> None:
        """
        Performs the handshake by reading and parsing the handshake response from
        the server process. This sets the protocol version, transport type, and server
        certificate for subsequent TLS channel creation.
        """
        logger.debug("🤝 Initiating handshake with server...")
        response_str = await self._read_handshake_response()
        if not response_str:
            logger.error("🤝 Handshake response is empty.")
            raise HandshakeError("No handshake response received.")

        response_str = response_str.decode() if isinstance(response_str, bytes) else response_str

        try:
            core_version, protocol_version, transport_name, endpoint, protocol, server_cert = (
                parse_handshake_response(response_str)
            )
        except Exception as e:
            logger.error(f"🤝 Failed to parse handshake response: {e}")
            raise

        logger.debug(
            f"🤝 Parsed handshake response: version={core_version}, plugin_version={protocol_version}, "
            f"transport={transport_name}, endpoint={endpoint}, protocol={protocol}"
        )

        self._protocol_version = protocol_version
        self._server_cert = server_cert  # The handshake response returns the server cert string

        # Set up transport based on handshake data.
        if transport_name == "tcp":
            self._transport = TCPSocketTransport()
        elif transport_name == "unix":
            self._transport = UnixSocketTransport(path=endpoint)
        else:
            logger.error(f"🚄 Unsupported transport type: {transport_name}")
            raise TransportError(f"Unsupported transport: {transport_name}")

        await self._transport.connect(endpoint)
        logger.info(f"🚄 Connected via {transport_name} to {endpoint}")

        # Set up TLS for the secure gRPC channel.
        await self._setup_tls()

    async def _setup_tls(self) -> None:
        """
        Sets up TLS credentials for the client's gRPC channel using the new Certificate API.
        If auto mTLS is enabled, the client either loads provided certificates or generates new
        self-signed certificates.
        """
        logger.debug("🔐 Setting up TLS credentials for the client...")
        auto_mtls = rpcplugin_config.get("PLUGIN_AUTO_MTLS")
        client_cert_pem = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
        client_key_pem = rpcplugin_config.get("PLUGIN_CLIENT_KEY")

        if auto_mtls:
            if client_cert_pem and client_key_pem:
                logger.info("🔐 Using provided client certificate and key.")
                client_cert_obj = Certificate(
                    cert=client_cert_pem,
                    key=client_key_pem,
                    generate_keypair=False
                )
            else:
                logger.info("🔐 No client certificate provided; generating new self-signed certificate.")
                client_cert_obj = Certificate(
                    generate_keypair=True,
                    key_type="ecdsa",  # Change to "rsa" if desired.
                    common_name="localhost"
                )
                logger.debug("🔐 Generated new self-signed client certificate.")

            self.client_cert = client_cert_obj.cert
            self.client_key_pem = client_cert_obj.key
        else:
            logger.info("🔐 mTLS not enabled; operating in insecure mode.")

    async def _read_handshake_response(self) -> str:
        """
        Reads the handshake response from the server process with concurrent stderr handling.
        
        The handshake response is expected to be a pipe-delimited string containing:
        - Handshake version
        - Protocol version
        - Transport type
        - Endpoint
        - Protocol type
        - Server certificate (optional)
        
        Returns:
            str: The handshake response string.
            
        Raises:
            HandshakeError: If no response is received, timeout occurs, or response is invalid.
        """
        logger.debug("🤝📖🚀 Reading handshake response from server process...")
        
        if not self._process or not self._process.stdout:
            logger.error("🤝📖❌ No process or stdout available for handshake")
            raise HandshakeError("No process or stdout available for handshake.")

        async def read_stderr() -> None:
            """Continuously read and log stderr output."""
            logger.trace("🤝📖🔍 Reading from server stderr...")
            while True:
                err_line = self._process.stderr.readline()
                if not err_line:
                    logger.debug("🤝📖✅ Server stderr stream closed")
                    break
                print(err_line.rstrip(), file=sys.stderr, flush=True)

        async def read_stdout() -> str:
            """
            Read stdout until handshake response is found.
            Returns the first line containing a pipe character.
            """
            logger.trace("🤝📖🔍 Reading from server stdout...")
            while True:
                line = self._process.stdout.readline()
                if not line:
                    logger.error("🤝📖❌ Server stdout stream closed without handshake")
                    raise HandshakeError("Server stdout closed without handshake response")
                
                print(line.rstrip(), file=sys.stdout, flush=True)
                if '|' in line:
                    logger.debug("🤝📖✅ Found handshake response")
                    return line.strip()

        stderr_task = asyncio.create_task(read_stderr())
        try:
            response = await asyncio.wait_for(
                read_stdout(),
                timeout=5.0  # 5 seconds should be enough for handshake
            )
            if not response:
                logger.error("🤝📖❌ Empty handshake response received")
                raise HandshakeError("Empty handshake response")
            
            logger.debug(f"🤝📖✅ Received handshake response: {response[:50]}...")
            return response
            
        except asyncio.TimeoutError:
            logger.error("🤝📖❌ Timeout waiting for handshake response")
            raise HandshakeError("Timeout waiting for handshake response")
            
        except Exception as e:
            logger.error(f"🤝📖❌ Error reading handshake: {e}")
            # Capture stderr for debugging
            stderr_output = ""
            if self._process and self._process.stderr:
                stderr_output = self._process.stderr.read()
                if stderr_output:
                    logger.error(f"🤝📖❗ Server stderr: {stderr_output}")
            raise HandshakeError(
                f"Failed to read handshake response. Server stderr: {stderr_output}"
            ) from e
            
        finally:
            logger.debug("🤝📖🔒 Cleaning up stderr reader task")
            stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stderr_task

    async def _create_grpc_channel(self) -> None:
        """
        Creates and initializes a secure gRPC channel using the server certificate
        (obtained during handshake) and the client's mTLS credentials.
        """
        try:
            if not self._server_cert:
                raise HandshakeError("Server certificate missing from handshake.")

            # Determine proper endpoint format.
            if isinstance(self._transport, UnixSocketTransport):
                endpoint = f"unix://{self._transport.endpoint}"
            else:
                endpoint = self._transport.endpoint

            logger.debug(f"🚢 Creating gRPC channel to endpoint: {endpoint}")

            if not self.client_cert or not self.client_key_pem:
                raise HandshakeError("Client certificate or key missing for TLS channel.")

            # If the server certificate does not include the PEM header/footer,
            # reconstruct the full PEM certificate.
            if not self._server_cert.startswith("-----BEGIN CERTIFICATE-----"):
                cert_lines = [self._server_cert[i:i+64] for i in range(0, len(self._server_cert), 64)]
                full_pem = "-----BEGIN CERTIFICATE-----\n" + \
                   "\n".join(cert_lines) + \
                   "\n-----END CERTIFICATE-----"
                logger.debug("🔐 Reconstructed full PEM certificate for server.")
            else:
                logger.debug("🔑 The _server_cert did not begin with x509 header.")
                full_pem = self._server_cert

            credentials = grpc.ssl_channel_credentials(
                root_certificates=full_pem.encode(),
                private_key=self.client_key_pem.encode(),
                certificate_chain=self.client_cert.encode(),
            )

            logger.debug("**************************************************************")
            logger.debug("**************************************************************")
            logger.debug(f"client_key_pem: {self.client_key_pem.encode()}")
            logger.debug(f"   client_cert: {self.client_cert.encode()}")
            logger.debug(f"      full_pem: {full_pem.encode()}")
            logger.debug("**************************************************************")
            logger.debug("✅ gRPC SSL channel credentials successfully created.")
            logger.debug("**************************************************************")

            self._channel = grpc.aio.secure_channel(
                endpoint,
                credentials,
                options=[
                    ('grpc.ssl_target_name_override', 'localhost'),
                    ('grpc.max_receive_message_length', 16 * 1024 * 1024),
                    ('grpc.max_send_message_length', 16 * 1024 * 1024),
                ]
            )
            logger.debug("✅ gRPC channel successfully created.")
        except Exception as e:
            logger.error(f"❌ Failed to create gRPC channel: {e}")
            raise HandshakeError(f"Failed to create gRPC channel: {e}") from e

    async def close(self) -> None:
        """
        Gracefully shuts down the RPCPluginClient by:
          - Closing the gRPC channel.
          - Terminating the server subprocess.
          - Closing the transport connection.
        """
        logger.info("🔄 Stopping RPC plugin client...")
        if self._channel:
            try:
                await self._channel.close()
                logger.info("🔄 gRPC channel closed.")
            except Exception as e:
                logger.warning(f"⚠️ Error closing gRPC channel: {e}")
        if self._process and isinstance(self._process, subprocess.Popen):
            try:
                self._process.terminate()
                await asyncio.get_event_loop().run_in_executor(None, self._process.wait)
                logger.info("🔄 Server process terminated.")
            except Exception as e:
                logger.error(f"❌ Error stopping server process: {e}")
        if self._transport:
            try:
                await self._transport.close()
                logger.info("🔄 Transport closed successfully.")
            except Exception as e:
                logger.warning(f"⚠️ Error closing transport: {e}")
        # Reset internal state.
        self._process = None
        self._channel = None
        self._transport = None

    async def start(self) -> None:
        """
        Starts the RPC plugin client by:
          - Generating or loading client mTLS certificates if auto mTLS is enabled.
          - Launching the server subprocess.
          - Performing the handshake.
          - Creating the secure gRPC channel.
        """
        logger.debug("🔄 Starting RPC plugin client...")
        if rpcplugin_config.get("PLUGIN_AUTO_MTLS"):
            logger.debug("🔐 Auto mTLS enabled; preparing client certificates...")
            if not (rpcplugin_config.get("PLUGIN_CLIENT_CERT") and rpcplugin_config.get("PLUGIN_CLIENT_KEY")):
                # Generate a new self-signed certificate using the Certificate API.
                client_cert_obj = Certificate(
                    generate_keypair=True,
                    key_type="ecdsa",  # or "rsa" as desired.
                    common_name="client.example.com"
                )
                self.client_cert = client_cert_obj.cert
                self.client_key_pem = client_cert_obj.key
                logger.debug("🔐 Generated new self-signed client certificate.")
            else:
                self.client_cert = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
                self.client_key_pem = rpcplugin_config.get("PLUGIN_CLIENT_KEY")
                logger.debug("🔐 Loaded provided client certificate.")
        else:
            logger.info("🔐 mTLS disabled; operating in insecure mode.")

        # Prepare environment for launching the server process.
        env = os.environ.copy()
        if self.config and 'env' in self.config:
            env.update(self.config['env'])
        env["PLUGIN_CLIENT_CERT"] = self.client_cert or ""
        
        # Launch the server subprocess.
        if not self._process:
            try:
                self._process = subprocess.Popen(
                    self.command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                logger.info("📡 Server process started.")
            except Exception as e:
                logger.error(f"❌ Failed to start server process: {e}")
                raise

        # Optionally, relay stderr.
        self._relay_stderr()

        # Perform the handshake with the server.
        await self._perform_handshake()

        # Create the gRPC channel using the handshake data.
        await self._create_grpc_channel()

        logger.info("✅ RPC plugin client started successfully.")

    async def connect(self) -> None:
        """
        Ensures connection is established. The handshake should already be
        completed during start().
        """
        logger.debug("🔄 Connecting RPC plugin client...")
        try:
            if not self._process:
                raise RuntimeError("❌ Server process is not running. Did you call start()?")

            # Only create channel if needed
            if not self._channel:
                logger.debug("🔌 No gRPC channel exists; creating one...")
                await self._create_grpc_channel()
            else:
                logger.debug("🔌 Using existing gRPC channel")

            # Optional: verify channel is healthy
            try:
                await self._channel.channel_ready()
                logger.debug("🔌 gRPC channel is ready")
            except grpc.RpcError as e:
                logger.error(f"❌ Channel health check failed: {e}")
                raise

            logger.info("✅ RPC plugin client connected successfully.")

        except Exception as e:
            logger.error(f"❌ Error connecting RPC plugin client: {e}")
            await self.close()
            raise

