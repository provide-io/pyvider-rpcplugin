import asyncio
import grpc
import logging
import os
import signal
from pathlib import Path

from pyvider.rpcplugin.client import SecureRpcClient, ClientConfig
from pyvider.rpcplugin.config import RpcPluginConfig, LogLevel, set_config_defaults_for_client
from pyvider.rpcplugin.handshake import HandshakeConfig
from pyvider.rpcplugin.broker import GRPCBroker # For serving the ExternalMockService via broker

# Import generated protobuf code for ServiceA (to call into the plugin)
from . import service_a_pb2, service_a_pb2_grpc

# Import generated protobuf code for ExternalMockService (to implement and serve it)
from . import external_mock_service_pb2, external_mock_service_pb2_grpc

from .fault_injector import inject_fault_async as inject_external_fault_async # Can use fault injector here too

logger = logging.getLogger(__name__)

# --- Configuration for client connecting to the plugin ---
# These should align with how plugin_main.py's server is configured (certs, etc.)
# This CA should be the one that signed the plugin's server certificate (plugin_ca.pem in ex13)
CLIENT_CA_FOR_PLUGIN_SERVER_CERT = Path(__file__).parent / ".plugin_certs" / "plugin_ca.pem"
# This client cert/key must be signed by CLIENT_CA_CERT_FILE from plugin_main.py (plugin_ca.pem)
CLIENT_CERT_FILE = Path(__file__).parent / ".client_app_certs" / "client_app.pem"
CLIENT_KEY_FILE = Path(__file__).parent / ".client_app_certs" / "client_app.key"
CLIENT_APP_CA_CERT_FILE = Path(__file__).parent / ".client_app_certs" / "client_app_ca.pem" # CA for this client app

def ensure_client_app_certs():
    """Generates certs for client_app.py, signed by the plugin's CA if mTLS for plugin is used."""
    CLIENT_APP_CERT_DIR = Path(__file__).parent / ".client_app_certs"
    CLIENT_APP_CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Create a CA for the client_app itself (e.g., if it were to serve mTLS services)
    # For this example, this CA is mostly for completeness or if other services connected to client_app.
    if not (CLIENT_APP_CA_CERT_FILE.exists()):
        from pyvider.rpcplugin.crypto import generate_keypair as gen_kp, generate_x509_certificate as gen_x509
        client_app_ca_keypair = gen_kp("rsa")
        client_app_ca_cert_obj = gen_x509(
            private_key=client_app_ca_keypair.private_key, public_key=client_app_ca_keypair.public_key,
            common_name="Example13 ClientApp CA", is_ca=True, days_valid=30
        )
        with open(CLIENT_APP_CA_CERT_FILE, "wb") as f: f.write(client_app_ca_cert_obj.public_bytes_pem)
        # Key not saved for this example CA, not strictly needed unless signing other certs here.
        logger.info(f"ClientApp CA certificate generated: {CLIENT_APP_CA_CERT_FILE}")


    if CLIENT_CERT_FILE.exists() and CLIENT_KEY_FILE.exists():
        logger.info("ClientApp's own client certificate for plugin connection already exists.")
        return

    logger.info("Generating ClientApp's client certificate for connecting to the plugin...")

    # This client certificate needs to be signed by the CA the plugin server trusts.
    # That CA is plugin_ca.pem from plugin_main.py's .plugin_certs directory.
    plugin_ca_cert_path = Path(__file__).parent / ".plugin_certs" / "plugin_ca.pem"
    plugin_ca_key_path = Path(__file__).parent / ".plugin_certs" / "plugin_ca.key" # Need key to sign
                                                                                    # This is a simplification; typically CA key is highly protected.
                                                                                    # For example, certs.py in Ex12 shows this.
                                                                                    # Here, we assume plugin_ca.key is available if we need to generate it.
                                                                                    # If plugin_ca.key isn't available, this step must be done manually
                                                                                    # or by a proper CA infrastructure.

    if not plugin_ca_cert_path.exists(): # Basic check
        logger.error(f"Plugin's CA certificate ({plugin_ca_cert_path}) not found. "
                     "Run plugin_main.py first to generate its certs, or place the CA cert there.")
        logger.error("Cannot generate a client certificate for client_app.py without the plugin's CA.")
        # As a fallback, if we can't sign, we won't create client certs. Connection will fail if mTLS.
        return


    # For this example, we'll assume that if plugin_ca.pem exists, we might not have its key.
    # A REAL setup: Client gets its cert from a CA.
    # This example is tricky: plugin_main.py creates its own CA. client_app.py needs a cert from it.
    # For now, let's log a warning and proceed. If mTLS is on for plugin, connection will fail without valid client cert.
    # The user would need to manually create a client cert signed by .plugin_certs/plugin_ca.pem
    # and place them at CLIENT_CERT_FILE and CLIENT_KEY_FILE.
    logger.warning("Automatic generation of client_app.pem signed by plugin_ca.pem is not fully implemented here "
                   "due to CA key access.")
    logger.warning(f"Please ensure {CLIENT_CERT_FILE} and {CLIENT_KEY_FILE} are valid and signed by "
                   f"{plugin_ca_cert_path.name} if the plugin is in mTLS mode.")
    logger.warning("If these files are missing, mTLS connection to plugin will likely fail.")
    # To make this runnable: create placeholder/dummy files if they don't exist,
    # knowing they might not work for mTLS.
    if not CLIENT_CERT_FILE.exists():
        CLIENT_CERT_FILE.touch()
        logger.info(f"Placeholder {CLIENT_CERT_FILE.name} created. IT IS LIKELY NOT VALID FOR mTLS.")
    if not CLIENT_KEY_FILE.exists():
        CLIENT_KEY_FILE.touch()
        logger.info(f"Placeholder {CLIENT_KEY_FILE.name} created. IT IS LIKELY NOT VALID FOR mTLS.")


# --- ExternalMockService Implementation (served by this client_app via broker) ---
class ExternalMockServiceImpl(external_mock_service_pb2_grpc.ExternalMockServiceServicer):
    async def ProcessExternalData(self, request: external_mock_service_pb2.ExternalRequest, context: grpc.aio.ServicerContext) -> external_mock_service_pb2.ExternalResponse:
        peer = context.peer() # Should show it's coming from the plugin's broker
        logger.info(f"[ExternalMockService] Received ProcessExternalData from {peer} with: '{request.data_from_A_via_broker}'")

        await inject_external_fault_async("ExternalService_Processing") # Optional fault point

        processed_data = f"ExternalMockService processed ({request.data_from_A_via_broker})"
        logger.info(f"[ExternalMockService] Sending response: {processed_data}")
        return external_mock_service_pb2.ExternalResponse(processed_external_data=processed_data)

    async def StreamExternalData(self, request_iterator: grpc.aio. molteplicità[external_mock_service_pb2.ExternalRequest], context: grpc.aio.ServicerContext):
        logger.info("[ExternalMockService] StreamExternalData called.")
        async for request in request_iterator:
            logger.info(f"[ExternalMockService] Stream request: {request.data_from_A_via_broker}")
            await inject_external_fault_async("ExternalService_Processing_Stream")
            yield external_mock_service_pb2.ExternalResponse(
                processed_external_data=f"Streamed ack: {request.data_from_A_via_broker}"
            )
        logger.info("[ExternalMockService] StreamExternalData finished.")


async def run_grpc_client_calls(plugin_client: SecureRpcClient):
    """Makes gRPC calls to ServiceA in the plugin."""
    if not plugin_client.channel or not plugin_client.stubs:
        logger.error("Plugin client channel or stubs not initialized.")
        return

    # Assuming ServiceA is the primary service exposed by the plugin that client_app interacts with.
    # The plugin_client auto-connects and sets up stubs based on its config.
    # We need to tell it which service/stub we want if it's not default or only one.
    # For this example, let's assume plugin_client is configured to connect to the plugin
    # and can provide a stub for ServiceA.
    # This part depends on how SecureRpcClient is intended to be used for multiple services.
    # Typically, you'd get a specific stub.

    # Let's assume the SecureRpcClient is configured to connect to the plugin and has a 'get_stub' method
    # or the stub for the primary service is available directly.
    # For now, we'll create a new stub using the plugin_client's channel.
    # This assumes plugin_client.channel is the channel to the *plugin's main server*.

    try:
        service_a_stub = service_a_pb2_grpc.ServiceAStub(plugin_client.channel) # type: ignore
        logger.info("Successfully created ServiceAStub using plugin client's channel.")
    except Exception as e:
        logger.error(f"Failed to create ServiceAStub from plugin client's channel: {e}")
        return

    test_cases = [
        ("Test Data 1 (A only)", False, False),
        ("Test Data 2 (A -> B)", True, False),
        ("Test Data 3 (A -> Ext)", False, True),
        ("Test Data 4 (A -> B -> C, A -> Ext)", True, True),
    ]

    for i, (input_data, call_b, call_ext) in enumerate(test_cases):
        logger.info(f"\n--- Client App: Test Case {i+1} ---")
        logger.info(f"Input: '{input_data}', Call B: {call_b}, Call External: {call_ext}")
        try:
            request = service_a_pb2.RequestA(
                input_data=input_data,
                trigger_internal_call_to_b=call_b,
                trigger_broker_call_to_external=call_ext
            )
            response = await service_a_stub.ProcessDataA(request, timeout=15.0) # Increased timeout for full chain
            logger.info(f"[ClientApp] Response from ServiceA:")
            logger.info(f"  Processed A: {response.processed_data_A}")
            logger.info(f"  Data from B: {response.data_from_B}")
            logger.info(f"  Data from Ext: {response.data_from_external}")

        except grpc.aio.AioRpcError as e:
            logger.error(f"[ClientApp] Error calling ServiceA for '{input_data}': {e.details()} (Code: {e.code()})")
        except Exception as e:
            logger.error(f"[ClientApp] Generic error for '{input_data}': {e}")

        await asyncio.sleep(1) # Pause between test cases


async def main():
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    logger.info("Starting Example 13: Client Application")

    ensure_client_app_certs() # Generates client_app_ca.pem and placeholder client certs

    # --- Configure and start SecureRpcClient to connect to the plugin ---
    # These env vars would typically be set by the system launching this client app
    # and the plugin. They must match how the plugin is run.
    # For this example, we hardcode them to match plugin_main.py's defaults.

    # This configures the client *that connects to the plugin*.
    # It needs to know the plugin's address, handshake details, and certs for mTLS.
    # The `pyvider.rpcplugin.client.ClientConfig` and `SecureRpcClient` are used here.

    # Set environment variables for ClientConfig (normally done by orchestrator)
    os.environ["PLUGIN_HOST_ADDRESS"] = "localhost:50052" # Matches plugin_main.py
    os.environ["PLUGIN_SECURE_MODE"] = "mtls"
    # For mTLS, client_app needs to trust the plugin's server cert (via its CA)
    os.environ["PLUGIN_SERVER_CA_CERT_PATH"] = str(CLIENT_CA_FOR_PLUGIN_SERVER_CERT.resolve())
    # And provide its own client cert and key, signed by the CA the plugin trusts for clients
    os.environ["PLUGIN_CLIENT_CERT_PATH"] = str(CLIENT_CERT_FILE.resolve())
    os.environ["PLUGIN_CLIENT_KEY_PATH"] = str(CLIENT_KEY_FILE.resolve())

    os.environ["HANDSHAKE_MAGIC_COOKIE_KEY"] = "EXAMPLE13_MAGIC_COOKIE" # Must match plugin
    os.environ["HANDSHAKE_MAGIC_COOKIE_VALUE"] = "multi-service-cookie- flavorful-ant-jazz"
    os.environ["PLUGIN_LOG_LEVEL"] = "DEBUG"

    # This is for the client component of client_app.py
    client_rpc_config = RpcPluginConfig()
    client_handshake_cfg = HandshakeConfig.from_rpc_config(client_rpc_config)
    # The ClientConfig for SecureRpcClient can also be derived from RpcPluginConfig
    # or instantiated directly with necessary parameters.
    # SecureRpcClient typically expects a command to run a plugin process.
    # Here, the "plugin" is already running (plugin_main.py).
    # We need a way to use SecureRpcClient to *just connect* to an existing gRPC service,
    # not to manage a subprocess.
    #
    # The existing `SecureRpcClient` is designed to LAUNCH a plugin.
    # For connecting to an ALREADY RUNNING plugin (like in this example scenario),
    # we might need a simpler gRPC channel setup or adapt SecureRpcClient.
    # For now, let's manually set up the channel and stub to the plugin.

    logger.info(f"Attempting to connect to plugin at {os.environ['PLUGIN_HOST_ADDRESS']}")
    plugin_channel = None
    try:
        if os.environ["PLUGIN_SECURE_MODE"] == "mtls":
            if not CLIENT_CERT_FILE.exists() or not CLIENT_KEY_FILE.exists() or \
               not CLIENT_CA_FOR_PLUGIN_SERVER_CERT.exists() or \
               os.path.getsize(CLIENT_CERT_FILE) == 0: # Check if placeholder
                logger.error("mTLS mode specified, but client certificates are missing, invalid, or placeholders.")
                logger.error(f"Ensure {CLIENT_CERT_FILE}, {CLIENT_KEY_FILE} are valid and signed by the plugin's CA,")
                logger.error(f"and {CLIENT_CA_FOR_PLUGIN_SERVER_CERT} is the plugin's CA cert.")
                raise FileNotFoundError("Client certs for mTLS missing or invalid.")

            with open(CLIENT_KEY_FILE, 'rb') as f: key_pem = f.read()
            with open(CLIENT_CERT_FILE, 'rb') as f: cert_pem = f.read()
            with open(CLIENT_CA_FOR_PLUGIN_SERVER_CERT, 'rb') as f: ca_pem = f.read()
            creds = grpc.ssl_channel_credentials(ca_pem, key_pem, cert_pem)
        elif os.environ["PLUGIN_SECURE_MODE"] == "tls":
            with open(CLIENT_CA_FOR_PLUGIN_SERVER_CERT, 'rb') as f: ca_pem = f.read() # Client trusts plugin's CA
            creds = grpc.ssl_channel_credentials(ca_pem)
        else: # insecure
            creds = None # Handled by insecure_channel

        if creds:
            plugin_channel = grpc.aio.secure_channel(os.environ["PLUGIN_HOST_ADDRESS"], creds)
        else:
            plugin_channel = grpc.aio.insecure_channel(os.environ["PLUGIN_HOST_ADDRESS"])

        logger.info("Waiting for plugin channel to be ready...")
        await asyncio.wait_for(plugin_channel.channel_ready(), timeout=10)
        logger.info("Channel to plugin is ready.")

        # Mock a SecureRpcClient instance for run_grpc_client_calls
        class MockPluginClient:
            def __init__(self, ch):
                self.channel = ch
                self.stubs = {} # Not used by run_grpc_client_calls current impl
                self.process = None # Not used
            async def close(self):
                if self.channel: await self.channel.close()

        mock_plugin_client_to_service_a = MockPluginClient(plugin_channel)

    except Exception as e:
        logger.error(f"Failed to connect to plugin: {e}")
        if plugin_channel: await plugin_channel.close()
        return


    # --- Configure and start GRPCBroker to serve ExternalMockService ---
    # This client_app.py will SERVE the ExternalMockService, which the plugin will call INTO.
    broker_server = None
    if os.getenv("GRPC_BROKER_ENABLE", "false").lower() == "true":
        logger.info("GRPCBroker is enabled by plugin. Client_app will serve ExternalMockService via broker.")

        # The broker component within client_app.py needs its own RpcPluginConfig context
        # to know how to communicate with the broker in the plugin.
        # This is a bit meta: client_app uses rpcplugin libs to talk to plugin,
        # and also uses rpcplugin libs (broker) to BE CALLED BY plugin.

        # For the broker connection FROM client_app TO plugin_broker_service:
        # This requires client_app to act as a gRPC client to the plugin's internal GRPCBroker service.
        # This connection needs to be established using the main plugin's address and security.
        # RpcPluginConfig should already be set up for this from above.

        broker = GRPCBroker(rpc_config=client_rpc_config, handshake_config=client_handshake_cfg) # Uses same config as client part

        # Add ExternalMockService to the broker's internal server
        # The subchannel_name must match what ServiceAImpl uses in `open_subchannel`.
        subchannel_name_for_external = "ExternalMockServiceChannel"

        # The broker itself will start a gRPC server if it's on the "serving" side.
        # Here, client_app is "serving" ExternalMockService TO the plugin via the broker.
        # The GRPCBroker in client_app needs to connect to the GRPCBroker in plugin_main.
        # `broker.start_serving_subchannel` does this.
        # It makes client_app's broker connect to plugin_main's broker and announce it can serve this.
        try:
            # This part needs to be async if start_serving_subchannel is async
            # Current rpcplugin broker.start_serving_subchannel might be sync.
            # Let's assume it can be wrapped or is async-compatible.
            # For now, let's run it in an executor if it's blocking, or ensure it's async.
            # The method itself sets up the server and then returns.
            # The actual serving happens in background tasks within the broker.

            logger.info(f"Starting to serve ExternalMockService on broker subchannel '{subchannel_name_for_external}'...")
            # This is where client_app tells the plugin's broker "I can handle requests for ExternalMockService"
            # The broker in client_app connects to the broker in plugin_main.
            # This is a client-side use of the broker to expose a service.

            # The `GRPCBroker.start_serving_subchannel` will create a server for ExternalMockService
            # and manage the connection to the plugin's broker service.
            # The credentials for this internal server within the broker can be auto-generated or specified.
            # For mTLS between client_app's broker server and plugin's broker client, certs are needed.
            # Broker handles this internally using plugin's secure_mode and cert paths if needed.
            # Let's use specific certs for the service client_app exposes, if possible.
            # For this example, let's assume broker uses self-signed for its internal server or plugin's certs.

            # The broker needs to be "started" or "connected" first.
            # This typically happens as part of SecureRpcClient or PluginServer initialization.
            # Since we are using GRPCBroker standalone here on the client_app side:
            if not await broker.connect_to_plugin_broker_service(plugin_channel): # Pass the main channel to plugin
                 logger.error("Client App Broker could not connect to Plugin's Broker Service. External calls will fail.")
            else:
                logger.info("Client App Broker connected to Plugin's Broker Service.")
                broker.start_serving_subchannel(
                    servicer_instance=ExternalMockServiceImpl(),
                    add_servicer_func=external_mock_service_pb2_grpc.add_ExternalMockServiceServicer_to_server,
                    subchannel_name=subchannel_name_for_external,
                    # server_credentials=grpc.ssl_server_credentials(...) # Optionally provide server certs for this brokered service
                )
                logger.info(f"ExternalMockService is now being served by client_app via broker on subchannel '{subchannel_name_for_external}'.")

        except Exception as e:
            logger.error(f"Failed to set up or serve ExternalMockService via broker: {e}")
            # Continue without broker if setup fails, external calls from plugin will fail.
    else:
        broker = None
        logger.info("GRPCBroker is not enabled by plugin. Client_app will not serve ExternalMockService.")


    # Run the main client logic (calling ServiceA)
    if mock_plugin_client_to_service_a:
        client_task = asyncio.create_task(run_grpc_client_calls(mock_plugin_client_to_service_a))
    else:
        client_task = None


    # Keep client_app running to serve ExternalMockService if broker is active
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    def _sig_handler(*args):
        logger.info("ClientApp shutdown signal received.")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _sig_handler)

    logger.info("ClientApp is running. Press Ctrl+C to stop.")
    await stop_event.wait()

    logger.info("ClientApp shutting down...")
    if client_task:
        client_task.cancel()
        try:
            await client_task
        except asyncio.CancelledError:
            logger.info("Client gRPC calls task cancelled.")

    if broker:
        logger.info("Stopping broker services in client_app...")
        await broker.stop() # Ensure broker cleans up its connections and server
        logger.info("Broker services in client_app stopped.")

    if hasattr(mock_plugin_client_to_service_a, 'close'):
        await mock_plugin_client_to_service_a.close() # type: ignore
        logger.info("Connection to plugin closed.")

    logger.info("ClientApplication has shut down.")


if __name__ == "__main__":
    try:
        from . import service_a_pb2, service_a_pb2_grpc, external_mock_service_pb2, external_mock_service_pb2_grpc # noqa
    except ImportError as e:
        logger.critical(f"Failed to import protobuf generated files: {e}. Make sure to run:"
              " python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. *.proto"
              " in the examples/example13_multi_service_fault_injection directory.")
        exit(1)
    asyncio.run(main())
