import asyncio
import grpc
import logging
import time
from pathlib import Path
import os
from typing import Optional # Added Optional import

# Import generated protobuf code
from . import service_pb2, service_pb2_grpc

# Import certificate paths
from .certs import (
    get_ca_cert_pem_path,
    get_client_cert_pem_path,
    get_client_key_pem_path,
    BASE_CERT_DIR, # For checking if certs exist
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")

# Global channel and stub to allow for re-creation
channel: Optional[grpc.aio.Channel] = None
stub: Optional[service_pb2_grpc.GreeterStub] = None

CURRENT_CA_VERSION = 1
CURRENT_CLIENT_CERT_VERSION = 1

def get_current_ca_path() -> Path:
    return get_ca_cert_pem_path(CURRENT_CA_VERSION)

def get_current_client_cert_path() -> Path:
    return get_client_cert_pem_path(CURRENT_CLIENT_CERT_VERSION)

def get_current_client_key_path() -> Path:
    return get_client_key_pem_path(CURRENT_CLIENT_CERT_VERSION)


async def create_channel_and_stub(server_addr: str) -> bool:
    global channel, stub
    logger.info(f"Attempting to create channel with CA: {get_current_ca_path().name}, "
                f"Client Cert: {get_current_client_cert_path().name}")

    try:
        with open(get_current_client_key_path(), 'rb') as f:
            private_key = f.read()
        with open(get_current_client_cert_path(), 'rb') as f:
            certificate_chain = f.read()
        with open(get_current_ca_path(), 'rb') as f: # Trust CA for server verification
            root_certificates = f.read()
    except FileNotFoundError as e:
        logger.error(f"A certificate file was not found: {e}. Ensure certs.py has been run.")
        return False

    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain
    )

    if channel:
        await channel.close()

    # Add options to ensure the channel tries to connect and indicates readiness
    options = [
        ('grpc.enable_retries', 1),
        ('grpc.keepalive_time_ms', 10000), # Send keepalive every 10s
        ('grpc.keepalive_timeout_ms', 5000), # Timeout for keepalive response
        ('grpc.keepalive_permit_without_calls', True), # Allow keepalive without active calls
        ('grpc.http2.min_time_between_pings_ms', 10000),
        ('grpc.http2.max_pings_without_data', 0), # Allow pings even if there are no calls
    ]

    channel = grpc.aio.secure_channel(server_addr, credentials, options=options)
    stub = service_pb2_grpc.GreeterStub(channel)

    try:
        # Wait for channel to be ready, with a timeout
        await asyncio.wait_for(channel.channel_ready(), timeout=10.0)
        logger.info(f"Channel to {server_addr} is ready.")
        return True
    except asyncio.TimeoutError:
        logger.error(f"Timeout waiting for channel to {server_addr} to become ready with current certs.")
        await channel.close()
        channel = None
        stub = None
        return False
    except grpc.aio.AioRpcError as e:
        logger.error(f"gRPC error during channel creation or readiness check: {e.details()} (Code: {e.code()})")
        if channel: # Ensure channel is closed if it was created but didn't become ready
            await channel.close()
        channel = None
        stub = None
        return False


async def call_say_hello(name: str):
    if not stub:
        logger.error("Stub not available. Cannot call SayHello.")
        return
    try:
        logger.info(f"Calling SayHello with name: {name}...")
        response = await stub.SayHello(service_pb2.HelloRequest(name=name))
        logger.info(f"Greeter client received: '{response.message}'")
    except grpc.aio.AioRpcError as e:
        logger.error(f"Error calling SayHello: {e.details()} (Code: {e.code()})")
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            logger.error("Server seems unavailable. Connection might have been lost or server cert expired.")


async def trigger_server_cert_rotation():
    global CURRENT_CA_VERSION, stub
    if not stub:
        logger.error("Stub not available. Cannot call RotateCert.")
        return

    logger.info("Calling RotateCert RPC on server...")
    try:
        response: service_pb2.RotateCertReply = await stub.RotateCert(service_pb2.RotateCertRequest())
        logger.info(f"RotateCert response: {response.status_message}")

        # A simple check if CA might have changed. Real logic could be more robust.
        # For this example, if server is now v2, it means it's using CA v2.
        if "Server v2" in response.status_message and "CA v2" in response.status_message:
            if CURRENT_CA_VERSION == 1: # We were using CA v1
                logger.info("Server indicates it might be using a new CA (CA v2). Attempting to fetch new CA cert...")

                # Fetch new CA from server
                # Note: This GetNewCACert call might fail if the current channel (using old CA v1)
                # can no longer validate the server's new certificate (server_v2.pem signed by CA_v2).
                # This is a classic chicken-and-egg problem in CA rotation.
                # Solutions:
                # 1. Server temporarily serves its new cert signed by *both* old and new CAs (complex).
                # 2. Server exposes GetNewCACert over a less secure channel or signed by the old CA initially.
                # 3. Out-of-band CA distribution.
                # For this example, we assume GetNewCACert is somehow still accessible or the old CA is still trusted by the server for this specific RPC.
                # A more robust client might try to connect with the old CA, and if it fails with SSL handshake error,
                # then try to get the new CA (perhaps over an insecure channel or a dedicated endpoint).

                try:
                    logger.info("Calling GetNewCACert to fetch CA v2...")
                    ca_reply: service_pb2.GetNewCACertReply = await stub.GetNewCACert(service_pb2.GetNewCACertRequest())
                    if ca_reply.new_ca_cert_pem:
                        new_ca_pem_path = BASE_CERT_DIR / "ca_v2_from_server.pem"
                        with open(new_ca_pem_path, "w") as f:
                            f.write(ca_reply.new_ca_cert_pem)
                        logger.info(f"New CA certificate (v2) received and saved to {new_ca_pem_path.name}")

                        # Update client's CA to v2 for subsequent connections
                        # In a real app, you'd load this into your trust store.
                        # For this example, we'll just switch the file path.
                        # We assume ca_v2.pem was already generated by certs.py and matches this.
                        # Here, we'll just switch our CURRENT_CA_VERSION to 2, assuming certs.py created ca_v2.pem
                        if get_ca_cert_pem_path(2).exists():
                            CURRENT_CA_VERSION = 2
                            logger.info("Client will now use CA v2 for server trust.")

                            # Client might also need to rotate its own certificate if the server now only trusts CA v2
                            # For simplicity, we'll assume client_v1 is still trusted or we'd switch client cert version too.
                            # If server now ONLY trusts clients signed by CA v2, client would need client_v2.pem.
                            # Let's assume for now client_v1 is fine, or server accepts both.
                            # If we need client_v2:
                            # global CURRENT_CLIENT_CERT_VERSION
                            # CURRENT_CLIENT_CERT_VERSION = 2
                            # logger.info("Client will now use Client Cert v2.")

                            logger.info("Re-creating channel with new CA...")
                            if not await create_channel_and_stub(channel._target.decode()): # type: ignore
                                logger.error("Failed to re-create channel with new CA v2. Subsequent calls might fail.")
                                return
                            logger.info("Successfully re-created channel with CA v2.")
                        else:
                            logger.error("CA v2 (ca_v2.pem) not found locally. Cannot switch trust. Please run certs.py.")
                    else:
                        logger.warning("GetNewCACert did not return a CA certificate.")
                except grpc.aio.AioRpcError as e:
                    logger.error(f"Error calling GetNewCACert: {e.details()} (Code: {e.code()})")
                    logger.error("Could not fetch new CA. Client may not trust rotated server cert.")

            elif CURRENT_CA_VERSION == 2 and "Server v1" in response.status_message and "CA v1" in response.status_message:
                 logger.info("Server indicates it has rotated back to CA v1.")
                 CURRENT_CA_VERSION = 1
                 logger.info("Client will now use CA v1 for server trust.")
                 logger.info("Re-creating channel with CA v1...")
                 if not await create_channel_and_stub(channel._target.decode()): # type: ignore
                     logger.error("Failed to re-create channel with CA v1. Subsequent calls might fail.")
                     return
                 logger.info("Successfully re-created channel with CA v1.")

        elif "Server certificate rotated successfully" in response.status_message:
             logger.info("Server cert rotated, but CA for client validation seems unchanged based on message. Re-creating channel just in case.")
             # Even if CA didn't change, server cert did. Re-create channel to pick up new server cert.
             if not await create_channel_and_stub(channel._target.decode()): # type: ignore
                logger.error("Failed to re-create channel after server cert rotation (same CA).")
                return
             logger.info("Successfully re-created channel after server cert rotation (same CA).")


    except grpc.aio.AioRpcError as e:
        logger.error(f"Error calling RotateCert: {e.details()} (Code: {e.code()})")
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            logger.error("Server seems unavailable. Connection might have been lost before rotation command.")


async def main_client_logic(server_addr: str):
    global CURRENT_CA_VERSION, CURRENT_CLIENT_CERT_VERSION

    # Initial connection with v1 certs
    logger.info("--- Initial Connection (Client v1, CA v1) ---")
    if not await create_channel_and_stub(server_addr):
        logger.error("Initial channel creation failed. Exiting.")
        return

    await call_say_hello("Alice_v1_initial")
    await asyncio.sleep(1)

    # Simulate operations...
    logger.info("\n--- Simulating some operations before server cert expires or rotation ---")
    for i in range(2):
        await call_say_hello(f"Alice_v1_op_{i+1}")
        await asyncio.sleep(0.5)

    # Server's v1 cert is designed to expire in 1 day.
    # Client will continue to use it. If server rotates due to expiry, client calls will fail.
    # If we trigger rotation *before* expiry, it's a proactive rotation.

    logger.info("\n--- Triggering First Server Certificate Rotation (to Server v3, CA v1) ---")
    await trigger_server_cert_rotation() # Server should go to v3 (signed by CA v1)
    await asyncio.sleep(1) # Give server time to restart if it does

    logger.info("\n--- Testing connection after first rotation (should be Server v3, CA v1) ---")
    await call_say_hello("Bob_after_rotation1_to_v3")
    await asyncio.sleep(1)
    await call_say_hello("Charlie_after_rotation1_to_v3")

    logger.info("\n--- Triggering Second Server Certificate Rotation (to Server v2, CA v2) ---")
    await trigger_server_cert_rotation() # Server should go to v2 (signed by CA v2), client updates to CA v2
    await asyncio.sleep(1)

    logger.info("\n--- Testing connection after second rotation (should be Server v2, CA v2) ---")
    await call_say_hello("David_after_rotation2_to_v2_and_CA_v2")
    await asyncio.sleep(1)
    await call_say_hello("Eve_after_rotation2_to_v2_and_CA_v2")

    logger.info("\n--- Triggering Third Server Certificate Rotation (back to Server v1, CA v1) ---")
    await trigger_server_cert_rotation() # Server should go back to v1 (signed by CA v1), client updates to CA v1
    await asyncio.sleep(1)

    logger.info("\n--- Testing connection after third rotation (should be Server v1, CA v1) ---")
    await call_say_hello("Frank_after_rotation3_to_v1_and_CA_v1")

    # Simulate server's v1 cert expiring if it was short-lived
    logger.info("\n--- Simulating passage of time - server's original v1 cert might expire ---")
    logger.info("If server was still on v1 and it expired, the next call should fail or reflect a rotated cert if server auto-rotated.")
    logger.info("Our server_v1.pem was set to expire in 1 day by certs.py.")
    logger.info("If more than a day passed OR if server proactively rotated due to expiry monitoring, behavior will change.")
    logger.info("Let's wait a bit and try again. If server hasn't rotated from v1, this might fail if cert expired.")

    # This part is tricky because the server needs to be running long enough for its cert to expire
    # or it needs an internal mechanism to rotate *before* client makes the call.
    # The current server example rotates on RPC call or if its expiry check leads to manual restart with new certs.
    # For this client test, we assume rotation is primarily client-driven via RPC.
    # The "expiry" scenario is best tested by letting server run, its cert expires, then client tries to connect.

    await asyncio.sleep(2) # Short delay
    logger.info("\n--- Final check (state depends on previous rotations and potential expiry) ---")
    await call_say_hello("Grace_final_check")

    if channel:
        await channel.close()
    logger.info("Client operations complete.")


async def main():
    server_address = os.getenv("GRPC_SERVER_ADDRESS", "localhost:50051")

    # Check if certs exist
    if not (BASE_CERT_DIR.exists() and get_ca_cert_pem_path(1).exists()):
         logger.error(f"Initial certificates (e.g., {get_ca_cert_pem_path(1)}) not found in {BASE_CERT_DIR}."
                      " Please run `python examples/example12_mtls_cert_rotation/certs.py` first.")
         return

    await main_client_logic(server_address)

if __name__ == "__main__":
    try:
        from . import service_pb2, service_pb2_grpc # noqa
    except ImportError:
        logger.error("Failed to import protobuf generated files. Make sure to run:"
              " python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. service.proto"
              " in the examples/example12_mtls_cert_rotation directory.")
        exit(1)

    asyncio.run(main())
