#!/usr/bin/env python3
import grpc
import logging
import os
from proto import kv_pb2, kv_pb2_grpc

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def main():
    try:
        # Get and validate certs
        client_cert = os.getenv('PLUGIN_CLIENT_CERT')
        client_key = os.getenv('PLUGIN_CLIENT_KEY') 
        server_cert = os.getenv('PLUGIN_SERVER_CERT')
        
        if not all([client_cert, client_key, server_cert]):
            missing = [k for k, v in {
                'PLUGIN_CLIENT_CERT': client_cert,
                'PLUGIN_CLIENT_KEY': client_key,
                'PLUGIN_SERVER_CERT': server_cert
            }.items() if not v]
            raise ValueError(f"Missing env vars: {missing}")

        logger.debug("Client cert length: %d", len(client_cert))
        logger.debug("Client key length: %d", len(client_key))
        logger.debug("Server cert length: %d", len(server_cert))

        # Create channel creds with debug
        try:
            creds = grpc.ssl_channel_credentials(
                root_certificates=server_cert.encode(),
                private_key=client_key.encode(), 
                certificate_chain=client_cert.encode()
            )
            logger.debug("Created SSL credentials")
        except Exception as e:
            logger.error("Failed creating credentials: %s", e)
            raise

        # Create channel with debug
        try:
            channel = grpc.secure_channel(
                'localhost:50051',
                creds,
                options=[
                    ('grpc.ssl_target_name_override', 'localhost'),
                    ('grpc.min_reconnect_backoff_ms', 100),
                    ('grpc.max_reconnect_backoff_ms', 1000)
                ]
            )
            logger.debug("Created secure channel")
        except Exception as e:
            logger.error("Failed creating channel: %s", e)
            raise

        # Make request with timeout
        try:
            stub = kv_pb2_grpc.KVStub(channel)
            response = stub.Get(
                kv_pb2.GetRequest(key="test"),
                timeout=5
            )
            logger.info("Response: %s", response.value)
        except grpc.RpcError as e:
            logger.error("RPC Error: %s", e.details())
            logger.error("Debug error: %s", e.debug_error_string())
            raise
        finally:
            channel.close()

    except Exception as e:
        logger.error("Fatal error", exc_info=True)

if __name__ == "__main__":
    main()
