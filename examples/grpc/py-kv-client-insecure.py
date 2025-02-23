#!/usr/bin/env python3

import os
import socket

import grpc
from proto import kv_pb2, kv_pb2_grpc

from pyvider.rpcplugin.logger import logger


def test_socket_connection(sock_path: str) -> bool:
    """Test raw socket connection"""
    try:
        logger.debug(f"Testing raw socket connection to: {sock_path}")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(sock_path)
        logger.debug("Raw socket connection successful")
        return True
    except Exception as e:
        logger.error(f"Raw socket connection failed: {e}")
        return False
    finally:
        sock.close()

def get_channel(endpoint: str) -> grpc.Channel:
    """Create and verify gRPC channel connection"""
    # Strip unix: prefix if present
    sock_path = endpoint.replace('unix:', '', 1)
    
    # Test raw socket first
    if not test_socket_connection(sock_path):
        raise RuntimeError(f"Socket {sock_path} is not accessible")

    logger.debug(f"Creating gRPC channel to endpoint: {endpoint}")
    
    # Basic channel options
    options = [
        ('grpc.use_local_subchannel_pool', 1),
        ('grpc.enable_http_proxy', 0),
        ('grpc.max_receive_message_length', 16 * 1024 * 1024),
        ('grpc.max_send_message_length', 16 * 1024 * 1024)
    ]

    for opt, val in options:
        logger.debug(f"Channel option: {opt}={val}")

    try:
        channel = grpc.insecure_channel(endpoint, options=options)
        logger.debug("Channel created, waiting for ready state...")

        # Wait for channel ready
        ready_future = grpc.channel_ready_future(channel)
        ready_future.result(timeout=5)
        
        logger.debug("Channel is ready")
        return channel

    except grpc.FutureTimeoutError:
        logger.error("Timeout waiting for channel to be ready")
        if channel:
            channel.close()
        raise
    except Exception as e:
        logger.error(f"Failed to create channel: {e}")
        if channel:
            channel.close()
        raise

def test_operations(stub: kv_pb2_grpc.KVStub):
    """Test basic KV operations with detailed logging"""
    test_key = "test"
    test_value = b"test_value"

    try:
        # Test Put
        logger.debug(f"Attempting Put operation - Key: {test_key}, Value length: {len(test_value)}")
        stub.Put(kv_pb2.PutRequest(key=test_key, value=test_value))
        logger.info("Put operation successful")

        # Test Get
        logger.debug(f"Attempting Get operation - Key: {test_key}")
        response = stub.Get(kv_pb2.GetRequest(key=test_key))
        
        if not response:
            raise RuntimeError("Get operation returned None")
            
        logger.debug(f"Get response received - Value length: {len(response.value)}")
        
        if response.value != test_value:
            raise ValueError(f"Value mismatch - Got length: {len(response.value)}, Expected length: {len(test_value)}")
        
        logger.info("Get operation successful - values match")
        return True

    except grpc.RpcError as e:
        logger.error("RPC operation failed:")
        logger.error(f"  Status code: {e.code()}")
        logger.error(f"  Details: {e.details()}")
        raise RuntimeError(f"RPC failed: {e.code()} - {e.details()}")
    except Exception as e:
        logger.error(f"Operation error: {str(e)}")
        raise

def main():
    logger.debug("Starting KV client test")
    
    try:
        # Get and validate endpoint
        endpoint = os.getenv("PLUGIN_SERVER_ENDPOINT")
        if not endpoint:
            raise RuntimeError("PLUGIN_SERVER_ENDPOINT environment variable not set")
        
        logger.debug(f"Using server endpoint: {endpoint}")

        # Ensure unix: prefix
        if not endpoint.startswith('unix:'):
            endpoint = f'unix:{endpoint}'
            logger.debug(f"Added unix: prefix - Final endpoint: {endpoint}")

        # Create channel
        logger.debug("Establishing gRPC channel...")
        channel = None
        try:
            channel = get_channel(endpoint)
            logger.debug("Creating KV stub...")
            stub = kv_pb2_grpc.KVStub(channel)
            
            # Run tests
            logger.debug("Starting KV operations test...")
            test_operations(stub)
            logger.info("All operations completed successfully")
            
        finally:
            if channel:
                logger.debug("Closing gRPC channel...")
                channel.close()

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
