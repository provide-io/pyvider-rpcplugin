#!/usr/bin/env python3
"""
server_chat.py - gRPC Chat Server with Real-Time Streaming

Usage:
    python server_chat.py

Key Features:
- Supports unary SendMessage RPC to broadcast a single message to all clients.
- Streams past message history via GetMessageHistory.
- Provides a bidirectional ChatStream so clients can both send and receive
  messages in real-time.

Example (Bidi streaming flow):
    1. Client connects to ChatStream()
    2. Server spawns a background task to read any incoming messages from client
       and broadcast them to all connected queues.
    3. Server yields from the client's personal queue so it receives all messages
       (both from itself and others).
"""

import asyncio
import logging

import grpc
from grpc.aio import server

import chat_pb2_grpc
from chat_service import ChatService


async def serve() -> None:
    """
    Asynchronous gRPC server startup
    """
    grpc_server = server()
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatService(), grpc_server)
    grpc_server.add_insecure_port("[::]:50051")

    await grpc_server.start()
    logging.info("🚀 Chat Server started on port 50051. Waiting for connections...")
    await grpc_server.wait_for_termination()


def main() -> None:
    """Entrypoint for the server script"""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        logging.info("❌ Server shutdown via KeyboardInterrupt.")


if __name__ == "__main__":
    main()
