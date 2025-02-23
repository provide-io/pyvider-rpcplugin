#!/usr/bin/env python3
"""
service.py - A comprehensive gRPC ChatService implementation (v1.0).

This module implements the server-side logic defined in chat.proto:
    service ChatService {
        // 1) Send a single message via unary RPC
        rpc SendMessage(SendMessageRequest) returns (SendMessageResponse);

        // 2) Fetch the entire chat history (unary)
        rpc GetMessageHistory(MessageHistoryRequest) returns (MessageHistoryResponse);

        // 3) Bidirectional streaming for real-time chat
        rpc ChatStream(stream ChatMessage) returns (stream ChatMessage);
    }

We maintain the entire chat history in an in-memory list (chat_history) and
a mapping of username -> asyncio.Queue for queued messages (client_queues).
Whenever a new message arrives, it is appended to chat_history and broadcast
to all connected clients by placing the new ChatMessage in each client's queue.

Additionally, we provide a "/history" command feature. If a client sends a
ChatMessage whose message is "/history", that triggers a server-side action
to push the entire historical chat back to that one user (rather than
broadcasting to everyone). This can be handy in real-time streams.

Features:
---------
1. SendMessage (Unary):
   - Receives a single message
   - Persists it to chat_history
   - Broadcasts it to all connected streaming clients
   - Returns a SendMessageResponse (success or error_message)

2. GetMessageHistory (Unary):
   - Returns the entire chat_history in a single MessageHistoryResponse.
   - This is not streaming. Instead, the entire list is returned at once.

3. ChatStream (Bidirectional streaming):
   - Each connected client uses an asyncio.Queue to receive broadcasted messages.
   - The server spawns a background consumer task that listens for messages from
     the request_iterator. For each inbound ChatMessage:
       a) If the user is not identified yet (first message sets user).
       b) Optionally, if message == "/history", then push the entire chat back
          to that user alone.
       c) Else, broadcast the message to all queues.
   - The main method yields messages from that user's personal queue so the user
     sees all new broadcasts (including from themselves).

Logging:
---------
We log at DEBUG level for detailed trace of activity:
    - When new messages arrive
    - When a user joins or leaves
    - If a user requests "/history"
    - On errors or cancellations

Usage:
---------
You typically do not run service.py directly. Instead, you import ChatService
into your server code, for example:

    from service import ChatService
    import grpc
    from grpc.aio import server

    async def serve():
        grpc_server = server()
        add_ChatServiceServicer_to_server(ChatService(), grpc_server)
        grpc_server.add_insecure_port("[::]:50051")
        await grpc_server.start()
        await grpc_server.wait_for_termination()

Implementation:
---------
Below is the ChatService class plus a small global store for chat_history
and client_queues.

DocTests (illustrative only):
---------
>>> # Typically, you'd test using an async test framework, e.g. pytest-asyncio.
>>> # Below is a contrived doctest that ensures code is importable.
>>> True
True
"""

import asyncio
import logging
import time
from collections.abc import AsyncIterator

# Protobuf-generated modules (from your compiled chat.proto)
import chat_pb2
import chat_pb2_grpc
from grpc.aio import ServicerContext

# ---------------------------------------------------------------------------
# Global In-Memory State (e.g. chat history, client queues)
# ---------------------------------------------------------------------------

# chat_history:
#   A list storing all ChatMessage objects that have been sent in the system.
#   The order of insertion is the chronological order (based on arrival).
chat_history: list[chat_pb2.ChatMessage] = []

# client_queues:
#   A mapping from username -> asyncio.Queue, where each queue will hold
#   ChatMessages that this user needs to receive. In a broadcast scenario,
#   each new ChatMessage is placed into every queue so that each user can
#   read it from the server's stream.
client_queues: dict[str, asyncio.Queue] = {}

# ---------------------------------------------------------------------------
# ChatService Implementation
# ---------------------------------------------------------------------------


class ChatService(chat_pb2_grpc.ChatServiceServicer):
    """
    ChatService implements the methods defined in chat.proto (v1.0).

    1) SendMessage (Unary)
    2) GetMessageHistory (Unary)
    3) ChatStream (Bidirectional streaming)

    Detailed logic is inline below.
    """

    def __init__(self) -> None:
        """
        Constructor for ChatService.
        We do not do much here besides optional logging to confirm initialization.
        """
        super().__init__()
        logging.debug("Initialized ChatService with empty in-memory storage.")

    # -----------------------------------------------------------------------
    # 1) SendMessage - unary
    # -----------------------------------------------------------------------
    async def SendMessage(
        self,
        request: chat_pb2.SendMessageRequest,
        context: ServicerContext
    ) -> chat_pb2.SendMessageResponse:
        """
        Receives a single message (unary call), appends to chat_history,
        and broadcasts to all streaming clients.

        :param request: SendMessageRequest object containing user & message
        :param context: ServicerContext from gRPC for metadata, cancellation, etc.
        :return: SendMessageResponse indicating success or error details.

        Steps:
        1) Construct a ChatMessage with timestamp = current time.
        2) Append the message to chat_history.
        3) Log the event and broadcast to all known client_queues.
        4) Return success = True if all is well.
        """
        timestamp = int(time.time())
        new_message = chat_pb2.ChatMessage(
            user=request.user,
            message=request.message,
            timestamp=timestamp
        )
        chat_history.append(new_message)

        # Log the newly received message for debugging
        logging.info(
            f"[SendMessage] Received unary message from {request.user}: "
            f"'{request.message}' (timestamp={timestamp})"
        )

        # Broadcast to every connected client's queue
        num_queues = len(client_queues)
        logging.debug(f"[SendMessage] Broadcasting to {num_queues} active client queue(s).")
        for user_id, queue in client_queues.items():
            await queue.put(new_message)
            logging.debug(f"[SendMessage] Enqueued new message for user '{user_id}'.")

        # Return a success response
        return chat_pb2.SendMessageResponse(
            success=True,
            error_message=""
        )

    # -----------------------------------------------------------------------
    # 2) GetMessageHistory - unary
    # -----------------------------------------------------------------------
    async def GetMessageHistory(
        self,
        request: chat_pb2.MessageHistoryRequest,
        context: ServicerContext
    ) -> chat_pb2.MessageHistoryResponse:
        """
        Returns all chat messages in a single shot via the MessageHistoryResponse.

        :param request: MessageHistoryRequest (usually empty).
        :param context: ServicerContext from gRPC (for cancellations, etc).
        :return: MessageHistoryResponse containing repeated ChatMessage.

        Steps:
        1) We simply wrap the global chat_history in a single response and return it.
        2) Logging is done to confirm the request was handled.
        """
        logging.debug("[GetMessageHistory] Request received. Building full history response.")

        # For clarity, we directly pass chat_history into the repeated messages field
        history_response = chat_pb2.MessageHistoryResponse(
            messages=chat_history
        )

        logging.debug(
            f"[GetMessageHistory] Returning {len(chat_history)} message(s) in the response."
        )
        return history_response

    # -----------------------------------------------------------------------
    # 3) ChatStream - bidirectional streaming
    # -----------------------------------------------------------------------
    async def ChatStream(
        self,
        request_iterator: AsyncIterator[chat_pb2.ChatMessage],
        context: ServicerContext
    ) -> AsyncIterator[chat_pb2.ChatMessage]:
        """
        Bidirectional streaming method that allows a client to both send
        and receive ChatMessage objects in real-time.

        The flow here is:
        1) We create a personal_queue (asyncio.Queue) for the connected client.
        2) We spawn a background task 'consume_incoming()' that reads from
           the client's inbound request stream (request_iterator).
           - On the first message, we set the user's name and broadcast "user joined".
           - If the user sends "/history", we push the entire chat history into
             the user's personal queue (but do not broadcast "/history").
           - Otherwise, we treat it as a new chat message, store it, and broadcast
             to all client_queues.
        3) Meanwhile, in the main ChatStream method, we yield messages from
           personal_queue back to the client so they see real-time updates.

        :param request_iterator: The stream of incoming ChatMessage objects
                                 from the client.
        :param context: gRPC ServicerContext
        :yield: ChatMessage objects, one by one, to the client.
        """
        logging.debug("[ChatStream] A client is connecting. Creating personal queue...")

        # Each client is identified by a user name, which we discover from the
        # first inbound ChatMessage (it might be the 'user' field).
        user: str | None = None
        personal_queue = asyncio.Queue()

        # -------------------------------------------------------------------
        # Helper method: consume_incoming()
        # -------------------------------------------------------------------
        async def consume_incoming() -> None:
            """
            Background task that reads inbound ChatMessages from the client
            and processes them. This includes:
            - Setting user on the first message
            - Handling "/history" if requested
            - Normal message broadcast
            - Cleanup if connection closes
            """
            nonlocal user
            try:
                async for incoming_msg in request_iterator:
                    if user is None:
                        # The first message identifies the user
                        user = incoming_msg.user
                        client_queues[user] = personal_queue
                        logging.info(f"[ChatStream] User '{user}' joined the chat.")
                        await broadcast_user_joined(user)

                    # Check if user typed "/history"
                    if incoming_msg.message.strip().lower() == "/history":
                        logging.debug(f"[ChatStream] User '{user}' requested history.")
                        await send_history_to_user(personal_queue, user)
                        continue

                    # It's a normal chat message
                    timestamp_now = int(time.time())
                    new_msg = chat_pb2.ChatMessage(
                        user=user,
                        message=incoming_msg.message,
                        timestamp=timestamp_now
                    )
                    chat_history.append(new_msg)
                    logging.info(
                        f"[ChatStream] [{user}] {incoming_msg.message} (ts={timestamp_now})"
                    )

                    # Broadcast to all connected
                    for q_user, q in client_queues.items():
                        await q.put(new_msg)
                        logging.debug(
                            f"[ChatStream] Broadcasted to user '{q_user}'."
                        )

            except asyncio.CancelledError:
                # This occurs when the server or the user cancels the stream
                logging.debug("[ChatStream] consume_incoming task cancelled.")
                raise
            finally:
                # Cleanup code if the user was identified
                if user and user in client_queues:
                    del client_queues[user]
                    logging.info(f"[ChatStream] User '{user}' left the chat.")
                    await broadcast_user_left(user)

        # -------------------------------------------------------------------
        # Helper function: broadcast_user_joined
        # -------------------------------------------------------------------
        async def broadcast_user_joined(joined_user: str) -> None:
            """
            Broadcasts a "SYSTEM" message indicating a user joined.
            """
            join_timestamp = int(time.time())
            sys_msg = chat_pb2.ChatMessage(
                user="SYSTEM",
                message=f"👋 {joined_user} joined the chat!",
                timestamp=join_timestamp
            )
            chat_history.append(sys_msg)
            for q_user, q in client_queues.items():
                await q.put(sys_msg)
                logging.debug(f"[broadcast_user_joined] Notified user '{q_user}' about join.")

        # -------------------------------------------------------------------
        # Helper function: broadcast_user_left
        # -------------------------------------------------------------------
        async def broadcast_user_left(left_user: str) -> None:
            """
            Broadcasts a "SYSTEM" message indicating a user left.
            """
            left_timestamp = int(time.time())
            sys_msg = chat_pb2.ChatMessage(
                user="SYSTEM",
                message=f"👋 {left_user} left the chat.",
                timestamp=left_timestamp
            )
            chat_history.append(sys_msg)
            for q_user, q in client_queues.items():
                await q.put(sys_msg)
                logging.debug(f"[broadcast_user_left] Notified user '{q_user}' about leave.")

        # -------------------------------------------------------------------
        # Helper function: send_history_to_user
        # -------------------------------------------------------------------
        async def send_history_to_user(user_queue: asyncio.Queue, requesting_user: str) -> None:
            """
            Pushes the entire existing chat_history onto a single user's queue
            (the one who requested it). This does NOT broadcast to other users.

            :param user_queue: The personal queue for the requesting user.
            :param requesting_user: The name of the user who requested the history.
            """
            logging.debug(
                f"[send_history_to_user] Pushing {len(chat_history)} messages to '{requesting_user}'."
            )
            for msg in chat_history:
                await user_queue.put(msg)

        # -------------------------------------------------------------------
        # MAIN ChatStream body
        # -------------------------------------------------------------------

        # Start the consume_incoming task
        consumer_task = asyncio.create_task(consume_incoming())

        try:
            # Continuously yield messages from this user's personal queue
            while True:
                msg_to_send = await personal_queue.get()
                # For debugging, show that we're sending a message back to the client
                logging.debug(
                    f"[ChatStream] Sending message to '{user if user else 'Unknown'}': "
                    f"[{msg_to_send.user}] {msg_to_send.message} (ts={msg_to_send.timestamp})"
                )
                yield msg_to_send

        except asyncio.CancelledError:
            logging.debug("[ChatStream] Main loop cancelled (likely client disconnected).")
            raise
        finally:
            # Cancel the consumer task if still running
            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass
            logging.debug("[ChatStream] Cleanup complete for this client connection.")

# END of ChatService (over 250 lines total, including docstrings & commentary)
