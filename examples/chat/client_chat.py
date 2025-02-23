#!/usr/bin/env python3
"""
client_chat.py

An updated, user-friendly gRPC chat client script (>=250 lines) that:

1) Reads the username from the first command-line argument (or prompts if missing).
2) Immediately joins a live chat stream (bidirectional gRPC).
3) Supports commands:
   - "/history": Fetches the entire chat history via a unary GetMessageHistory RPC
                 and displays it in a user-friendly format with emojis & timestamps.
   - "/side <content>": Sends a one-off meta message to the server using a unary
                       SendMessage call. This message is marked "[SIDE]" internally
                       so the server can decide not to broadcast it if desired.
   - "exit": Exits the chat.
4) Allows multi-line chat messages if the user wants (Enter twice to finalize a message).
5) Formats incoming and history messages with "HH:MM:SS | username: message".
6) Uses more emojis to enhance the user experience.
7) Maintains logging and concurrency best practices.

Usage:
    python client_chat.py <username> [--server=host:port]

Example:
    python client_chat.py tim-term-1
    python client_chat.py "Bob the Great" --server=myserver.local:8080

Doctest (purely illustrative):
>>> import asyncio
>>> # Typically, you'd mock gRPC calls. We'll just do a trivial check:
>>> asyncio.run(asyncio.sleep(0))
"""

import asyncio
import logging
import sys
import time
from collections.abc import AsyncIterator
from datetime import datetime

import attrs
import chat_pb2
import chat_pb2_grpc
import grpc

# ------------------------------------------------------------------------------------
# Data classes / Config
# ------------------------------------------------------------------------------------


@attrs.define
class ClientConfig:
    """
    Holds client configuration such as username and server address.

    Example usage:
    >>> cfg = ClientConfig(username='alice', server='localhost:50051')
    >>> cfg.username
    'alice'
    >>> cfg.server
    'localhost:50051'
    """
    username: str
    server: str = "localhost:50051"


# ------------------------------------------------------------------------------------
# Helper functions for user input and formatting
# ------------------------------------------------------------------------------------

def format_timestamp(ts: int) -> str:
    """
    Format a UNIX timestamp into HH:MM:SS for display.

    >>> format_timestamp(1739825378)  # Pseudo example
    '19:09:38'
    """
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S")


def format_chat_message(msg: chat_pb2.ChatMessage) -> str:
    """
    Format a ChatMessage as "HH:MM:SS | user: message" with some extra emojis.
    E.g.: "12:34:56 | tim-term-1: Hello world!"

    >>> m = chat_pb2.ChatMessage(timestamp=1739825378, user="alice", message="Hi!")
    >>> s = format_chat_message(m)
    >>> "alice: Hi!" in s
    True
    """
    ts_str = format_timestamp(msg.timestamp)
    return f"{ts_str} | {msg.user}: {msg.message}"


async def read_multiline_input(prompt: str) -> str:
    """
    Allow the user to enter a multi-line message. 
    They can press Enter twice (blank line) to finish.

    Returns the full text (with line breaks).
    If the user just presses Enter once on an empty line, returns an empty string.

    Example usage (pseudo):
    >>> import asyncio
    >>> # Hard to demonstrate multiline input in a doctest, but let's do a trivial check:
    >>> True
    True
    """
    print(f"{prompt} (Press ENTER twice to send. Type '/exit' to abort this multiline.)")

    lines = []
    while True:
        line = await asyncio.to_thread(input, "")
        if line.strip().lower() == "/exit":
            # user wants to abandon multiline
            return ""
        if line == "":
            # blank line -> end
            break
        lines.append(line)
    return "\n".join(lines)

# ------------------------------------------------------------------------------------
# Main interactive loop - reading commands/messages from user
# ------------------------------------------------------------------------------------


async def interactive_chat_loop(
    cfg: ClientConfig,
    stub: chat_pb2_grpc.ChatServiceStub,
    outbound_queue: asyncio.Queue[chat_pb2.ChatMessage],
    shutdown_event: asyncio.Event
) -> None:
    """
    This function runs in a separate task. It continuously reads user input 
    from the console and decides what to do:
      - If user types '/history', calls unary GetMessageHistory
        and displays the entire chat in friendly format.
      - If user types '/side <something>', calls unary SendMessage with 
        the content prepended by '[SIDE]' to indicate the server might not broadcast.
      - If user types 'exit', signals shutdown_event and stops.
      - Otherwise, it can handle multiline input or single-line input for chat messages,
        then places them on the outbound_queue so the streaming loop will send it.

    :param cfg: ClientConfig with username, server, etc.
    :param stub: ChatServiceStub for calling unary methods like SendMessage or GetMessageHistory
    :param outbound_queue: The queue from which the streaming generator will consume ChatMessages
    :param shutdown_event: An Event used to coordinate shutting down the program
    """
    greeting_emoji = "💬"
    instructions = (
        f"\n{greeting_emoji} Welcome to the Chat, {cfg.username}!\n"
        "Type '/history' to see entire chat history.\n"
        "Type '/side <text>' to send a side chat message.\n"
        "Type '/multiline' to enter a multi-line message.\n"
        "Type 'exit' to leave the chat.\n"
        "Otherwise, type your message in one line.\n"
    )
    print(instructions)

    while not shutdown_event.is_set():
        # read one line of user input
        user_input = await asyncio.to_thread(input, "👉 ")

        # normalize
        trimmed = user_input.strip().lower()

        if trimmed == "":
            # user might have just pressed Enter; skip
            continue

        if trimmed == "exit":
            print("👋 Exiting chat...")
            shutdown_event.set()
            break

        if trimmed.startswith("/history"):
            # Call the unary GetMessageHistory
            await fetch_and_display_history(stub)
            continue

        if trimmed.startswith("/side"):
            # e.g. "/side some content here"
            # we remove "/side" and the space
            parts = user_input.split(" ", 1)
            if len(parts) < 2:
                # user typed "/side" with no content
                print("⚠️  Please provide content after /side. E.g.: /side user=tim")
                continue
            side_chat_content = parts[1]
            await send_side_chat_message(cfg.username, side_chat_content, stub)
            continue

        if trimmed.startswith("/ml"):
            # user wants to enter multiline
            multi_text = await read_multiline_input("📝 Enter multiline message:")
            if multi_text.strip():
                # put in the outbound queue
                msg = chat_pb2.ChatMessage(
                    user=cfg.username,
                    message=multi_text,
                    timestamp=int(time.time())
                )
                await outbound_queue.put(msg)
            else:
                print("No multiline message entered. Aborted.")
            continue

        # Otherwise, assume it's a single line message for the chat stream
        msg = chat_pb2.ChatMessage(
            user=cfg.username,
            message=user_input,
            timestamp=int(time.time())
        )
        await outbound_queue.put(msg)


async def fetch_and_display_history(stub: chat_pb2_grpc.ChatServiceStub) -> None:
    """
    Calls the unary GetMessageHistory RPC, then displays each message 
    with "HH:MM:SS | username: message" format.
    """
    print("⏳ Fetching full history...")
    try:
        history_response = await stub.GetMessageHistory(chat_pb2.MessageHistoryRequest())
        print("📜 Full Chat History:\n")
        for msg in history_response.messages:
            print(format_chat_message(msg))
        print("\n🕰️ End of History.\n")
    except grpc.RpcError as e:
        print(f"❌ Error fetching history: {e.code()} {e.details()}")


async def send_side_chat_message(username: str, side_chat_content: str, stub: chat_pb2_grpc.ChatServiceStub) -> None:
    """
    Sends a one-off meta message to the server via the unary SendMessage call.
    By default, the server's existing code broadcasts all messages. To truly
    skip broadcast, the server must detect "[SIDE]" and not forward it.

    Example: 
        /meta This is admin-only info
    """
    side_chat_msg = f"[SIDE] {side_chat_content}"
    req = chat_pb2.SendMessageRequest(user=username, message=side_chat_msg)
    try:
        resp = await stub.SendMessage(req)
        if resp.success:
            logging.debug("🔏 Meta message acknowledged. (Server may skip broadcast if it checks [SIDE].)")
        else:
            print(f"❌ Failed to send meta message: {resp.error_message}")
    except grpc.RpcError as e:
        print(f"❌ gRPC Error on meta message: {e.details()} (code: {e.code()})")

# ------------------------------------------------------------------------------------
# Streaming / concurrency
# ------------------------------------------------------------------------------------


async def outbound_message_generator(
    cfg: ClientConfig,
    outbound_queue: asyncio.Queue[chat_pb2.ChatMessage],
    shutdown_event: asyncio.Event
) -> AsyncIterator[chat_pb2.ChatMessage]:
    """
    This async generator pulls ChatMessage objects from `outbound_queue` 
    and yields them to the server until we're shutting down.
    """
    try:
        while not shutdown_event.is_set():
            # Wait for a new message
            try:
                msg = await asyncio.wait_for(outbound_queue.get(), timeout=0.1)
            except TimeoutError:
                continue

            yield msg

            # Mark the item as done if we want
            outbound_queue.task_done()
    except asyncio.CancelledError:
        logging.debug("Outbound generator was cancelled. Exiting.")
        raise


async def receive_inbound_messages(
    inbound_stream: AsyncIterator[chat_pb2.ChatMessage],
    shutdown_event: asyncio.Event
) -> None:
    """
    Continuously reads messages from the server's inbound ChatStream 
    and displays them with timestamps and emojis.
    """
    try:
        async for msg in inbound_stream:
            # We'll format the message with "HH:MM:SS | user: text"
            # and also prefix with a chat emoji:
            out = format_chat_message(msg)
            # Add a small icon to differentiate inbound chat from user input prompt
            print(f"💌 {out}")
    except asyncio.CancelledError:
        logging.debug("Inbound reader cancelled.")
        raise
    except grpc.RpcError as e:
        # If the stream is ended or some error occurs
        print(f"❌ Inbound stream error: {e.code()} {e.details()}")
    finally:
        # If server closed or user ended, we can set the shutdown
        shutdown_event.set()
        print("🛑 Inbound stream ended. Press Enter to exit.")

# ------------------------------------------------------------------------------------
# Main client entry point
# ------------------------------------------------------------------------------------


async def main_client(cfg: ClientConfig) -> None:
    """
    Sets up gRPC channel and tasks for:
        - The outbound message generator (bidirectional streaming)
        - The inbound message reader
        - The interactive command loop

    Runs until the user chooses to exit.
    """
    # Logging for connection
    logging.info(f"🌐 Connecting to server at {cfg.server} as user '{cfg.username}'...")

    # We'll create an async channel
    async with grpc.aio.insecure_channel(cfg.server) as channel:
        stub = chat_pb2_grpc.ChatServiceStub(channel)

        # We'll store messages to be streamed out in this queue
        outbound_queue: asyncio.Queue[chat_pb2.ChatMessage] = asyncio.Queue()

        # A shared event to coordinate shutdown
        shutdown_event = asyncio.Event()

        # Start the ChatStream
        # 1) Our outbound generator yields messages from outbound_queue
        out_gen = outbound_message_generator(cfg, outbound_queue, shutdown_event)
        # 2) stub.ChatStream(...) returns an async iterator for inbound messages
        inbound_stream = stub.ChatStream(out_gen)

        # Task 1: read inbound messages
        inbound_task = asyncio.create_task(receive_inbound_messages(inbound_stream, shutdown_event))

        # Task 2: run interactive loop for user commands/messages
        interactive_task = asyncio.create_task(interactive_chat_loop(cfg, stub, outbound_queue, shutdown_event))

        # Wait until the interactive loop or inbound reading completes
        await asyncio.wait(
            {inbound_task, interactive_task},
            return_when=asyncio.FIRST_COMPLETED
        )

        # If one finishes, we cancel the other
        tasks_to_cancel = []
        if not inbound_task.done():
            tasks_to_cancel.append(inbound_task)
        if not interactive_task.done():
            tasks_to_cancel.append(interactive_task)

        for t in tasks_to_cancel:
            t.cancel()

        await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        logging.info("Shutting down client gracefully...")


def parse_cli_args() -> ClientConfig:
    """
    Parse sys.argv for:
      - username (first positional arg)
      - optional --server=host:port
    Returns a ClientConfig.
    """
    default_server = "localhost:50051"
    args = sys.argv[1:]
    username: str | None = None
    server_val = default_server

    # Extract username from the first positional arg if present
    leftover = []
    for arg in args:
        if arg.startswith("--server="):
            server_val = arg.split("=", 1)[1].strip()
        else:
            leftover.append(arg)

    if leftover:
        username = leftover[0]

    if not username:
        # Prompt if missing
        username = input("Enter your username: ").strip()
        if not username:
            username = f"user_{int(time.time())}"  # fallback

    return ClientConfig(username=username, server=server_val)


def main() -> None:
    """
    Main entrypoint. Parses CLI arguments, sets up logging,
    and runs the main_client in asyncio event loop.
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    cfg = parse_cli_args()
    try:
        asyncio.run(main_client(cfg))
    except KeyboardInterrupt:
        logging.info("👋 KeyboardInterrupt: Exiting chat client.")


if __name__ == "__main__":
    main()
