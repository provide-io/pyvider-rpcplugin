
# chatapp/storage.py

from collections import defaultdict
import asyncio

from chatapp.proto.chat_pb2 import ChatMessage

#: The global list of all historical messages
chat_history: list[ChatMessage] = []

#: A map of username => asyncio.Queue[ChatMessage]
client_queues: dict[str, asyncio.Queue[ChatMessage]] = {}
