from typing import ClassVar as _ClassVar

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message

DESCRIPTOR: _descriptor.FileDescriptor

class EchoRequest(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: str | None = ...) -> None: ...

class EchoResponse(_message.Message):
    __slots__ = ("reply",)
    REPLY_FIELD_NUMBER: _ClassVar[int]
    reply: str
    def __init__(self, reply: str | None = ...) -> None: ...
