from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class TestRequest(_message.Message):
    __slots__ = ("Input",)
    INPUT_FIELD_NUMBER: _ClassVar[int]
    Input: int
    def __init__(self, Input: _Optional[int] = ...) -> None: ...

class TestResponse(_message.Message):
    __slots__ = ("Output",)
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    Output: int
    def __init__(self, Output: _Optional[int] = ...) -> None: ...

class PrintKVRequest(_message.Message):
    __slots__ = ("Key", "ValueString", "ValueInt")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUESTRING_FIELD_NUMBER: _ClassVar[int]
    VALUEINT_FIELD_NUMBER: _ClassVar[int]
    Key: str
    ValueString: str
    ValueInt: int
    def __init__(self, Key: _Optional[str] = ..., ValueString: _Optional[str] = ..., ValueInt: _Optional[int] = ...) -> None: ...

class PrintKVResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BidirectionalRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class BidirectionalResponse(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class PrintStdioRequest(_message.Message):
    __slots__ = ("stdout", "stderr")
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    stdout: bytes
    stderr: bytes
    def __init__(self, stdout: _Optional[bytes] = ..., stderr: _Optional[bytes] = ...) -> None: ...

class PingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PongResponse(_message.Message):
    __slots__ = ("msg",)
    MSG_FIELD_NUMBER: _ClassVar[int]
    msg: str
    def __init__(self, msg: _Optional[str] = ...) -> None: ...
