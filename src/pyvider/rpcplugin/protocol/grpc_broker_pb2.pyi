from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar

from google.protobuf import (
    descriptor as _descriptor,  # type: ignore[import-untyped]
    message as _message,  # type: ignore[import-untyped]
)

DESCRIPTOR: _descriptor.FileDescriptor

class ConnInfo(_message.Message):
    __slots__ = ("address", "knock", "network", "service_id")
    class Knock(_message.Message):
        __slots__ = ("ack", "error", "knock")
        KNOCK_FIELD_NUMBER: _ClassVar[int]
        ACK_FIELD_NUMBER: _ClassVar[int]
        ERROR_FIELD_NUMBER: _ClassVar[int]
        knock: bool
        ack: bool
        error: str
        def __init__(self, knock: bool = ..., ack: bool = ..., error: str | None = ...) -> None: ...

    SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    KNOCK_FIELD_NUMBER: _ClassVar[int]
    service_id: int
    network: str
    address: str
    knock: ConnInfo.Knock
    def __init__(
        self,
        service_id: int | None = ...,
        network: str | None = ...,
        address: str | None = ...,
        knock: ConnInfo.Knock | _Mapping | None = ...,
    ) -> None: ...
