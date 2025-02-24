# pyvider/rpcplugin/transport/base.py

import abc
from typing import Optional

import attrs


@attrs.define(frozen=False, slots=False)
class RPCPluginTransport(abc.ABC):
    endpoint: Optional[str] = attrs.field(init=False, default=None)

    @abc.abstractmethod
    async def listen(self) -> str:
        ...

    @abc.abstractmethod
    async def connect(self, endpoint: str) -> None:
        ...

    @abc.abstractmethod
    async def close(self) -> None:
        ...
