# pyvider/rpcplugin/transport/base.py

import abc

import attrs


@attrs.define(frozen=False, slots=False)
class RPCPluginTransport(abc.ABC):
    endpoint: str | None = attrs.field(init=False, default=None)

    @abc.abstractmethod
    async def listen(self) -> str: ...

    @abc.abstractmethod
    async def connect(self, endpoint: str) -> None: ...

    @abc.abstractmethod
    async def close(self) -> None: ...
