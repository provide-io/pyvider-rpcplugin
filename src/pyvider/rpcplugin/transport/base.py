# pyvider/rpcplugin/transport/base.py

import abc
import attrs

@attrs.define(frozen=False, slots=False)
class RPCPluginTransport(abc.ABC):
    endpoint: str | None = attrs.field(init=False, default=None)

    @abc.abstractmethod
    async def listen(self) -> str: ...                       # pragma: no cover

    @abc.abstractmethod
    async def connect(self, endpoint: str) -> None: ...      # pragma: no cover

    @abc.abstractmethod
    async def close(self) -> None: ...                       # proagma: no cover
