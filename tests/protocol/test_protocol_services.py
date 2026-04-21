#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import asyncio
from typing import Any, AsyncIterator

import pytest
from provide.testkit.mocking import AsyncMock

from google.protobuf import empty_pb2

from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    _SENTINEL,
)


class DummyContext:
    def __init__(self) -> None:
        self.callbacks: list[Any] = []

    def add_done_callback(self, callback: Any) -> None:
        self.callbacks.append(callback)

    def trigger_done(self) -> None:
        for cb in self.callbacks:
            cb(None)


@pytest.mark.asyncio
async def test_broker_service_open_close_flow(monkeypatch) -> None:
    service = GRPCBrokerService()

    monkeypatch.setattr(
        "pyvider.rpcplugin.protocol.service.SubchannelConnection.open",
        AsyncMock(),
    )
    monkeypatch.setattr(
        "pyvider.rpcplugin.protocol.service.SubchannelConnection.close",
        AsyncMock(),
    )

    async def request_iter() -> AsyncIterator[ConnInfo]:
        yield ConnInfo(
            service_id=1,
            network="unix",
            address="/tmp/one",
            knock=ConnInfo.Knock(knock=True),
        )
        yield ConnInfo(service_id=1, knock=ConnInfo.Knock(knock=False))
        yield ConnInfo(service_id=2, knock=ConnInfo.Knock(knock=False))

    responses = []
    async for resp in service.StartStream(request_iter(), DummyContext()):
        responses.append(resp)

    assert len(responses) == 3
    assert responses[0].knock.ack is True
    assert responses[1].knock.ack is True
    assert responses[2].knock.error == "Channel not found"


@pytest.mark.asyncio
async def test_broker_service_outer_error(monkeypatch) -> None:
    service = GRPCBrokerService()
    monkeypatch.setattr(
        "pyvider.rpcplugin.protocol.service.SubchannelConnection.open",
        AsyncMock(),
    )

    async def request_iter() -> AsyncIterator[ConnInfo]:
        yield ConnInfo(
            service_id=3,
            network="unix",
            address="/tmp/three",
            knock=ConnInfo.Knock(knock=True),
        )
        raise RuntimeError("iterator failure")

    outputs = []
    async for resp in service.StartStream(request_iter(), DummyContext()):
        outputs.append(resp)

    assert outputs[-1].knock.error.endswith("iterator failure")


@pytest.mark.asyncio
async def test_stdio_service_stream(monkeypatch) -> None:
    service = GRPCStdioService()
    ctx = DummyContext()

    async def producer() -> None:
        await service.put_line(b"line-stdout")
        await service.put_line(b"line-stderr", is_stderr=True)
        await service._message_queue.put(_SENTINEL)
        service._shutdown = True
        ctx.trigger_done()

    stream = service.StreamStdio(empty_pb2.Empty(), ctx)
    producer_task = asyncio.create_task(producer())

    collected: list[StdioData] = []
    async for stdio in stream:
        collected.append(stdio)
        if len(collected) == 2:
            break

    await producer_task

    assert collected[0].channel == StdioData.STDOUT
    assert collected[1].channel == StdioData.STDERR

# 🐍🔌📞🔚
