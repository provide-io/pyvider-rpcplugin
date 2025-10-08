"""Tests covering exception formatting and factory utilities."""

from __future__ import annotations

from typing import Any

import pytest

from pyvider.rpcplugin import factories
from pyvider.rpcplugin.exception import RPCPluginError


def test_rpcplugin_error_str_formats_prefix_code_hint() -> None:
    err = RPCPluginError("Something went wrong", hint="check config", code=400)
    msg = str(err)
    assert msg.startswith("[RPCPluginError] Something went wrong")
    assert "[Code: 400]" in msg
    assert "(Hint: check config)" in msg


def test_rpcplugin_error_does_not_duplicate_existing_prefix() -> None:
    err = RPCPluginError("[RPCPluginError] Already prefixed")
    assert str(err) == "[RPCPluginError] Already prefixed"


@pytest.mark.asyncio
async def test_create_basic_protocol_behaviour() -> None:
    BasicProtocol = factories.create_basic_protocol()
    protocol = BasicProtocol(service_name_override="custom.service")

    descriptors = await protocol.get_grpc_descriptors()
    assert descriptors == (None, "custom.service")
    assert protocol.get_method_type("Anything") == "unary_unary"


def test_plugin_protocol_with_custom_class() -> None:
    class DummyProto:
        def __init__(self, *, service_name_override: str | None = None, extra: str | None = None) -> None:
            self.service_name = service_name_override or "default"
            self.extra = extra

    proto = factories.plugin_protocol(protocol_class=DummyProto, service_name="svc", extra="value")
    assert isinstance(proto, DummyProto)
    assert proto.service_name == "svc"
    assert proto.extra == "value"


def test_plugin_protocol_default_kwargs_passthrough() -> None:
    proto = factories.plugin_protocol(service_name_override="direct")
    assert proto.service_name == "direct"


def test_plugin_server_invalid_transport() -> None:
    protocol = factories.create_basic_protocol()
    handler: Any = object()

    with pytest.raises(ValueError, match="Unsupported transport type"):
        factories.plugin_server(protocol=protocol(), handler=handler, transport="invalid")


def test_plugin_client_auto_connect_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    warnings: list[str] = []

    def fake_warning(message: str) -> None:
        warnings.append(message)

    monkeypatch.setattr("pyvider.rpcplugin.factories.logger.warning", fake_warning, raising=True)
    client = factories.plugin_client(command=["echo"], auto_connect=True)
    assert client.command == ["echo"]
    assert warnings and "auto_connect=True" in warnings[0]
