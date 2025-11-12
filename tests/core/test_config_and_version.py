# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Tests covering version handling and configuration helpers."""

from __future__ import annotations

import importlib

from provide.foundation.errors import ValidationError
import pytest

from pyvider.rpcplugin import __version__
from pyvider.rpcplugin.config import RPCPluginConfig  # noqa: F401 - imported for type checks
from pyvider.rpcplugin.config.configure import configure
from pyvider.rpcplugin.config.validators import (
    validate_protocol_versions_list,
    validate_transport_list,
)


def test_version_is_available() -> None:
    """Test that __version__ is available and is a valid version string."""
    assert __version__ is not None
    assert isinstance(__version__, str)
    assert len(__version__) > 0
    # Should be a valid version format (either semver or dev)
    assert "." in __version__ or __version__ == "0.0.0-dev"


def test_config_module_reexports(monkeypatch: pytest.MonkeyPatch) -> None:
    config_module = importlib.import_module("pyvider.rpcplugin.config")
    configure_module = importlib.import_module("pyvider.rpcplugin.config.configure")

    fresh_instance = config_module.RPCPluginConfig.from_env()
    monkeypatch.setattr(config_module, "rpcplugin_config", fresh_instance, raising=True)

    assert hasattr(config_module, "configure")
    assert config_module.configure is configure_module.configure
    assert config_module.rpcplugin_config is fresh_instance


def test_configure_updates_prefixed_unprefixed_and_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    config_module = importlib.import_module("pyvider.rpcplugin.config")
    configure_module = importlib.import_module("pyvider.rpcplugin.config.configure")
    fresh_instance = config_module.RPCPluginConfig.from_env()
    monkeypatch.setattr(config_module, "rpcplugin_config", fresh_instance, raising=True)

    warnings: list[str] = []

    def fake_warning(message: str) -> None:
        warnings.append(message)

    monkeypatch.setattr(configure_module.logger, "warning", fake_warning, raising=True)

    configure(
        magic_cookie="magic-cookie",
        protocol_version=42,
        transports=["tcp"],
        auto_mtls=True,
        handshake_timeout=12.5,
        log_level="DEBUG",
        unknown_option="value",
    )

    assert fresh_instance.plugin_magic_cookie_value == "magic-cookie"
    assert fresh_instance.plugin_protocol_versions == [42]
    assert fresh_instance.plugin_server_transports == ["tcp"]
    assert fresh_instance.plugin_client_transports == ["tcp"]
    assert fresh_instance.plugin_auto_mtls is True
    assert fresh_instance.plugin_handshake_timeout == 12.5
    assert fresh_instance.plugin_log_level == "DEBUG"
    assert warnings and "Unknown configuration parameter: unknown_option" in warnings[0]


def test_configure_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    config_module = importlib.import_module("pyvider.rpcplugin.config")

    class BrokenConfig:
        def __init__(self) -> None:
            self._value = "unchanged"

        @property
        def plugin_magic_cookie_value(self) -> str:
            return self._value

        @plugin_magic_cookie_value.setter
        def plugin_magic_cookie_value(self, value: str) -> None:
            raise RuntimeError(f"Cannot set to {value}")

    broken = BrokenConfig()
    monkeypatch.setattr(config_module, "rpcplugin_config", broken, raising=True)

    with pytest.raises(config_module.ConfigError, match="Failed to configure RPC plugin"):
        configure(magic_cookie="should-fail")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1,2,3", [1, 2, 3]),
        ([4, 5], [4, 5]),
    ],
)
def test_validate_protocol_versions_list_success(value: str | list[int], expected: list[int]) -> None:
    assert validate_protocol_versions_list(value) == expected


def test_validate_protocol_versions_list_invalid_type() -> None:
    with pytest.raises(ValidationError, match="Protocol versions must be a list or comma-separated string"):
        validate_protocol_versions_list(10)  # type: ignore[arg-type]


def test_validate_protocol_versions_list_invalid_entry() -> None:
    with pytest.raises(ValidationError, match="must be between 1 and 7"):
        validate_protocol_versions_list([999])


def test_validate_transport_list_success() -> None:
    assert validate_transport_list("unix,tcp") == ["unix", "tcp"]


def test_validate_transport_list_invalid_entry() -> None:
    with pytest.raises(ValidationError, match="Invalid transport 'bogus'"):
        validate_transport_list(["bogus"])

# 🐍🔌📞🔚
