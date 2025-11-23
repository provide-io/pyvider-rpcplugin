# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

import asyncio
import os
import sys

os.environ.pop("OPENOBSERVE_URL", None)

# On Windows, prevent UnicodeEncodeError from emoji/box-drawing characters in
# provide.foundation's structured logger.  colorama wraps sys.stdout with an
# AnsiToWin32 proxy whose .wrapped attribute is the real cp1252 TextIOWrapper.
# That reference is saved in structlog's PrintLogger._file before pytest
# replaces sys.stdout with its capture buffer.  Reconfiguring the underlying
# streams (sys.__stdout__ / sys.__stderr__) to UTF-8 fixes all write paths.
if sys.platform == "win32":
    for _real in (sys.__stdout__, sys.__stderr__, sys.stdout, sys.stderr):
        if _real is None:
            continue
        # Direct reconfigure (TextIOWrapper)
        if hasattr(_real, "reconfigure"):
            try:
                _real.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
            except Exception:
                pass
        # colorama AnsiToWin32: reconfigure the inner .wrapped stream
        for _attr in ("wrapped", "stream"):
            _inner = getattr(_real, _attr, None)
            if _inner is not None and hasattr(_inner, "reconfigure"):
                try:
                    _inner.reconfigure(encoding="utf-8", errors="replace")
                except Exception:
                    pass

from attrs import fields

# gRPC health stubs generated with newer releases perform a strict runtime check
# via google.protobuf.runtime_version. On this environment (grpcio==1.74.x) the
# check aborts; disable it so the stock modules import for test usage.
try:  # pragma: no cover - best effort shim
    from google.protobuf import runtime_version as _runtime_version

    def _noop_validate(*_: object, **__: object) -> None:
        return None

    _runtime_version.ValidateProtobufRuntimeVersion = _noop_validate  # type: ignore[assignment]
except Exception:
    pass


# Import provide-testkit fixtures directly
import pytest

from pyvider.rpcplugin.config import RPCPluginConfig
from tests.fixtures import *

# Import provide-testkit fixtures directly
from provide.testkit.mocking.fixtures import (
    async_mock_factory,
    magic_mock_factory,
    spy_fixture,
    auto_patch,
    mock_open_fixture,
)
from provide.testkit.transport.fixtures import free_port, tcp_client_server
from provide.testkit.crypto import (
    client_cert,
    server_cert,
    ca_cert,
    valid_key_pem,
    valid_cert_pem,
    invalid_key_pem,
    invalid_cert_pem,
    malformed_cert_pem,
    empty_cert,
    temporary_cert_file,
    temporary_key_file,
    external_ca_pem,
)


def get_all_env_vars() -> list[str]:
    """
    Extract all environment variable keys from RPCPluginConfig metadata.

    This provides dynamic env var discovery without hardcoded constants,
    ensuring test isolation covers all config fields automatically.
    """
    return [
        field.metadata.get("env_var") for field in fields(RPCPluginConfig) if field.metadata.get("env_var")
    ]


@pytest.fixture
def _function_event_loop():
    """Provide the event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    # Cleanup pending tasks
    try:
        pending = asyncio.all_tasks(loop)
    except AttributeError:
        # Python 3.9+ uses asyncio.all_tasks without loop parameter
        pending = asyncio.all_tasks()
        pending = {task for task in pending if task.get_loop() == loop}

    for task in pending:
        task.cancel()

    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.close()


@pytest.fixture(autouse=True, scope="function")
def reset_rpcplugin_config_singleton():
    """
    Fixture to reset the RPCPluginConfig singleton and relevant env vars before each test.
    This ensures complete test isolation with respect to configuration.

    Uses metadata-driven env var discovery to eliminate hardcoded constants.
    """
    # Foundation config doesn't use singleton pattern like old implementation
    # Environment cleanup is sufficient for test isolation

    # Backup and clear all environment variables from config metadata
    env_keys_to_clear = get_all_env_vars()
    original_env_values = {key: os.environ.get(key) for key in env_keys_to_clear if key}

    for key in env_keys_to_clear:
        if key and key in os.environ:
            del os.environ[key]

    # The test runs now in a pristine environment. The first call to
    # RPCPluginConfig.from_env() in the test will create a fresh instance.
    yield

    # Teardown: Restore original environment variables
    for key, value in original_env_values.items():
        if value is not None:
            os.environ[key] = value
        elif key in os.environ:
            del os.environ[key]

    # Foundation config loads fresh from environment each time
    # No singleton cleanup needed

# 🐍🔌📞🔚
