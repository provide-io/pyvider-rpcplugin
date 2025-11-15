# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

from tests.fixtures.client import (
    client_command,
    client_instance,
    mock_grpc_channel,
    mock_process,
    mock_transport,
    mock_unix_transport,
    test_client_command,
)
from tests.fixtures.dummy import (
    DummyGRPCServer,
    DummyReader,
    DummyWriter,
    dummy_reader,
    dummy_writer,
)

# Crypto fixtures now imported from provide-testkit.crypto via conftest.py
from tests.fixtures.handshake import (
    handshake_config,
    invalid_handshake_config,
    mock_core_version,
)
from tests.fixtures.mocks import (
    MockBytesIO,
    MockHandler,
    MockProtocol,
    MockServicer,
    mock_server_config,
    mock_server_handler,
    mock_server_protocol,
    mock_server_transport,
    mock_server_transport_tcp,
    mock_server_transport_unix,
    server_with_mocks,
)
from tests.fixtures.server import (
    server_instance,
    valid_server_env,
)
from tests.fixtures.transport import (
    SocketStateMonitor,
    managed_unix_socket_path,
    socket_monitor,
    unix_transport,
    unused_tcp_port,
)
from tests.fixtures.utils import (
    cleanup_temp_files,
    ensure_asyncio_cleanup,
    summarize_text,
)

__all__ = [
    # utils
    "cleanup_temp_files",
    "ensure_asyncio_cleanup",
    "summarize_text",
    # dummy
    "DummyReader",
    "DummyWriter",
    "DummyGRPCServer",
    "dummy_writer",
    "dummy_reader",
    # mocks
    "MockProtocol",
    "MockHandler",
    "MockServicer",
    "MockBytesIO",
    "mock_server_transport",
    "mock_server_transport_tcp",
    "mock_server_transport_unix",
    "mock_server_handler",
    "mock_server_protocol",
    "mock_server_config",
    "server_with_mocks",
    # crypto fixtures now available from provide-testkit.crypto via conftest.py
    # handshake
    "mock_core_version",
    "handshake_config",
    "invalid_handshake_config",
    # transport
    "SocketStateMonitor",
    "socket_monitor",
    "unused_tcp_port",
    "unix_transport",
    "managed_unix_socket_path",
    # client
    "client_command",
    "client_instance",
    "mock_process",
    "mock_transport",
    "mock_unix_transport",
    "mock_grpc_channel",
    "test_client_command",
    # server
    "valid_server_env",
    "server_instance",
]

# 🐍🔌📞🔚
