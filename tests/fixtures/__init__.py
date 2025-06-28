# tests/fixtures/__init__.py

from tests.fixtures.utils import (
    cleanup_temp_files,
    ensure_asyncio_cleanup,
    summarize_text,
)
from tests.fixtures.dummy import (
    DummyReader,
    DummyWriter,
    DummyGRPCServer,
    DummyAioServer,
    dummy_writer,
    dummy_reader,
)
from tests.fixtures.mocks import (
    MockProtocol,
    MockHandler,
    MockServicer,
    MockBytesIO,
    mock_server_transport,
    mock_server_transport_tcp,
    mock_server_transport_unix,
    mock_server_handler,
    mock_server_protocol,
    mock_server_config,
    server_with_mocks,
)
from tests.fixtures.crypto import (
    client_cert,
    server_cert,
    valid_key_pem,
    valid_cert_pem,
    invalid_key_pem,
    invalid_cert_pem,
    malformed_cert_pem,
    empty_cert,
    temporary_cert_file,
    temporary_key_file,
    dev_root_ca,
    external_dev_ca_pem,
)
from tests.fixtures.handshake import (
    mock_core_version,
    handshake_config,
    invalid_handshake_config,
)
from tests.fixtures.transport import (
    SocketStateMonitor,
    socket_monitor,
    unused_tcp_port,
    unix_transport,
    managed_unix_socket_path,
    transport_cleanup,
)
from tests.fixtures.client import (
    client_command,
    client_instance,
    mock_process,
    mock_transport,
    mock_unix_transport,
    mock_grpc_channel,
    test_client_command,
)
from tests.fixtures.server import (
    valid_server_env,
    server_instance,
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
    "DummyAioServer",
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
    # crypto
    "client_cert",
    "server_cert",
    "valid_key_pem",
    "valid_cert_pem",
    "invalid_key_pem",
    "invalid_cert_pem",
    "malformed_cert_pem",
    "empty_cert",
    "temporary_cert_file",
    "temporary_key_file",
    "dev_root_ca",
    "external_dev_ca_pem",
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
    "transport_cleanup",
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
