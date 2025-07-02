# tests/fixtures/__init__.py

from tests.fixtures.client import (
    client_command,
    client_instance,
    mock_grpc_channel,
    mock_process,
    mock_transport,
    mock_unix_transport,
    started_client_instance,  # Add the new fixture here
    test_client_command,
)
from tests.fixtures.crypto import (
    client_cert,
    dev_root_ca,
    empty_cert,
    external_dev_ca_pem,
    invalid_cert_pem,
    invalid_key_pem,
    malformed_cert_pem,
    server_cert,
    temporary_cert_file,
    temporary_key_file,
    valid_cert_pem,
    valid_key_pem,
)
from tests.fixtures.dummy import (
    DummyGRPCServer,
    DummyReader,
    DummyWriter,
    dummy_reader,
    dummy_writer,
)
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
    rpc_plugin_server_manager,
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
    # client
    "client_command",
    "client_instance",
    "mock_process",
    "mock_transport",
    "mock_unix_transport",
    "mock_grpc_channel",
    "test_client_command",
    "started_client_instance",  # And here
    # server
    "valid_server_env",
    "server_instance",
    "rpc_plugin_server_manager",
]
