from enum import Enum


class TransportLogMessages(Enum):
    # TCP Transport Logs
    transport_debug_tcp_listen_start = "🔌🚀🕹 Starting listen() for TCP server..."
    transport_error_tcp_bind_failed = "🔌❌⚠ Failed to bind TCP server: {error}"
    transport_info_tcp_listening = "🔌✅👍 TCP server listening at {endpoint}"
    transport_error_tcp_init_failed = "🔌❌⚠ Error initializing TCP server: {error}"
    transport_debug_tcp_client_connected = (
        "🔌🤝👀 New client connected from {client_info}"
    )
    transport_debug_tcp_client_disconnected = "🔌🤝🛑 Client {client_info} disconnected"
    transport_debug_tcp_data_received = (
        "🔌🤝🔍 Received data from {client_info}: {data}"
    )
    transport_debug_tcp_data_echoed = "🔌🤝✅ Echoed data to {client_info}"
    transport_warning_tcp_client_abrupt_disconnection = (
        "🔌🤝⚠ Client {client_info} disconnected abruptly: {error}"
    )
    transport_error_tcp_client_handling = (
        "🔌🤝❌ Error handling client {client_info}: {error}"
    )
    transport_info_tcp_connection_closed = "🔌🤝🔒 Closed connection to {client_info}"
    transport_error_tcp_connection_close_failed = (
        "🔌🤝❌ Error closing connection to {client_info}: {error}"
    )
    transport_debug_tcp_connect_attempt = (
        "🔌🚀🕵️ Attempting connection to TCP endpoint: {endpoint}"
    )
    transport_error_tcp_invalid_endpoint_format = (
        "🔌❌⚠ Invalid TCP endpoint format: {endpoint}"
    )
    transport_error_tcp_unexpected_endpoint_format = (
        "🔌❌⚠ Unexpected endpoint format: {endpoint}"
    )
    transport_error_tcp_address_resolution_failed = (
        "🔌❌⚠ getaddrinfo failed for {host}:{port}: {error}"
    )
    transport_info_tcp_connection_success = (
        "🔌✅👍 Successfully connected to TCP endpoint: {endpoint}"
    )
    transport_error_tcp_connection_timeout = (
        "🔌❌⚠ Connection timeout for TCP endpoint {endpoint}: {error}"
    )
    transport_error_tcp_connection_failed = (
        "🔌❌⚠ Failed to connect to TCP endpoint {endpoint}: {error}"
    )
    transport_debug_tcp_closing_transport = (
        "🔌🔒🛑 Closing TCP transport at endpoint {endpoint}"
    )
    transport_info_tcp_client_writer_closed = "🔌🔒✅ Client writer closed successfully"
    transport_error_tcp_client_writer_close_failed = (
        "🔌🔒❌ Error closing client writer: {error}"
    )
    transport_info_tcp_server_closed = "🔌🔒✅ TCP server closed successfully"
    transport_error_tcp_server_close_failed = "🔌🔒❌ Error closing TCP server: {error}"

    # Unix Transport Logs
    transport_debug_unix_client_connected = (
        "📞🤝🚀 New client connection from {peer_info}"
    )
    transport_debug_unix_connection_added = (
        "📞📥✅ Added connection to pool: {connection.remote_addr}"
    )
    transport_debug_unix_no_data_received = (
        "📞📥⚠️ No data received from {peer_info}, closing connection"
    )
    transport_debug_unix_data_received = (
        "📞📥✅ Received data from {peer_info}: {bytes_received} bytes"
    )
    transport_debug_unix_data_echoed = "📞📤✅ Echoed data back to {peer_info}"
    transport_debug_unix_connection_handler_cancelled = (
        "📞🛑✅ Connection handler cancelled for {peer_info}"
    )
    transport_error_unix_client_handling = (
        "📞❗❌ Error handling client {peer_info}: {error}"
    )
    transport_debug_unix_connection_closed = "📞🔒✅ Closed connection from {peer_info}"
    transport_debug_unix_socket_in_use = "📞🔍❌ Socket {path} is in use"
    transport_debug_unix_socket_available = "📞🔍✅ Socket {path} is available"
    transport_error_unix_socket_check_failed = "📞🔍❌ Error checking socket: {error}"
    transport_debug_unix_create_socket = "📞🕹🚀 Creating Unix socket at {path}"
    transport_error_unix_socket_already_in_use = "📞🕹❌ Socket {path} already in use"
    transport_debug_unix_removed_stale_socket = (
        "📞🕹✅ Removed stale socket file: {path}"
    )
    transport_error_unix_stale_socket_remove_failed = (
        "📞🕹❌ Failed to remove stale socket: {error}"
    )
    transport_debug_unix_server_listening = "📞🕹✅ Server listening on {path}"
    transport_error_unix_server_create_failed = (
        "📞🕹❌ Failed to create Unix socket: {error}"
    )
    transport_debug_unix_writer_closed = "📞🔒✅ Writer closed successfully"
    transport_error_unix_writer_close_failed = "📞🔒❌ Error closing writer: {error}"
    transport_debug_unix_connect_attempt = (
        "📞🤝🚀 Connecting to Unix socket at {endpoint}"
    )
    transport_error_unix_connection_failed = (
        "📞🤝❌ Failed to connect to Unix socket: {error}"
    )
    transport_debug_unix_connection_success = (
        "📞🤝✅ Connected to Unix socket at {endpoint}"
    )
    transport_debug_unix_closing_transport = (
        "📞🔒🚀 Closing Unix socket transport at {path}"
    )
    transport_debug_unix_closing_active_connections = (
        "📞🔒🔄 Closing {count} active connections"
    )
    transport_debug_unix_client_writer_closed = "📞🔒✅ Closed client writer"
    transport_error_unix_client_writer_close_failed = (
        "📞🔒⚠️ Error closing writer: {error}"
    )
    transport_debug_unix_server_closed = "📞🔒✅ Closed server"
    transport_error_unix_server_close_failed = "📞🔒⚠️ Error closing server: {error}"
    transport_debug_unix_socket_file_removed = "📞🔒✅ Removed socket file: {path}"
    transport_error_unix_socket_file_remove_failed = (
        "📞🔒❌ Failed to remove socket file: {error}"
    )
    transport_debug_unix_transport_closed = (
        "📞🔒✅ Unix socket transport closed completely"
    )
