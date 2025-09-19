#
# pyvider/rpcplugin/defaults.py
#
"""
Default configuration values for the RPC plugin system.

This module centralizes all default values to avoid inline defaults
throughout the codebase, following project conventions.
"""

# Protocol version defaults
DEFAULT_SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]
DEFAULT_PLUGIN_PROTOCOL_VERSIONS = [1]

# Transport defaults
DEFAULT_SERVER_TRANSPORTS = ["unix", "tcp"]
DEFAULT_CLIENT_TRANSPORTS = ["unix", "tcp"]

# Timing and delay defaults (in seconds)
DEFAULT_PROCESS_WAIT_TIME = 0.1  # Standard wait for process operations
DEFAULT_HANDSHAKE_RETRY_WAIT = 0.2  # Wait time for handshake retries
DEFAULT_CLEANUP_WAIT_TIME = 0.05  # Brief wait for cleanup operations
DEFAULT_SOCKET_CHECK_WAIT = 0.1  # Wait time for socket state checks

# gRPC configuration defaults
DEFAULT_GRPC_KEEPALIVE_TIME_MS = 30000  # 30 seconds
DEFAULT_GRPC_KEEPALIVE_TIMEOUT_MS = 5000  # 5 seconds
DEFAULT_GRPC_GRACE_PERIOD = 0.5  # Grace period for channel close
DEFAULT_CONNECTION_TIMEOUT = 5.0  # Connection timeout in seconds
DEFAULT_PROCESS_WAIT_TIMEOUT = 7.0  # Process wait timeout in seconds

# Buffer and data size defaults (in bytes)
DEFAULT_BUFFER_SIZE = 16384  # 16KB default buffer size for data operations
DEFAULT_CHUNK_SIZE = 1024  # 1KB default chunk size for streaming

# Certificate defaults
DEFAULT_CERT_VALIDITY_DAYS = 365  # Certificate validity period in days

# Handshake and negotiation defaults
DEFAULT_HANDSHAKE_CHUNK_TIMEOUT = 1.0  # Timeout for chunk reading
DEFAULT_HANDSHAKE_INNER_TIMEOUT = 2.0  # Inner timeout for handshake operations
DEFAULT_NEGOTIATION_TIMEOUT = 2.0  # Timeout for protocol negotiation
