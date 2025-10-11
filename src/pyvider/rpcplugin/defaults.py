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

# Handshake and negotiation defaults (values not yet configurable)
DEFAULT_HANDSHAKE_CHUNK_TIMEOUT = 1.0  # Timeout for chunk reading
DEFAULT_HANDSHAKE_INNER_TIMEOUT = 2.0  # Inner timeout for handshake operations
DEFAULT_NEGOTIATION_TIMEOUT = 2.0  # Timeout for protocol negotiation
DEFAULT_PROCESS_WAIT_TIMEOUT = 7.0  # Process wait timeout in seconds

# =================================
# Core Configuration Defaults
# =================================
DEFAULT_PLUGIN_CORE_VERSION = 1
DEFAULT_PLUGIN_PROTOCOL_VERSION = 1
DEFAULT_PLUGIN_MAGIC_COOKIE_KEY = "PLUGIN_MAGIC_COOKIE"
DEFAULT_PLUGIN_MAGIC_COOKIE_VALUE = "test_cookie_value"
DEFAULT_PLUGIN_LOG_LEVEL = "INFO"

# =================================
# Timeout Configuration Defaults (in seconds)
# =================================
DEFAULT_PLUGIN_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_PLUGIN_CONNECTION_TIMEOUT = 30.0
DEFAULT_PLUGIN_CHANNEL_READY_TIMEOUT = 10.0
DEFAULT_PLUGIN_SERVER_READY_TIMEOUT = 5.0

# =================================
# Buffer and Size Defaults (in bytes)
# =================================
DEFAULT_PLUGIN_BUFFER_SIZE = 16384
DEFAULT_PLUGIN_CHUNK_SIZE = 8192

# =================================
# Transport Configuration Defaults
# =================================
DEFAULT_PLUGIN_SERVER_TRANSPORTS = ["unix", "tcp"]
DEFAULT_PLUGIN_CLIENT_TRANSPORTS = ["unix", "tcp"]
DEFAULT_SUPPORTED_TRANSPORTS = ["unix", "tcp"]

# =================================
# Security Configuration Defaults
# =================================
DEFAULT_PLUGIN_AUTO_MTLS = True
DEFAULT_PLUGIN_INSECURE = False
DEFAULT_PLUGIN_CERT_VALIDITY_DAYS = 365
DEFAULT_PLUGIN_MTLS_CERT_DIR = "/tmp/plugin-certs"
DEFAULT_PLUGIN_CLIENT_CERT_FILE = ""
DEFAULT_PLUGIN_CLIENT_KEY_FILE = ""
DEFAULT_PLUGIN_CLIENT_ROOT_CERTS = ""

# Certificate fields (PEM format or file:// paths)
DEFAULT_PLUGIN_SERVER_CERT = None
DEFAULT_PLUGIN_SERVER_KEY = None
DEFAULT_PLUGIN_SERVER_ROOT_CERTS = None
DEFAULT_PLUGIN_CLIENT_CERT = None
DEFAULT_PLUGIN_CLIENT_KEY = None
DEFAULT_PLUGIN_CA_CERT = None

# =================================
# gRPC Configuration Defaults
# =================================
DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIME_MS = 30000
DEFAULT_PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS = 5000
DEFAULT_PLUGIN_GRPC_GRACE_PERIOD = 0.5
DEFAULT_PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE = 4 * 1024 * 1024  # 4MB
DEFAULT_PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE = 4 * 1024 * 1024  # 4MB

# =================================
# Client Configuration Defaults
# =================================
DEFAULT_PLUGIN_CLIENT_MAX_RETRIES = 3
DEFAULT_PLUGIN_CLIENT_RETRY_DELAY = 1.0
DEFAULT_PLUGIN_CLIENT_BACKOFF_MULTIPLIER = 2.0
DEFAULT_PLUGIN_CLIENT_MAX_RETRY_DELAY = 10.0

# Additional retry configuration
DEFAULT_PLUGIN_CLIENT_RETRY_ENABLED = True
DEFAULT_PLUGIN_CLIENT_INITIAL_BACKOFF_MS = 100
DEFAULT_PLUGIN_CLIENT_MAX_BACKOFF_MS = 5000
DEFAULT_PLUGIN_CLIENT_RETRY_JITTER_MS = 50
DEFAULT_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S = 30.0

# =================================
# Server Configuration Defaults
# =================================
DEFAULT_PLUGIN_SERVER_HOST = "localhost"
DEFAULT_PLUGIN_SERVER_PORT = 0
DEFAULT_PLUGIN_SERVER_UNIX_SOCKET_PATH = "/tmp/plugin.sock"
DEFAULT_PLUGIN_SHUTDOWN_FILE_PATH = ""

# =================================
# Feature Configuration Defaults
# =================================
DEFAULT_PLUGIN_RATE_LIMIT_ENABLED = False
DEFAULT_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND = 100.0
DEFAULT_PLUGIN_RATE_LIMIT_BURST_CAPACITY = 200
DEFAULT_PLUGIN_HEALTH_SERVICE_ENABLED = True
DEFAULT_PLUGIN_UI_ENABLED = False
DEFAULT_PLUGIN_SHOW_EMOJI_MATRIX = False
