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
