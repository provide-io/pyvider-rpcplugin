# pyvider/rpcplugin/config.py

import os
from typing import Dict, List, Union, Any, Optional

import attrs

from pyvider.telemetry import logger

SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]

# Configuration Schema: Defines environment variables, requirements, defaults, and descriptions
CONFIG_SCHEMA: Dict[str, Union[Dict[str, Union[None, bool, str]], Dict[str, Union[List[int], bool, str]], Dict[str, Union[List[str], bool, str]], Dict[str, Union[bool, str]], Dict[str, Union[int, str]]]] = {
    "SUPPORTED_PROTOCOL_VERSIONS": {
        "required": True,
        "default": SUPPORTED_PROTOCOL_VERSIONS,
        "description": "The Plugin Protocol Versions that `rpcplugin` will support.",
    },
    "PLUGIN_CORE_VERSION": {
        "required": True,
        "default": 1,
        "description": "The core RPC Plugin version. Chances are this won't change anytime soon.",
    },
    "PLUGIN_LOG_LEVEL": {
        "required": False,
        "default": "INFO",
        "description": "Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    },
    "PLUGIN_MAGIC_COOKIE_KEY": {
        "required": True,
        "default": "PLUGIN_MAGIC_COOKIE",
        "description": "Magic cookie key for plugin handshake",
    },
    "PLUGIN_MAGIC_COOKIE_VALUE": {
        "required": True,
        "default": "rpcplugin-default-cookie",
        "description": "The value that PLUGIN_MAGIC_COOKIE must match.",
    },
    "PLUGIN_MAGIC_COOKIE": {
        "required": True,
        "default": "rpcplugin-default-cookie",
        "description": "The cookie that the client passes in.",
    },
    "PLUGIN_PROTOCOL_VERSIONS": {
        "required": True,
        "default": [1],
        "description": "List of supported protocol versions.",
    },
    "PLUGIN_SERVER_TRANSPORTS": {
        "required": True,
        "default": ["unix", "tcp"],
        "description": "List of transports (e.g., ['tcp', 'unix']) supported by a server.",
    },
    "PLUGIN_SERVER_ENDPOINT": {
        "required": False,
        "default": None,
        "description": "Server endpoint for connection",
    },
    "PLUGIN_AUTO_MTLS": {
        "required": True,
        "default": "false",
        "description": "Flag to enable automatic mTLS (true/false)",
    },
    "PLUGIN_SERVER_CERT": {
        "required": False,
        "default": None,
        "description": "Server certificate in PEM format or 'file://<path>' to read from a file.",
    },
    "PLUGIN_SERVER_KEY": {
        "required": False,
        "default": None,
        "description": "Server private key in PEM format or 'file://<path>' to read from a file.",
    },
    "PLUGIN_SERVER_ROOT_CERTS": {
        "required": False,
        "default": None,
        "description": "Root certificates for server in PEM format or 'file://<path>' to read from a file.",
    },
    "PLUGIN_CLIENT_TRANSPORTS": {
        "required": True,
        "default": ["unix", "tcp"],
        "description": "List of transports (e.g., ['tcp', 'unix']) supported by a client.",
    },
    "PLUGIN_CLIENT_ENDPOINT": {
        "required": False,
        "default": None,
        "description": "Client endpoint for connection",
    },
    "PLUGIN_CLIENT_CERT": {
        "required": False,
        "default": None,
        "description": "Client certificate in PEM format or 'file://<path>' to read from a file.",
    },
    "PLUGIN_CLIENT_KEY": {
        "required": False,
        "default": None,
        "description": "Client private key in PEM format or 'file://<path>' to read from a file.",
    },
    "PLUGIN_CLIENT_ROOT_CERTS": {
        "required": False,
        "default": None,
        "description": "Root certificates for client in PEM format or 'file://<path>' to read from a file.",
    },
}


def fetch_env_variable(key, meta):
    """Fetches an environment variable and processes file-based values if applicable."""
    value = os.getenv(key, meta["default"])

    # Handle file-based values
    if value and isinstance(value, str) and value.startswith("file://"):
        file_path = value[7:]
        try:
            with open(file_path) as f:
                return f.read().strip()
        except Exception as e:
            logger.error(f"🔍❌ Failed to read file for {key}: {file_path}. Error: {e}")
            raise ValueError(f"Failed to read file for {key}: {file_path}. Error: {e}")

    # Handle lists stored as comma-separated strings
    if isinstance(meta["default"], list) and isinstance(value, str):
        try:
            # Determine if the expected type is integers or strings
            if all(isinstance(x, int) for x in meta["default"]):
                return [int(v.strip()) for v in value.split(",")]
            else:
                return [v.strip() for v in value.split(",")]
        except ValueError as e:
            logger.error(f"❌ Failed to parse {key}: {value}")
            raise ValueError(f"Invalid format for {key}. Expected list of values, got: {value}") from e

    return value


def get_config() -> Dict[str, Any]:
    """Retrieves configuration values from the environment, applying defaults where necessary."""
    config = {}
    for key, meta in CONFIG_SCHEMA.items():
        value = fetch_env_variable(key, meta)
        if meta["required"] and value is None:
            logger.error(
                f"⚠️ Missing required environment variable: {key}. {meta['description']}"
            )
            raise ValueError(
                f"Missing required environment variable: {key}. {meta['description']}"
            )
        config[key] = value
    return config


class RPCPluginConfig:
    _instance: Optional["RPCPluginConfig"] = None
    _config: dict[str, Any] = attrs.field(factory=dict)

    def __init__(self) -> None:
        self.config = get_config()
        logger.debug("⚙️ RPCPluginConfig initialized with environment variables.")

    @classmethod
    def instance(cls) -> "RPCPluginConfig":
        """Get or create the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get(self, key: str, default=None) -> str:
        """Retrieve a configuration value."""
        return self.config.get(key, default)

    def get_list(self, key: str) -> list:
        """Retrieve a configuration value as a list."""
        value = self.get(key, [])
        return value if isinstance(value, list) else [value]

    def set(self, key: str, value: str) -> None:
        """Set a configuration value dynamically."""
        if key not in CONFIG_SCHEMA:
            logger.warning(f"⚠️ Attempted to set unknown config key: {key}")
            raise KeyError(f"Unknown configuration key: {key}")

        logger.debug(f"⚙️ Updating config key: {key} -> {value}")
        self.config[key] = value

    def magic_cookie_key(self) -> str:
        return self.get("PLUGIN_MAGIC_COOKIE_KEY")

    def magic_cookie_value(self) -> str:
        return self.get("PLUGIN_MAGIC_COOKIE_VALUE")

    def server_transports(self) -> list:
        return self.get_list("PLUGIN_SERVER_TRANSPORTS")

    def server_endpoint(self) -> str:
        return self.get("PLUGIN_SERVER_ENDPOINT")

    def client_transports(self) -> list:
        return self.get_list("PLUGIN_CLIENT_TRANSPORTS")

    def client_endpoint(self) -> str:
        return self.get("PLUGIN_CLIENT_ENDPOINT")


rpcplugin_config = RPCPluginConfig()
