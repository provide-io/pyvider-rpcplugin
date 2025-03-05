#!/usr/bin/env python3
# plog.py

import logging
import unicodedata
from functools import partial
from typing import Dict, Union, Any


# Ensure NFC-normalized emoji for consistent formatting
def normalize_emoji(emoji: str) -> str:
    return unicodedata.normalize("NFC", emoji)


# 🔥 Define Logging Levels
LOG_LEVELS: Dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

# 🏷️ Define Logging Structure
LOGGING_MATRIX = {
    "error": {
        "server": {
            "failure": "🚨 Server failure detected",
            "timeout": "⏳ Server timeout",
        },
        "client": {
            "disconnect": "🔌 Client disconnected unexpectedly",
        },
    },
    "info": {
        "connection": {
            "success": "✅ Connection successful",
            "attempt": "🔄 Attempting to connect",
        },
        "system": {
            "startup": "🚀 System startup complete",
            "shutdown": "🛑 System shutdown initiated",
        },
    },
    "warning": {
        "resource": {
            "low_memory": "⚠️ Low memory warning",
            "disk_space": "💾 Disk space running low",
        },
    },
}

# 📌 Global Logger Configuration
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
logger: logging.Logger = logging.getLogger("plog")


class LogNamespace:
    """Dynamically generates logging functions from predefined levels and actions."""

    def __init__(self, log_level: str, namespace: dict) -> None:
        self.log_level = log_level
        self.namespace = namespace

    def __getattr__(self, key: str) -> Union[partial[None], LogNamespace]:
        """Dynamically generate logging functions."""
        if key in self.namespace:
            if isinstance(self.namespace[key], dict):
                return LogNamespace(self.log_level, self.namespace[key])
            else:
                # Partial function to allow optional arguments
                return partial(self._log, key)

        raise AttributeError(f"Invalid log path: {self.log_level}.{key}")

    def _log(self, key: str, **kwargs: Any) -> None:
        """Perform logging with optional parameters."""
        message = self.namespace.get(key, "Unknown log event")
        formatted_message = normalize_emoji(message)

        log_function = getattr(logger, self.log_level, logger.info)
        log_function(f"{formatted_message} {kwargs if kwargs else ''}")


class PLog:
    """Primary logging interface for hierarchical, structured logging."""

    def __init__(self) -> None:
        for level, namespace in LOGGING_MATRIX.items():
            setattr(self, level, LogNamespace(level, namespace))


plog = PLog()

# ✅ Example Usage
if __name__ == "__main__":
    plog.error.server.failure()
    plog.error.client.disconnect(user="admin", reason="timeout")
    plog.info.system.startup()
    plog.warning.resource.low_memory(available="500MB")
    plog.info.connection.success(ip="192.168.1.1", port=8080)
