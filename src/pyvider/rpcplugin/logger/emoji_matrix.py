"""
emoji_matrix.py
---------------
Defines a three-emoji logging contract for Pyvider.
Each log message should be prefixed with:
  1. Primary Emoji: The major domain/component.
  2. Secondary Emoji: The specific action/subdomain.
  3. Tertiary Emoji: The outcome/status.
Set PLUGIN_SHOW_EMOJI_MATRIX to true to display this matrix at startup.
"""

import os

from pyvider.rpcplugin.logger import logger

# Primary (Component/Domain) Emoji Mapping:
PRIMARY_EMOJI = {
    "server": "🛎️",  # Server: Represents the service provider (like a bellhop serving guests).
    "client": "🙋",  # Client: Represents the service consumer (like a guest requesting service).
    "plugin": "🔌",  # Plugin: Represents the plugin architecture and dynamic loading.
    "tcp": "🌐",  # TCP: Represents TCP/IP network communications.
    "unix": "📞",  # Unix: Represents local IPC via Unix domain sockets.
    "handshake": "🤝",  # Handshake: Represents connection negotiation and protocol setup.
    "security": "🔐",  # Security: Represents certificate handling, mTLS, and encryption.
    "config": "⚙️",  # Configuration: Represents configuration management and env parsing.
    "protocol": "📡",  # Protocol: Represents RPC protocol operations and service definitions.
    "utilities": "🧰",  # Utilities: Represents helper functions and common utilities.
    "exceptions": "❗",  # Exceptions: Represents custom exception handling.
    "telemetry": "🛰️",  # Telemetry: Represents monitoring, metrics, and tracing.
    "di": "💉",  # Dependency Injection: Represents service registration and injection.
}

# Secondary (Action/Subdomain) Emoji Mapping:
SECONDARY_EMOJI = {
    "start": "🚀",  # Start: Launching processes.
    "handshake": "🤝",  # Handshake: Negotiating connections.
    "connect": "🕵️",  # Connect: Inspecting or attempting a connection.
    "listen": "🕹",  # Listen: Awaiting events or connections.
    "read": "📖",  # Read: Reading data.
    "write": "📤",  # Write: Sending data.
    "receive": "📥",  # Receive: Capturing incoming data.
    "close": "🔒",  # Close: Terminating connections.
    "parse": "🔍",  # Parse: Validating or checking data formats.
    "build": "📝",  # Build: Constructing messages, certificates, or responses.
    "retry": "🔁",  # Retry: Reattempting operations.
    "test": "🧪",  # Test: Running tests or mocks.
    "cert": "📜",  # Cert: Operations specifically involving certificates.
    "key": "🔑",  # Key: Operations involving key management.
    "encrypt": "🛡️ ",  # Encrypt: Encryption or integrity checks.
}

# Tertiary (Outcome/Status) Emoji Mapping:
TERTIARY_EMOJI = {
    "success": "✅",  # Success: Operation completed successfully.
    "error": "❌",  # Error: A recoverable, non-fatal error occurred.
    "failure": "🚫",  # Failure: A terminal or critical failure occurred.
    "warning": "⚠️",  # Warning: A cautionary, non-critical issue.
    "stop": "🛑",  # Stop: Process/connection halted or shut down.
    "affirmative": "👍",  # Affirmative: Positive confirmation.
    "monitor": "👀",  # Monitor: Observing state changes.
    "crash": "💥",  # Crash: A critical crash occurred.
    "none": "⭕",  # None: No value produced or empty result.
    "suspend": "⏸️",  # Suspend: Operation is temporarily paused.
    "resume": "▶️",  # Resume: Operation has resumed.
    "pending": "⏳",  # Pending: Operation is waiting or incomplete.
    "idle": "💤",  # Idle: Operation is in a low-activity state.
    "ongoing": "🔄",  # Ongoing: Operation is repeating or continuous.
}


def show_emoji_matrix() -> None:
    """
    Logs the three-emoji contract mapping using logger.info() if
    the PLUGIN_SHOW_EMOJI_MATRIX environment variable is truthy.
    """
    show = os.getenv("PLUGIN_SHOW_EMOJI_MATRIX", "false").strip().lower() in (
        "true",
        "1",
        "yes",
    )
    if not show:
        return

    header = "Emoji Matrix (Primary | Secondary | Tertiary):"
    divider = "-" * len(header)
    lines = [header, divider]

    lines.append("\nComponents (Primary):")
    for key, emoji in PRIMARY_EMOJI.items():
        lines.append(f"  {emoji}  -> {key.capitalize()}")

    lines.append("\nActions (Secondary):")
    for key, emoji in SECONDARY_EMOJI.items():
        lines.append(f"  {emoji}  -> {key.capitalize()}")

    lines.append("\nOutcomes (Tertiary):")
    for key, emoji in TERTIARY_EMOJI.items():
        lines.append(f"  {emoji}  -> {key.capitalize()}")

    output = "\n".join(lines)
    logger.info(output)
