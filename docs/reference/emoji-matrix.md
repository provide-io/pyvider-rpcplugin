---
title: Emoji Logging Matrix
description: Reference for the emoji-based logging system in Pyvider
---

# Emoji Logging Matrix

Pyvider uses a structured emoji-based logging system that prefixes log messages with three emojis to indicate the domain, action, and status of each operation. This provides a visual, scannable way to understand logs at a glance—because wading through walls of text is so 2020.

## Emoji Structure

Each log message follows this pattern:

```
[Domain] → [Action] → [Status]  Message
```

For example:
```
🔌🚀✅ Starting plugin server
```

This indicates:
- Domain (`🔌`): Plugin component
- Action (`🚀`): Starting operation
- Status (`✅`): Success

## Domain Emojis (First Position)

| Emoji | Domain | Description |
|-------|--------|-------------|
| 🛎️ | Server | Server component operations |
| 🙋 | Client | Client component operations |
| 🔌 | Plugin | Plugin component operations |
| 🌐 | TCP | TCP transport operations |
| 📞 | Unix | Unix socket transport operations |
| 🤝 | Handshake | Handshake protocol operations |
| 🔐 | Security | Security and certificate operations |
| ⚙️ | Config | Configuration management |
| 📡 | Protocol | Protocol and gRPC operations |
| 🧰 | Utils | Utility functions |
| ❗ | Exception | Exception handling |
| 🛰️ | Telemetry | Monitoring and metrics |
| 💉 | DI | Dependency injection |

## Action Emojis (Second Position)

| Emoji | Action | Description |
|-------|--------|-------------|
| 🚀 | Start | Starting processes or operations |
| 🤝 | Handshake | Handshake operations |
| 🕵️ | Connect | Connection attempts |
| 🕹 | Listen | Listening for connections |
| 📖 | Read | Reading data |
| 📤 | Write | Writing or sending data |
| 📥 | Receive | Receiving data |
| 🔒 | Close | Closing or shutting down |
| 🔍 | Parse | Parsing or validating data |
| 📝 | Build | Building or constructing objects |
| 🔁 | Retry | Retrying operations |
| 🧪 | Test | Testing operations |
| 📜 | Cert | Certificate operations |
| 🔑 | Key | Key operations |
| 🛡️ | Encrypt | Encryption operations |

## Status Emojis (Third Position)

| Emoji | Status | Description |
|-------|--------|-------------|
| ✅ | Success | Operation succeeded |
| ❌ | Error | Operation failed with error |
| 🚫 | Fail | Operation failed without error |
| ⚠️ | Warn | Warning condition |
| 🛑 | Stop | Operation stopped |
| 👍 | Affirm | Positive acknowledgment |
| 👀 | Monitor | Monitoring or observing |
| 💥 | Crash | System crash |
| ⭕ | None | No particular status |
| ⏸️ | Suspend | Operation suspended |
| ▶️ | Resume | Operation resumed |
| ⏳ | Pending | Operation pending |
| 💤 | Idle | System idle |
| 🔄 | Ongoing | Operation in progress |

## Usage Examples

Here are some common logging patterns:

### Server Operations

```python
logger.debug("🛎️🚀✅ Starting plugin server")
logger.debug("🛎️🕹✅ Server listening on transport")
logger.error("🛎️🚀❌ Server startup failed: {e}")
logger.debug("🛎️🔒✅ Server shutdown complete")
```

### Client Operations

```python
logger.debug("🙋🚀✅ Starting plugin client")
logger.debug("🙋🕵️✅ Client connecting to plugin")
logger.error("🙋🕵️❌ Connection failed: {e}")
logger.debug("🙋🔒✅ Client closed successfully")
```

### Handshake Operations

```python
logger.debug("🤝🚀✅ Starting handshake negotiation")
logger.debug("🤝🔍✅ Validating magic cookie")
logger.error("🤝🔍❌ Invalid magic cookie")
logger.debug("🤝📝✅ Handshake response built")
```

### Transport Operations

```python
logger.debug("🌐🚀✅ Starting TCP transport")
logger.debug("🌐🕵️✅ TCP connecting to {endpoint}")
logger.debug("📞🕹✅ Unix socket listening on {path}")
logger.error("📞🕵️❌ Unix socket connection failed: {e}")
```

### Security Operations

```python
logger.debug("🔐🚀✅ Initializing security")
logger.debug("🔐📜✅ Generated self-signed certificate")
logger.debug("🔐🛡️✅ Established secure channel")
logger.error("🔐📜❌ Certificate validation failed: {e}")
```

## Integration with Logger

This emoji system is integrated with Pyvider's logger:

```python
from pyvider.rpcplugin.logger import logger

# Usage in your code
logger.debug("🔌🚀✅ Starting plugin initialization")
logger.info("🔌🤝✅ Plugin handshake completed")
logger.warning("🔌📥⚠️ Received unexpected message")
logger.error("🔌❌ Plugin error: {e}")
```

## Configuring Emoji Logging

To enable or configure the emoji logging system:

```python
# Enable emoji display on startup
os.environ["PLUGIN_SHOW_EMOJI_MATRIX"] = "true"

# Set log level
os.environ["PLUGIN_LOG_LEVEL"] = "DEBUG"
```

You can also disable emoji logging by setting a formatting environment variable, but why would you want to make your logs less fun?

## Display Considerations

The emojis are designed to be displayed in a monospaced font terminal with Unicode support. Most modern terminals support this, but if you're logging to a file or a system that doesn't support Unicode, you might want to use a custom formatter.

## Benefits of Emoji Logging

1. **Visual Scanning**: Quickly identify patterns and issues by scanning for emoji combinations
2. **Contextual Clues**: Understand the domain and operation without reading the entire message
3. **Status Highlighting**: Immediately spot errors (❌) and warnings (⚠️)
4. **Component Identification**: Easily differentiate between client, server, and transport logs
5. **Fun Factor**: Because debugging should be at least a little enjoyable

Remember, logs should be more than just text—they should tell a story. And sometimes that story involves tiny pictures.
