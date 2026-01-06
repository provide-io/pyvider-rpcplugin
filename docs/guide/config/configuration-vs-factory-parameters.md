# Configuration Options vs Factory Parameters

**Reading Time:** ~5 minutes

This guide clarifies the important distinction between **configuration options** and **factory function parameters** in pyvider-rpcplugin.

!!! warning "Common Confusion"
    A common mistake is trying to pass factory function parameters to `configure()` or set them as environment variables. This guide explains the difference and shows the correct usage.

## Quick Reference

| Aspect | Configuration Options | Factory Parameters |
|--------|----------------------|-------------------|
| **Purpose** | Global settings that affect framework behavior | Per-instance settings for specific servers/clients |
| **Scope** | Process-wide (all plugin instances) | Single plugin instance |
| **How to Set** | `configure()`, `rpcplugin_config`, environment vars | Direct function arguments |
| **Examples** | `auto_mtls`, `log_level`, `rate_limit_enabled` | `port`, `host`, `transport`, `command` |

## Configuration Options

Configuration options are **global settings** that affect the entire RPC plugin framework within a process.

### How to Set Configuration Options

There are three ways to set configuration options:

#### 1. Environment Variables (Recommended)

```bash
# Configuration options use PLUGIN_* prefix
export PLUGIN_AUTO_MTLS=true
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
export PLUGIN_SERVER_PORT=8080
```

#### 2. Using configure() Function

```python
from pyvider.rpcplugin import configure

# Explicit parameters (5 total)
configure(
    magic_cookie="my-secret",      # Sets plugin_magic_cookie_value
    protocol_version=1,            # Sets plugin_core_version & plugin_protocol_versions
    transports=["unix", "tcp"],    # Sets plugin_server_transports & plugin_client_transports
    auto_mtls=True,                # Sets plugin_auto_mtls
    handshake_timeout=10.0         # Sets plugin_handshake_timeout
)

# Additional options via **kwargs (automatically prefixed with 'plugin_')
configure(
    log_level="DEBUG",                      # Sets plugin_log_level
    rate_limit_enabled=True,                # Sets plugin_rate_limit_enabled
    rate_limit_requests_per_second=100.0,   # Sets plugin_rate_limit_requests_per_second
    server_port=8080                        # Sets plugin_server_port
)
```

#### 3. Direct Configuration Access

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Access and modify configuration directly
rpcplugin_config.plugin_auto_mtls = True
rpcplugin_config.plugin_log_level = "DEBUG"
rpcplugin_config.plugin_server_port = 8080
```

### Available Configuration Options

All configuration options start with `plugin_` prefix. See the complete list in:
- [Configuration Reference](configuration-reference.md)
- [Client Configuration](configuration-guide.md)
- [Server Configuration](configuration-guide.md)
- [Security Configuration](configuration-guide.md)

## Factory Function Parameters

Factory function parameters are **per-instance settings** that apply to a specific server or client.

### plugin_server() Parameters

```python
def plugin_server(
    protocol: RPCPluginProtocol,    # Required: Protocol implementation
    handler: HandlerT,               # Required: Request handler
    transport: str = "unix",         # Transport type: "unix" or "tcp"
    transport_path: str | None = None,  # Unix socket path
    host: str = "127.0.0.1",        # TCP host address
    port: int = 0,                   # TCP port (0 = auto-assign)
    config: dict[str, Any] | None = None  # Instance config overrides
) -> RPCPluginServer
```

**Example:**

```python
from pyvider.rpcplugin import plugin_server

# Create TCP server on specific port
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",    # Factory parameter
    host="0.0.0.0",     # Factory parameter
    port=8080           # Factory parameter
)
```

### plugin_client() Parameters

```python
def plugin_client(
    command: list[str],              # Required: Command to launch plugin
    config: dict[str, Any] | None = None  # Environment vars for subprocess
) -> RPCPluginClient
```

**Example:**

```python
from pyvider.rpcplugin import plugin_client

# Create client with custom subprocess environment
client = plugin_client(
    command=["python", "plugin.py"],  # Factory parameter
    config={                          # Factory parameter
        "env": {
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "CUSTOM_VAR": "value"
        }
    }
)
```

### plugin_protocol() Parameters

```python
def plugin_protocol(
    protocol_class: type[RPCPluginProtocol] | None = None,
    handler_class: type[RPCPluginHandler] | None = None,
    service_name: str | None = None,
    **kwargs: Any
) -> RPCPluginProtocol
```

**Example:**

```python
from pyvider.rpcplugin import plugin_protocol

# Create basic protocol with custom service name
protocol = plugin_protocol(
    service_name="my.custom.Service"  # Factory parameter
)

# Create custom protocol instance
protocol = plugin_protocol(
    protocol_class=MyCustomProtocol,  # Factory parameter
    custom_option=True                # Passed to protocol constructor
)
```

## Common Mistakes

### ❌ Mistake 1: Passing Factory Parameters to configure()

```python
# WRONG - port is a factory parameter, not a config option
configure(
    port=8080,              # ❌ This doesn't exist
    tcp_port=8080,          # ❌ This doesn't exist
    enable_reflection=True  # ❌ This doesn't exist
)
```

```python
# CORRECT - use factory parameters directly
server = plugin_server(
    protocol=protocol,
    handler=handler,
    port=8080  # ✅ Factory parameter
)
```

### ❌ Mistake 2: Using Environment Variables for Factory Parameters

```bash
# WRONG - These aren't configuration options
export PLUGIN_PORT=8080              # ❌ Doesn't work
export PLUGIN_TCP_PORT=8080          # ❌ Doesn't work
export PLUGIN_ENABLE_REFLECTION=true # ❌ Doesn't work
```

```python
# CORRECT - Use actual config options or factory parameters
# Option 1: Use actual config option
export PLUGIN_SERVER_PORT=8080  # ✅ This exists

# Option 2: Use factory parameter
server = plugin_server(
    protocol=protocol,
    handler=handler,
    port=8080  # ✅ Direct parameter
)
```

### ❌ Mistake 3: Confusing Config Scope

```python
# WRONG - Trying to set per-instance settings globally
configure(
    command=["python", "plugin.py"],  # ❌ This is a client factory parameter
    transport_path="/tmp/my.sock"     # ❌ This is a server factory parameter
)
```

```python
# CORRECT - Use factory parameters for per-instance settings
client = plugin_client(
    command=["python", "plugin.py"]  # ✅ Factory parameter
)

server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport_path="/tmp/my.sock"  # ✅ Factory parameter
)
```

## When to Use What

### Use Configuration Options When:
- Setting process-wide behavior (log level, timeouts)
- Configuring security settings (mTLS, certificates)
- Enabling/disabling features (rate limiting, health checks)
- Setting defaults that apply to all instances

### Use Factory Parameters When:
- Creating a specific server or client instance
- Setting network binding (host, port for TCP)
- Specifying transport details (socket path)
- Providing instance-specific handlers/protocols

## Complete Example

Here's a complete example showing both configuration options and factory parameters used correctly:

```python
import os
from pyvider.rpcplugin import configure, plugin_server, plugin_client

# 1. Set global configuration (affects all instances)
configure(
    auto_mtls=False,                 # Config option: global security setting
    log_level="DEBUG",               # Config option: global logging
    handshake_timeout=30.0,          # Config option: global timeout
    rate_limit_enabled=True,         # Config option: enable feature
    rate_limit_requests_per_second=100.0  # Config option: feature setting
)

# 2. Create server with instance-specific settings
server = plugin_server(
    protocol=my_protocol,            # Factory parameter: required
    handler=my_handler,              # Factory parameter: required
    transport="tcp",                 # Factory parameter: this instance only
    host="0.0.0.0",                  # Factory parameter: this instance only
    port=8080                        # Factory parameter: this instance only
)

# 3. Create client with instance-specific settings
client = plugin_client(
    command=["python", "plugin.py"], # Factory parameter: required
    config={                         # Factory parameter: subprocess env vars
        "env": {
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "MY_API_KEY": os.getenv("MY_API_KEY")
        }
    }
)
```

## Instance Config Overrides

The `config` parameter in factory functions allows **instance-level overrides** of configuration options:

```python
# Global config says rate limiting is disabled
configure(rate_limit_enabled=False)

# But this specific server instance can override it
server = plugin_server(
    protocol=protocol,
    handler=handler,
    config={
        "PLUGIN_RATE_LIMIT_ENABLED": True,           # Override for this instance
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 50  # Instance-specific setting
    }
)
```

This is useful for:
- Running multiple plugin instances with different configs
- Testing with specific configurations
- Per-service rate limits or timeouts

## Summary

| What | How to Set | Example |
|------|-----------|---------|
| **Global config option** | `configure()`, `rpcplugin_config`, or env var | `configure(auto_mtls=True)` or `PLUGIN_AUTO_MTLS=true` |
| **Server instance setting** | `plugin_server()` parameter | `plugin_server(..., port=8080)` |
| **Client instance setting** | `plugin_client()` parameter | `plugin_client(command=[...])` |
| **Instance config override** | `config` dict parameter | `plugin_server(..., config={"PLUGIN_...": value})` |

## See Also

- [Configuration Reference](configuration-reference.md) - Complete list of all configuration options
- [Environment Variables](environment.md) - Environment variable reference
- [API Reference](../../reference/index.md) - Factory function documentation
