---
title: Environment Variables
description: Reference for environment variables used in Pyvider RPC Plugin
---

# Environment Variables Reference

Pyvider RPC Plugin uses environment variables for configuration and communication between the client and server. This reference documents all supported environment variables.

## Core Environment Variables

These variables are essential for the handshake process:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_MAGIC_COOKIE_KEY` | Yes | The name of the environment variable that contains the cookie value | `"BASIC_PLUGIN"` |
| `PLUGIN_MAGIC_COOKIE_VALUE` | Yes | The expected value of the cookie | `"hello"` |
| `PLUGIN_MAGIC_COOKIE` | Yes | The actual value of the cookie (should match `PLUGIN_MAGIC_COOKIE_VALUE`) | `"hello"` |
| `PLUGIN_PROTOCOL_VERSIONS` | Yes | Comma-separated list of protocol versions supported by the client | `"1,2,3,4,5,6,7"` |
| `PLUGIN_TRANSPORTS` | Yes | Comma-separated list of transport mechanisms supported by the client | `"unix,tcp"` |

## Security Environment Variables

These variables control the security aspects:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_AUTO_MTLS` | No | Whether to use automatic mTLS (true/false) | `"true"` |
| `PLUGIN_CLIENT_CERT` | No | PEM-encoded client certificate for mTLS | `"-----BEGIN CERTIFICATE-----\nMII..."` |
| `PLUGIN_CLIENT_KEY` | No | PEM-encoded client private key for mTLS | `"-----BEGIN PRIVATE KEY-----\nMII..."` |
| `PLUGIN_SERVER_CERT` | No | PEM-encoded server certificate for mTLS | `"-----BEGIN CERTIFICATE-----\nMII..."` |
| `PLUGIN_SERVER_KEY` | No | PEM-encoded server private key for mTLS | `"-----BEGIN PRIVATE KEY-----\nMII..."` |

## Logging Environment Variables

These variables control logging behavior:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_LOG_LEVEL` | No | The minimum log level to display (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `"DEBUG"` |
| `PLUGIN_SHOW_EMOJI_MATRIX` | No | Whether to show the emoji matrix at startup (true/false) | `"true"` |

## Transport Environment Variables

These variables configure transport-specific behavior:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_SERVER_ENDPOINT` | No | Default server endpoint for listening | `"127.0.0.1:0"` |
| `PLUGIN_CLIENT_ENDPOINT` | No | Default client endpoint for connection | `"127.0.0.1:12345"` |

## Variable Usage and Precedence

### Server-Side Variables

When a client launches a plugin server, it sets environment variables that the server reads to determine how it should behave. The critical variables are:

1. **Magic Cookie**: The server validates this to ensure it's being launched as a plugin
2. **Protocol Versions**: The server uses this to select a protocol version
3. **Transports**: The server uses this to select a transport mechanism
4. **Client Certificate**: The server uses this for mutual TLS authentication

### Client-Side Variables

The client uses environment variables to configure its own behavior and to pass information to servers:

```python
client = RPCPluginClient(
    command=["python", "plugin.py"],
    config={
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
            "PLUGIN_MAGIC_COOKIE": "hello",
            "PLUGIN_PROTOCOL_VERSIONS": "1,2,3,4,5,6,7",
            "PLUGIN_TRANSPORTS": "unix,tcp",
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_LOG_LEVEL": "DEBUG",
        }
    }
)
```

### Variable Resolution

Variables are resolved in this order of precedence:

1. Variables explicitly set in the client's `config["env"]` dictionary
2. Variables set in the current process's environment
3. Default values from the configuration system

### File-Based Values

Some environment variables can reference files using the `file://` prefix:

```python
config = {
    "env": {
        "PLUGIN_CLIENT_CERT": "file:///path/to/cert.pem",
        "PLUGIN_CLIENT_KEY": "file:///path/to/key.pem"
    }
}
```

This is particularly useful for certificate material that may be stored in files rather than directly in environment variables.

## Best Practices

1. **Security**: Never hardcode sensitive values like certificates or keys
2. **Isolation**: Use separate environment variable sets for different plugins
3. **Defaults**: Provide sensible defaults for optional variables
4. **Validation**: Validate all environment variables before use
5. **Cleanup**: Clear sensitive environment variables when done

## Environment Variable Examples

### Basic Plugin Launch

```python
env = {
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "6",
    "PLUGIN_TRANSPORTS": "unix,tcp"
}
```

### Secure Plugin Launch with mTLS

```python
env = {
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "6",
    "PLUGIN_TRANSPORTS": "unix,tcp",
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_CLIENT_CERT": "file:///path/to/cert.pem",
    "PLUGIN_CLIENT_KEY": "file:///path/to/key.pem"
}
```

### Debug-Mode Plugin Launch

```python
env = {
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "6",
    "PLUGIN_TRANSPORTS": "unix,tcp",
    "PLUGIN_LOG_LEVEL": "DEBUG",
    "PLUGIN_SHOW_EMOJI_MATRIX": "true"
}
```

## Related Topics

- [Handshake Protocol](../concepts/handshake.md): Details on how environment variables are used in the handshake
- [Security Model](../concepts/security.md): Information on security-related environment variables
- [Client Implementation](../guides/client-implementation.md): Guide on using environment variables in clients
