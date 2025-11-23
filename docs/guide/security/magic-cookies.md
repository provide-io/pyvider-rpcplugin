# Magic Cookies

Lightweight plugin authentication using cryptographically secure random tokens, providing strong security for local process communication without certificate overhead.

## Overview

Magic cookies are secure random tokens that authenticate plugin connections. They offer a simpler alternative to certificates while maintaining robust security for process-to-process communication.

### Key Benefits

- **Lightweight Security**: No PKI infrastructure required
- **Fast Authentication**: Minimal overhead compared to certificates
- **Process Isolation**: Each plugin gets unique authentication tokens
- **Automatic Generation**: Cryptographically secure random generation
- **Environment Integration**: Seamless integration with configuration management

### Quick Start

```python
from pyvider.rpcplugin import plugin_server, plugin_client
from pyvider.rpcplugin.security import MagicCookie

async def magic_cookie_example():
    """Basic magic cookie authentication."""

    # Generate secure magic cookie
    cookie = MagicCookie.generate()

    # Server with authentication
    server = plugin_server(
        services=[MyService()],
        magic_cookie=cookie.value,
        require_magic_cookie=True
    )

    # Client with matching cookie
    async with plugin_client(
        command=["python", "plugin.py"],
        magic_cookie=cookie.value
    ) as client:
        result = await client.service.secure_method()
        print(f"✅ Authenticated: {result}")
```

## Core Concepts

### 1. **Cookie Generation**

Magic cookies are generated using cryptographically secure random number generators with sufficient entropy to prevent prediction or brute force attacks.

```python
from pyvider.rpcplugin.security import MagicCookie

# Standard generation (256 bits of entropy)
cookie = MagicCookie.generate()

# Custom length
cookie = MagicCookie.generate(length=64)  # 512 bits

# From environment
cookie = MagicCookie.from_env("PLUGIN_MAGIC_COOKIE")
```

### 2. **Server Authentication**

Servers validate magic cookies on every connection attempt, rejecting unauthorized clients immediately.

```python
server = plugin_server(
    services=[MyService()],
    magic_cookie=cookie.value,
    require_magic_cookie=True,        # Reject without cookie
    cookie_timeout=300                # Cookie expires after 5 minutes
)
```

### 3. **Client Authentication**

Clients must provide the correct magic cookie to establish connections.

```python
async with plugin_client(
    command=["python", "plugin.py"],
    magic_cookie=cookie.value,
    cookie_validation=True            # Validate cookie format
) as client:
    # All requests authenticated with cookie
    await client.service.protected_method()
```

## Authentication Patterns

### Development Environment

```python
# Fixed cookie for development
cookie = MagicCookie.from_string("dev-magic-cookie-12345")

server = plugin_server(
    magic_cookie=cookie.value,
    require_magic_cookie=False,       # Optional in dev
    cookie_timeout=3600               # 1 hour timeout
)
```

### Production Environment

```python
# Generated cookie with strict validation
cookie = MagicCookie.generate(length=64)

server = plugin_server(
    magic_cookie=cookie.value,
    require_magic_cookie=True,        # Always required
    cookie_timeout=300,               # 5 minute timeout
    validate_cookie_entropy=True      # Ensure sufficient randomness
)
```

### Multi-Plugin Environment

```python
# Each plugin gets unique cookie
plugin_cookies = {
    "data-processor": MagicCookie.generate(),
    "file-handler": MagicCookie.generate(),
    "notification-service": MagicCookie.generate()
}

# Start servers with different cookies
for plugin_name, cookie in plugin_cookies.items():
    server = plugin_server(
        services=[get_plugin_service(plugin_name)],
        magic_cookie=cookie.value,
        plugin_id=plugin_name
    )
```

## Configuration Management

### Environment Variables

```bash
# Single plugin
export PLUGIN_MAGIC_COOKIE="$(python -c 'from pyvider.rpcplugin.security import MagicCookie; print(MagicCookie.generate().value)')"

# Multiple plugins  
export PLUGIN_DATA_MAGIC_COOKIE="<generated-cookie-1>"
export PLUGIN_FILE_MAGIC_COOKIE="<generated-cookie-2>"
export PLUGIN_NOTIFY_MAGIC_COOKIE="<generated-cookie-3>"
```

### Configuration Files

```yaml
# config.yaml
plugins:
  data_processor:
    magic_cookie: "${PLUGIN_DATA_MAGIC_COOKIE}"
    require_cookie: true
    timeout: 300

  file_handler:
    magic_cookie: "${PLUGIN_FILE_MAGIC_COOKIE}"  
    require_cookie: true
    timeout: 600
```

### Programmatic Configuration

```python
from provide.foundation import config

# Load from configuration
plugin_config = config.get_config()
cookie = MagicCookie.from_config(
    plugin_config.magic_cookie,
    fallback_generate=True  # Generate if not configured
)
```

## Error Handling

```python
from pyvider.rpcplugin.exception import AuthenticationError, MagicCookieError

async def secure_plugin_connection():
    try:
        async with plugin_client(magic_cookie=cookie.value) as client:
            return await client.service.protected_method()

    except AuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
        # Handle invalid/missing cookie

    except MagicCookieError as e:
        logger.error(f"Cookie error: {e}")
        # Handle malformed cookie

    except TimeoutError:
        logger.error("Cookie validation timed out")
        # Handle timeout scenarios
```

## Security Considerations

### Cookie Security

- **Generate Fresh**: Use new cookies for each session
- **Sufficient Entropy**: Minimum 256 bits of randomness
- **Secure Storage**: Protect cookies like passwords
- **Limited Lifetime**: Set reasonable expiration times
- **No Logging**: Never log cookie values

### Transport Security

- **Local Only**: Magic cookies designed for local IPC
- **Process Isolation**: Each plugin process gets unique cookies
- **Memory Protection**: Clear cookies from memory after use
- **Environment Cleanup**: Remove cookie environment variables

## Best Practices

1. **Rotate Regularly**: Generate new cookies periodically
1. **Validate Format**: Check cookie format and entropy
1. **Monitor Usage**: Log authentication attempts and failures
1. **Timeout Appropriately**: Balance security with usability
1. **Combine with mTLS**: Use both for network communication
1. **Test Authentication**: Verify authentication works correctly

## Troubleshooting

### Common Issues

#### Authentication Failures

```python
# Check cookie format
if not cookie.is_valid_format():
    logger.error("Invalid cookie format")

# Verify cookie matches
if server_cookie.value != client_cookie.value:
    logger.error("Cookie mismatch")
```

#### Environment Problems

```bash
# Verify cookie is set
echo $PLUGIN_MAGIC_COOKIE

# Check cookie length
python -c "import os; print(len(os.environ.get('PLUGIN_MAGIC_COOKIE', '')))"
```

## Integration Examples

### With Foundation Config

```python
from provide.foundation import config
from pyvider.rpcplugin.security import MagicCookie

# Load cookie from Foundation configuration
app_config = config.get_config()
cookie = MagicCookie.from_config(
    app_config.plugin_magic_cookie,
    auto_generate=True
)
```

### With Process Isolation

```python
# Combine with process isolation
isolator = ProcessIsolator(
    sandbox_config=SandboxConfig(
        magic_cookie=cookie.value,
        require_authentication=True
    )
)
```

## Next Steps

- **[mTLS Configuration](mtls/)** - Certificate-based authentication for network communication
- **[Process Isolation](process-isolation/)** - Secure plugin sandboxing
- **[Certificate Management](certificates/)** - PKI for advanced security scenarios
- **[Security Overview](index/)** - Complete security architecture guide