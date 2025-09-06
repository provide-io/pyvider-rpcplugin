# Unix Socket Transport

The `UnixSocketTransport` class provides Unix domain socket communication for the Pyvider RPC Plugin system. It's designed for high-performance local communication with robust path handling and cross-platform compatibility.

## Overview

Unix domain sockets offer the best performance for local plugin communication, providing:
- **High Performance**: No network stack overhead
- **Security**: Filesystem-based permissions
- **Reliability**: Built into the operating system
- **Compatibility**: Works with HashiCorp's Go plugin system

The implementation includes sophisticated path normalization, permission management, and cleanup handling to ensure reliable operation across different environments.

## Quick Start

```python
from pyvider.rpcplugin.transport import UnixSocketTransport

# Server usage
transport = UnixSocketTransport(path="/tmp/my-plugin.sock")
endpoint = await transport.listen()
print(f"Server listening on: {endpoint}")

# Client usage  
client_transport = UnixSocketTransport()
await client_transport.connect("/tmp/my-plugin.sock")

# Cleanup
await transport.close()
```

## Path Handling

### Path Normalization

The transport handles various path formats automatically:

```python
# These are all equivalent:
UnixSocketTransport(path="/tmp/plugin.sock")
UnixSocketTransport(path="unix:/tmp/plugin.sock")
UnixSocketTransport(path="unix://tmp/plugin.sock")

# All normalize to: "/tmp/plugin.sock"
```

### Automatic Path Generation

If no path is specified, an ephemeral path is generated:

```python
transport = UnixSocketTransport()  # No path specified
await transport.listen()
print(transport.endpoint)  # "/tmp/pyvider-abc12345.sock"
```

### Path Format Examples

| Input Format | Normalized Result | Notes |
|-------------|------------------|--------|
| `/tmp/plugin.sock` | `/tmp/plugin.sock` | Absolute path (preferred) |
| `unix:/tmp/plugin.sock` | `/tmp/plugin.sock` | Unix prefix removed |
| `unix://tmp/plugin.sock` | `/tmp/plugin.sock` | Double slash handled |
| `plugin.sock` | `plugin.sock` | Relative path preserved |
| `None` | `/tmp/pyvider-{uuid}.sock` | Auto-generated ephemeral |

## Server Usage

### Basic Server Setup

```python
from pyvider.rpcplugin.transport import UnixSocketTransport

async def setup_unix_server():
    transport = UnixSocketTransport(path="/tmp/my-plugin.sock")
    
    try:
        endpoint = await transport.listen()
        print(f"Server ready at: {endpoint}")
        
        # Server is now accepting connections
        # Your plugin server logic here
        
    finally:
        await transport.close()
```

### Permission Management

The transport automatically sets appropriate permissions:

```python
# Default permissions: 0o660 (owner + group read/write)
transport = UnixSocketTransport(path="/tmp/plugin.sock")
await transport.listen()

# Socket file permissions are set considering umask
# Ensures compatibility between different user/group scenarios
```

### Directory Creation

Parent directories are created automatically:

```python
# This works even if /tmp/plugins/ doesn't exist
transport = UnixSocketTransport(path="/tmp/plugins/my-app/plugin.sock")
await transport.listen()  # Creates directories as needed
```

### Stale Socket Handling

The transport handles stale socket files from previous runs:

```python
# If socket file exists but no process is listening:
transport = UnixSocketTransport(path="/tmp/existing.sock")
await transport.listen()  # Removes stale file and creates new socket

# If socket is actively in use by another process:
# Raises TransportError: "Socket /tmp/existing.sock is already running"
```

## Client Usage

### Basic Connection

```python
from pyvider.rpcplugin.transport import UnixSocketTransport

async def connect_to_plugin():
    transport = UnixSocketTransport()
    
    try:
        await transport.connect("/tmp/my-plugin.sock")
        # Connection established, transport.endpoint is set
        
        # Use the connection for communication
        
    finally:
        await transport.close()
```

### Connection with Retries

The transport includes built-in retry logic for connection:

```python
# Will retry if socket file doesn't exist initially
await transport.connect("/tmp/plugin.sock")  # Retries 3 times with 0.5s delays
```

### Path Validation

The client validates socket files before connection:

```python
# These will raise TransportError:
await transport.connect("/tmp/nonexistent.sock")  # File doesn't exist
await transport.connect("/tmp/regular-file.txt")   # Not a socket file
await transport.connect("/tmp/no-permission.sock") # Permission denied
```

## Error Handling

### Common Error Types

```python
from pyvider.rpcplugin.exception import TransportError

try:
    await transport.listen()
except TransportError as e:
    if "already running" in str(e):
        print("Socket is in use by another process")
    elif "Permission denied" in str(e):
        print("Insufficient permissions for socket path")
    elif "Failed to create directory" in str(e):
        print("Cannot create parent directories")
```

### Server-Side Error Scenarios

**Socket Already in Use**:
```python
# First server
server1 = UnixSocketTransport(path="/tmp/plugin.sock")
await server1.listen()  # Success

# Second server (same path)  
server2 = UnixSocketTransport(path="/tmp/plugin.sock")
await server2.listen()  # TransportError: "Socket is already running"
```

**Permission Issues**:
```python
# Insufficient permissions
transport = UnixSocketTransport(path="/root/plugin.sock")  
await transport.listen()  # TransportError: Permission denied
```

**Directory Creation Failures**:
```python
# Parent directory is read-only
transport = UnixSocketTransport(path="/readonly/plugin.sock")
await transport.listen()  # TransportError: Failed to create directory
```

### Client-Side Error Scenarios

**Socket Not Found**:
```python
await transport.connect("/tmp/missing.sock")  
# TransportError: "Socket /tmp/missing.sock does not exist"
```

**Not a Socket File**:
```python
await transport.connect("/tmp/regular-file.txt")
# TransportError: "Path exists but is not a socket"
```

**Connection Timeout**:
```python
await transport.connect("/tmp/unresponsive.sock")
# TransportError: "Connection to Unix socket timed out"
```

## Advanced Usage

### Custom Path Generation

```python
import tempfile
import uuid

class CustomUnixTransport(UnixSocketTransport):
    def __attrs_post_init__(self):
        if not self.path:
            # Custom ephemeral path logic
            self.path = os.path.join(
                tempfile.gettempdir(),
                "myapp",
                f"plugin-{uuid.uuid4().hex[:8]}.sock"
            )
        super().__attrs_post_init__()
```

### Connection Monitoring

```python
class MonitoredUnixTransport(UnixSocketTransport):
    async def _handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        logger.info(f"New client connected: {peer}")
        
        try:
            await super()._handle_client(reader, writer)
        finally:
            logger.info(f"Client disconnected: {peer}")
```

### Custom Cleanup

```python
class SafeCleanupTransport(UnixSocketTransport):
    async def close(self):
        # Custom pre-cleanup logic
        await self.save_state()
        
        try:
            await super().close()
        except Exception as e:
            # Custom error handling
            await self.emergency_cleanup()
            raise
```

## Security Considerations

### File System Permissions

The transport uses secure default permissions:

```bash
# Created socket permissions (considering umask)
-rw-rw---- 1 user group 0 /tmp/plugin.sock  # 0o660 base permissions
```

### Access Control Recommendations

**Development Environment**:
```python
# Permissive for easy testing
transport = UnixSocketTransport(path="/tmp/dev-plugin.sock")
# Uses default 0o660 permissions
```

**Production Environment**:
```python
# More restrictive - consider custom permissions
transport = UnixSocketTransport(path="/var/run/myapp/plugin.sock")
# Ensure proper directory ownership and permissions
```

### Path Security

**Safe Path Patterns**:
```python
# Use application-specific directories
"/var/run/myapp/plugin.sock"      # System service
"/tmp/myapp-{user}/plugin.sock"   # User-specific
"~/.local/share/myapp/plugin.sock" # User data directory
```

**Avoid These Patterns**:
```python
# Too generic - potential conflicts
"/tmp/plugin.sock"

# Predictable names - security risk  
"/tmp/plugin-123.sock"

# World-writable directories
"/var/tmp/plugin.sock"
```

## Performance Optimization

### Connection Pooling

For high-traffic scenarios, implement connection pooling:

```python
class PooledUnixTransport(UnixSocketTransport):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_pool = asyncio.Queue(maxsize=10)
    
    async def get_connection(self):
        try:
            return self.connection_pool.get_nowait()
        except asyncio.QueueEmpty:
            # Create new connection
            transport = UnixSocketTransport()
            await transport.connect(self.endpoint)
            return transport
    
    async def return_connection(self, conn):
        try:
            self.connection_pool.put_nowait(conn)
        except asyncio.QueueFull:
            await conn.close()
```

### Buffer Size Tuning

For high-throughput applications:

```python
# Custom buffer sizes in connection handling
class HighThroughputTransport(UnixSocketTransport):
    async def connect(self, endpoint: str) -> None:
        # Connect with larger buffers
        reader, writer = await asyncio.open_unix_connection(
            endpoint, 
            limit=64 * 1024  # 64KB buffer instead of default 8KB
        )
        self._reader, self._writer = reader, writer
        self.endpoint = endpoint
```

## Troubleshooting

### Common Issues

**Socket File Permissions**:
```bash
# Check socket file
ls -la /tmp/plugin.sock
srw-rw---- 1 user group 0 Oct 15 10:30 /tmp/plugin.sock

# Fix permissions if needed
chmod 660 /tmp/plugin.sock
```

**Stale Socket Detection**:
```bash
# Test if socket is actually listening
echo "test" | nc -U /tmp/plugin.sock

# Or use netstat/ss
ss -x | grep plugin.sock
```

**Directory Permissions**:
```bash
# Check parent directory
ls -ld /tmp/plugins/
drwxrwxr-x 2 user group 4096 Oct 15 10:30 /tmp/plugins/

# Create with proper permissions
mkdir -p /tmp/plugins
chmod 755 /tmp/plugins
```

### Debug Logging

Enable detailed logging for troubleshooting:

```python
import logging
logging.getLogger("pyvider.rpcplugin.transport.unix").setLevel(logging.DEBUG)

transport = UnixSocketTransport(path="/tmp/debug.sock")
await transport.listen()  # Verbose logging output
```

### Testing Socket Connectivity

```python
import asyncio
import os
import stat

async def test_unix_socket(path: str):
    """Test Unix socket connectivity and properties."""
    
    # Check if file exists
    if not os.path.exists(path):
        print(f"❌ Socket file does not exist: {path}")
        return False
    
    # Check if it's a socket
    mode = os.stat(path).st_mode
    if not stat.S_ISSOCK(mode):
        print(f"❌ Path exists but is not a socket: {path}")
        return False
    
    # Test connection
    try:
        reader, writer = await asyncio.open_unix_connection(path)
        writer.close()
        await writer.wait_closed()
        print(f"✅ Socket is accessible: {path}")
        return True
    except Exception as e:
        print(f"❌ Cannot connect to socket: {e}")
        return False

# Usage
await test_unix_socket("/tmp/plugin.sock")
```

## Class Reference

::: pyvider.rpcplugin.transport.unix.UnixSocketTransport

## Related Components

- [Base Transport](base.md) - Abstract transport interface
- [TCP Socket Transport](tcp.md) - Network communication alternative
- [Server API](../server/server.md) - Using Unix sockets in servers
- [Client API](../client/client.md) - Using Unix sockets in clients
- [Factory Functions](../factories.md) - Creating Unix socket transports