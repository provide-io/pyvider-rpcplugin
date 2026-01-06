# Transports

Pyvider RPC Plugin supports multiple transport layers for communication between host applications and plugin processes. Each transport provides different trade-offs between performance, security, and platform compatibility.

## Transport Types

### Unix Domain Sockets (UDS)
*Recommended for local communication*

Unix Domain Sockets provide the highest performance for Inter-Process Communication (IPC) on the same machine.

**Advantages:** Maximum performance, lower latency, file system permissions, resource efficient
**Limitations:** Same host only, path length limits, not available on Windows
**Best For:** High-performance local plugins, security-sensitive applications, production systems

### TCP Sockets
*Universal compatibility*

TCP sockets enable network communication, allowing plugins to run on different machines.

**Advantages:** Network communication, universal platform support, standard protocol
**Limitations:** Higher overhead, port management complexity, additional security considerations
**Best For:** Distributed architectures, Windows environments, cross-machine communication

## Transport Selection

### Automatic Negotiation

Pyvider RPC Plugin automatically selects the best available transport, preferring Unix sockets when available, falling back to TCP when needed.

### Configuration

```python
from pyvider.rpcplugin import configure

# View available transports
from pyvider.rpcplugin.config import rpcplugin_config
transports = rpcplugin_config.plugin_server_transports

# Configure transport preferences
configure(transports=["tcp"])  # TCP only
configure(transports=["unix"])  # Unix only  
configure(transports=["unix", "tcp"])  # Both, prefer unix
```

### Environment Variables

```bash
# Transport selection
export PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'
export PLUGIN_TCP_PORT="8080" 
export PLUGIN_UNIX_SOCKET_PATH="/tmp/my-plugin.sock"
```

## Implementation Details

### Basic Transport Usage

```python
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport
from pyvider.rpcplugin import plugin_server

# Unix socket transport (automatic path generation)
unix_transport = UnixSocketTransport()

# TCP transport (automatic port assignment)  
tcp_transport = TCPSocketTransport(host="127.0.0.1", port=0)

# Use with plugin server
server = plugin_server(protocol=my_protocol, handler=my_handler, transport=unix_transport)
```

**Key Features:**
- Automatic cleanup and collision detection
- Configurable permissions and binding
- Graceful error handling and fallbacks

## Platform Considerations

**Linux & macOS:** Full support for both Unix and TCP transports
```python
configure(transports=["unix", "tcp"])  # Unix preferred, TCP fallback
```

**Windows:** TCP transport only (Unix sockets are not supported)
```python
configure(transports=["tcp"])  # TCP only
```

## Performance Characteristics

| Transport | Throughput | Latency | CPU Usage |
|-----------|------------|---------|-----------|
| Unix Socket | **~45,000 msg/sec** | **~0.02ms** | Low |
| TCP (localhost) | ~35,000 msg/sec | ~0.03ms | Medium |
| TCP (network) | Varies by network | Varies by network | Medium |

### Optimization

```python
# Unix socket optimization
configure(unix_socket_buffer_size=65536, unix_socket_permissions=0o600)

# TCP optimization
configure(tcp_nodelay=True, tcp_buffer_size=65536, tcp_host="127.0.0.1")
```

## Security Considerations

### Unix Socket Security
- File permissions and secure paths
- Automatic cleanup on shutdown
- Process credential validation

### TCP Socket Security  
- Localhost binding (127.0.0.1)
- Non-privileged ports (>1024)
- mTLS for authentication

```python
# Secure configurations
configure(
    unix_socket_path="/var/run/myapp/plugin.sock",
    unix_socket_permissions=0o600,
    tcp_host="127.0.0.1",
    auto_mtls=True
)
```

## Usage Patterns

### Development vs Production

```python
# Development: Cross-platform compatibility
configure(transports=["tcp"], tcp_host="127.0.0.1", log_transport_details=True)

# Production: Maximum performance and security  
configure(transports=["unix"], unix_socket_path="/var/run/myapp/plugin.sock", 
         unix_socket_permissions=0o600)

# Graceful fallback
configure(transports=["unix", "tcp"])  # Try unix first, fallback to TCP
```

### Error Handling

```python
from pyvider.rpcplugin.exceptions import TransportError

try:
    server = plugin_server(protocol=protocol, handler=handler)
    await server.serve()
except TransportError as e:
    logger.error(f"Transport failed: {e}")
    # Implement fallback or recovery
```

## Troubleshooting

### Unix Socket Issues
**Permission Denied:** Check file permissions with `ls -la`, fix with `chmod 600`
**Address in Use:** Find processes with `lsof /path/to/socket.sock`, remove stale files

### TCP Issues  
**Port in Use:** Check with `netstat -tulpn | grep :port` or `lsof -i :port`, use `tcp_port=0` for auto-assignment
**Connection Refused:** Verify server is listening, check firewall settings

### Common Solutions
```python
# Enable detailed logging
configure(log_transport_details=True, log_level="DEBUG")

# Use automatic port/path assignment
configure(tcp_port=0, unix_socket_path=None)  # Auto-generate paths
```

## Transport Architecture

### Transport Interface

All transports implement the `RPCPluginTransport` interface:

```python
from abc import ABC, abstractmethod

class RPCPluginTransport(ABC):
    """Base interface for all plugin transports."""
    
    @abstractmethod
    async def start_server(self, host: str, port: int) -> dict:
        """Start server and return connection details."""
        pass
    
    @abstractmethod
    async def connect_client(self, connection_info: dict) -> tuple:
        """Connect client and return reader/writer streams."""
        pass
    
    @abstractmethod
    async def close(self):
        """Clean up transport resources."""
        pass
```

### Dynamic Selection

The transport manager automatically scores and selects optimal transports based on:
- **Security requirements** (Unix > mTLS > TCP)
- **Network needs** (TCP required for remote communication)  
- **Performance priority** (Unix fastest, mTLS has overhead)

Available transports are scored and the highest-scoring option is selected automatically.

## Advanced Features

### Enhanced Security
- **Process validation** for Unix sockets using peer credentials
- **mTLS support** for TCP with certificate validation  
- **Connection pooling** for high-throughput scenarios

### Performance Optimization
```python
# High-performance configurations
configure(
    unix_socket_buffer_size=1024*1024,  # 1MB buffers
    tcp_nodelay=True,                   # Disable Nagle algorithm
    connection_pool_size=50             # Pool connections for throughput
)
```

### Monitoring
Built-in metrics track connection counts, latency, throughput, and error rates for transport performance analysis.

## Implementation Resources

### Server Transport Configuration
- **[Server Transport Configuration](../server/transports.md)** - Advanced transport configuration for production servers, including performance optimization, mTLS setup, and monitoring
- **[Server Basic Setup](../server/basic-setup.md)** - How to configure transports in server implementations

### Configuration Integration
- **[Configuration Guide](../config/index.md)** - Environment-driven transport configuration with examples for different deployment scenarios
- **[Production Configuration](../config/advanced.md)** - Production transport configuration patterns

### Documentation
- **[Configuration Reference](../config/configuration-reference.md)** - Transport configuration options
- **[API Reference](../../reference/index.md)** - Auto-generated API documentation

## Related Concepts

- **[Security Model](security.md)** - How transports integrate with security layers including mTLS and authentication
- **[Handshake Process](architecture-and-handshake.md)** - Connection establishment details across different transports

## Examples and Learning Path

- **[Echo Service Examples](../../examples/echo-example.md)** - Transport usage in complete working service examples
- **[Basic Server Example](../../examples/quick-start.md)** - Simple transport configuration examples
