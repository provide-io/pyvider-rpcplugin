# TCP Socket Transport

The `TCPSocketTransport` class provides TCP/IP network communication for the Pyvider RPC Plugin system. It enables remote plugin communication and provides Windows compatibility where Unix sockets aren't available.

## Overview

TCP socket transport offers:
- **Remote Communication**: Connect to plugins across the network
- **Windows Compatibility**: Full support on Windows systems
- **Port Management**: Automatic port assignment and management  
- **Standard Protocol**: Uses familiar TCP/IP networking
- **Firewall Friendly**: Standard TCP ports work with existing network infrastructure

The implementation provides robust connection handling, port management, and error recovery for reliable network communication.

## Quick Start

```python
from pyvider.rpcplugin.transport import TCPSocketTransport

# Server usage with automatic port assignment
transport = TCPSocketTransport(host="127.0.0.1", port=0)
endpoint = await transport.listen()
print(f"Server listening on: {endpoint}")  # "127.0.0.1:54321"

# Server with specific port
transport = TCPSocketTransport(host="0.0.0.0", port=8080)
endpoint = await transport.listen()
print(f"Server listening on: {endpoint}")  # "0.0.0.0:8080"

# Client usage
client_transport = TCPSocketTransport()
await client_transport.connect("127.0.0.1:8080")

# Cleanup
await transport.close()
```

## Server Usage

### Automatic Port Assignment

For development and testing, use automatic port assignment:

```python
from pyvider.rpcplugin.transport import TCPSocketTransport

async def setup_tcp_server():
    # Port 0 means "assign any available port"
    transport = TCPSocketTransport(host="127.0.0.1", port=0)
    
    endpoint = await transport.listen()
    print(f"Server assigned port: {endpoint}")
    
    # The actual port is now available
    print(f"Listening on port: {transport.port}")
    
    return transport
```

### Specific Port Assignment

For production deployments, specify the exact port:

```python
async def production_server():
    transport = TCPSocketTransport(host="0.0.0.0", port=8080)
    
    try:
        endpoint = await transport.listen()
        print(f"Production server ready: {endpoint}")
        
        # Server logic here
        await serve_forever()
        
    except TransportError as e:
        if "already in use" in str(e):
            print("Port 8080 is already in use")
        else:
            print(f"Server failed to start: {e}")
    finally:
        await transport.close()
```

### Host Configuration Options

| Host Value | Description | Use Case |
|------------|------------|----------|
| `127.0.0.1` | Localhost only | Local development, security |
| `0.0.0.0` | All interfaces | Production, remote access |
| `192.168.1.100` | Specific IP | Multi-homed systems |
| `::1` | IPv6 localhost | IPv6-only environments |

```python
# Localhost only (secure)
transport = TCPSocketTransport(host="127.0.0.1", port=8080)

# All interfaces (accessible remotely)
transport = TCPSocketTransport(host="0.0.0.0", port=8080)

# Specific interface
transport = TCPSocketTransport(host="192.168.1.100", port=8080)
```

### Port Range Management

For services that need multiple ports:

```python
async def multi_port_setup():
    base_port = 8000
    transports = []
    
    for i in range(5):  # Start 5 servers
        transport = TCPSocketTransport(
            host="127.0.0.1", 
            port=base_port + i
        )
        try:
            endpoint = await transport.listen()
            transports.append(transport)
            print(f"Server {i} on {endpoint}")
        except TransportError:
            print(f"Port {base_port + i} unavailable, trying next...")
            continue
    
    return transports
```

## Client Usage

### Basic Connection

```python
from pyvider.rpcplugin.transport import TCPSocketTransport

async def connect_to_server():
    transport = TCPSocketTransport()
    
    try:
        await transport.connect("127.0.0.1:8080")
        print(f"Connected to: {transport.endpoint}")
        
        # Use the connection
        
    except TransportError as e:
        print(f"Connection failed: {e}")
    finally:
        await transport.close()
```

### Connection with Timeout

```python
import asyncio

async def connect_with_timeout():
    transport = TCPSocketTransport()
    
    try:
        # Connection has built-in timeout, but you can add outer timeout
        await asyncio.wait_for(
            transport.connect("remote-server.com:8080"),
            timeout=10.0
        )
        print("Connected successfully")
        
    except asyncio.TimeoutError:
        print("Connection timed out")
    except TransportError as e:
        print(f"Connection error: {e}")
```

### Endpoint Validation

The transport validates endpoint format:

```python
# Valid formats
await transport.connect("127.0.0.1:8080")     # IPv4
await transport.connect("localhost:8080")      # Hostname  
await transport.connect("[::1]:8080")          # IPv6 (with brackets)

# Invalid formats (will raise TransportError)
await transport.connect("127.0.0.1")          # Missing port
await transport.connect(":8080")              # Missing host
await transport.connect("127.0.0.1:abc")      # Non-numeric port
```

## Network Configuration

### Firewall Considerations

**Development Environment**:
```python
# Use localhost to avoid firewall issues
transport = TCPSocketTransport(host="127.0.0.1", port=0)
```

**Production Environment**:
```python
# Configure firewall rules for your specific port
transport = TCPSocketTransport(host="0.0.0.0", port=8080)

# Firewall rule example (Linux):
# sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### Docker and Container Usage

```python
# In Docker container
transport = TCPSocketTransport(host="0.0.0.0", port=8080)

# Docker run command:
# docker run -p 8080:8080 my-plugin-image
```

### Load Balancer Integration

```python
# Health check endpoint
async def setup_with_health_check():
    transport = TCPSocketTransport(host="0.0.0.0", port=8080)
    await transport.listen()
    
    # Load balancer can check TCP connectivity to port 8080
    return transport
```

## Error Handling

### Port Conflict Resolution

```python
from pyvider.rpcplugin.exception import TransportError

async def find_available_port(preferred_port: int = 8080):
    """Find an available port starting from preferred port."""
    
    for port in range(preferred_port, preferred_port + 100):
        transport = TCPSocketTransport(host="127.0.0.1", port=port)
        try:
            endpoint = await transport.listen()
            print(f"Found available port: {port}")
            return transport
        except TransportError as e:
            if "already in use" in str(e):
                continue  # Try next port
            else:
                raise  # Other error, don't retry
    
    raise TransportError("No available ports in range")
```

### Network Connectivity Issues

```python
async def robust_connection(host: str, port: int, max_retries: int = 3):
    """Connect with retry logic for network issues."""
    
    transport = TCPSocketTransport()
    last_error = None
    
    for attempt in range(max_retries):
        try:
            await transport.connect(f"{host}:{port}")
            print(f"Connected on attempt {attempt + 1}")
            return transport
            
        except TransportError as e:
            last_error = e
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"Attempt {attempt + 1} failed, retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
            else:
                print(f"All {max_retries} attempts failed")
    
    raise last_error
```

### DNS Resolution Issues

```python
import socket

async def resolve_and_connect(hostname: str, port: int):
    """Resolve hostname before connection attempt."""
    
    try:
        # Resolve hostname first
        ip_address = socket.gethostbyname(hostname)
        print(f"Resolved {hostname} to {ip_address}")
        
        # Connect using IP address
        transport = TCPSocketTransport()
        await transport.connect(f"{ip_address}:{port}")
        
        return transport
        
    except socket.gaierror as e:
        raise TransportError(f"DNS resolution failed for {hostname}: {e}")
```

## Security Considerations

### Network Security

**Local Development**:
```python
# Bind to localhost only for security
transport = TCPSocketTransport(host="127.0.0.1", port=8080)
# Only accessible from the same machine
```

**Production Deployment**:
```python
# Use specific interface when possible
transport = TCPSocketTransport(host="192.168.1.100", port=8080)  
# Not accessible from external networks
```

### TLS/SSL Integration

While the transport doesn't handle TLS directly, gRPC provides TLS support:

```python
# Transport provides the connection
transport = TCPSocketTransport(host="0.0.0.0", port=443)
await transport.listen()

# gRPC handles TLS on top of the TCP transport
# Configure TLS in your gRPC server/client setup
```

### Port Security Guidelines

**Reserved Ports**: Avoid system reserved ports (0-1023):
```python
# Good: Use high-numbered ports
transport = TCPSocketTransport(host="127.0.0.1", port=8080)

# Avoid: System reserved ports
# transport = TCPSocketTransport(host="127.0.0.1", port=80)  # Requires root
```

**Port Scanning Protection**:
```python
# Use non-standard ports to reduce scanning
transport = TCPSocketTransport(host="127.0.0.1", port=54321)

# Consider port randomization for temporary services
import random
random_port = random.randint(10000, 65535)
transport = TCPSocketTransport(host="127.0.0.1", port=random_port)
```

## Advanced Usage

### Connection Pooling

```python
class TCPConnectionPool:
    def __init__(self, host: str, port: int, pool_size: int = 5):
        self.host = host
        self.port = port
        self.pool = asyncio.Queue(maxsize=pool_size)
        self.pool_size = pool_size
    
    async def get_connection(self):
        try:
            return await self.pool.get_nowait()
        except asyncio.QueueEmpty:
            # Create new connection
            transport = TCPSocketTransport()
            await transport.connect(f"{self.host}:{self.port}")
            return transport
    
    async def return_connection(self, transport):
        try:
            await self.pool.put(transport)
        except asyncio.QueueFull:
            await transport.close()
    
    async def close_all(self):
        while not self.pool.empty():
            transport = await self.pool.get()
            await transport.close()
```

### Multi-Interface Server

```python
async def multi_interface_server():
    """Start server on multiple network interfaces."""
    
    interfaces = [
        ("127.0.0.1", 8080),  # Localhost
        ("192.168.1.100", 8080),  # LAN interface
        ("10.0.0.100", 8080),  # VPN interface
    ]
    
    servers = []
    for host, port in interfaces:
        try:
            transport = TCPSocketTransport(host=host, port=port)
            endpoint = await transport.listen()
            servers.append(transport)
            print(f"Server listening on {endpoint}")
        except TransportError as e:
            print(f"Failed to bind to {host}:{port} - {e}")
    
    return servers
```

### Connection Health Monitoring

```python
class HealthMonitoredTCP(TCPSocketTransport):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_count = 0
        self.last_activity = time.time()
    
    async def connect(self, endpoint: str) -> None:
        await super().connect(endpoint)
        self.connection_count += 1
        self.last_activity = time.time()
        print(f"TCP connection #{self.connection_count} established")
    
    async def close(self) -> None:
        await super().close()
        self.last_activity = time.time()
        print(f"TCP connection closed after {self.connection_count} connections")
    
    def get_health_stats(self):
        return {
            "connection_count": self.connection_count,
            "last_activity": self.last_activity,
            "seconds_since_activity": time.time() - self.last_activity,
        }
```

## Performance Optimization

### TCP Socket Options

```python
import socket

class OptimizedTCPTransport(TCPSocketTransport):
    async def listen(self) -> str:
        # Get the underlying socket for optimization
        endpoint = await super().listen()
        
        if self._server:
            # Access the underlying socket (implementation-specific)
            for sock in self._server.sockets:
                # Enable keep-alive
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                # Reduce TIME_WAIT
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Optimize for low latency
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        return endpoint
```

### Buffer Size Optimization

```python
class HighThroughputTCP(TCPSocketTransport):
    async def connect(self, endpoint: str) -> None:
        """Connect with optimized buffer sizes."""
        if not is_valid_tcp_endpoint(endpoint):
            raise TransportError(f"Invalid TCP endpoint format: {endpoint}")
        
        host, port = endpoint.split(":")
        
        try:
            # Open connection with larger buffers
            reader, writer = await asyncio.open_connection(
                host=host,
                port=int(port),
                limit=128 * 1024  # 128KB buffer
            )
            self._reader = reader
            self._writer = writer
            self.endpoint = endpoint
            
        except Exception as e:
            raise TransportError(f"Failed to connect to {endpoint}: {e}") from e
```

## Troubleshooting

### Port Availability Check

```bash
# Check if port is in use
netstat -tulpn | grep :8080
ss -tulpn | grep :8080

# Test connectivity
telnet localhost 8080
nc -zv localhost 8080
```

### Connection Testing

```python
import asyncio
import socket

async def test_tcp_connectivity(host: str, port: int):
    """Test TCP connectivity without transport layer."""
    
    try:
        # Low-level socket test
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✅ TCP connection to {host}:{port} successful")
            return True
        else:
            print(f"❌ TCP connection to {host}:{port} failed (code: {result})")
            return False
            
    except Exception as e:
        print(f"❌ TCP test error: {e}")
        return False

# Usage
await test_tcp_connectivity("127.0.0.1", 8080)
```

### Network Diagnostics

```python
import subprocess
import platform

def network_diagnostics(host: str, port: int):
    """Run network diagnostics for troubleshooting."""
    
    print(f"Network diagnostics for {host}:{port}")
    
    # Ping test
    if platform.system().lower() == "windows":
        ping_cmd = ["ping", "-n", "4", host]
    else:
        ping_cmd = ["ping", "-c", "4", host]
    
    try:
        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        print(f"Ping result: {'Success' if result.returncode == 0 else 'Failed'}")
    except Exception as e:
        print(f"Ping failed: {e}")
    
    # Traceroute (if remote host)
    if host not in ["127.0.0.1", "localhost"]:
        try:
            if platform.system().lower() == "windows":
                trace_cmd = ["tracert", host]
            else:
                trace_cmd = ["traceroute", host]
            
            result = subprocess.run(trace_cmd, capture_output=True, text=True)
            print("Traceroute completed")
        except Exception as e:
            print(f"Traceroute failed: {e}")
```

## Class Reference

::: pyvider.rpcplugin.transport.tcp.TCPSocketTransport

## Related Components

- [Base Transport](base.md) - Abstract transport interface
- [Unix Socket Transport](unix.md) - Local communication alternative
- [Server API](../server/server.md) - Using TCP sockets in servers
- [Client API](../client/client.md) - Using TCP sockets in clients  
- [Factory Functions](../factories.md) - Creating TCP socket transports