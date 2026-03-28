# Transport Configuration

Optimize transport layers for your plugin servers with Unix sockets, TCP, and mTLS configurations for different deployment scenarios.

!!! info "Configuration vs Factory Parameters" Transport-specific settings like `port`, `host`, and `transport_path` are **factory function parameters**, NOT configuration options.

```
- ✅ Use: `plugin_server(port=8080, host="0.0.0.0")`
- ❌ Don't: `configure(tcp_port=8080, tcp_host="0.0.0.0")`

    See [Config vs Factory Parameters](../config/configuration-vs-factory-parameters.md) for complete details.

## Transport Selection

### Automatic Selection

The framework automatically selects the best transport based on your configuration:

```python
from pyvider.rpcplugin import configure, plugin_server

# Auto-select transport (Unix preferred, TCP fallback)
configure(transports=["unix", "tcp"])

server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Manual Transport Configuration

```python
from pyvider.rpcplugin import configure, plugin_server

# Unix socket only (highest performance)
# Set global transport preference
configure(transports=["unix"])

# Create server with specific socket path
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="unix",
    transport_path="/tmp/my-plugin.sock"  # Factory parameter
)

# TCP only (cross-platform compatibility)
# Set global transport preference
configure(transports=["tcp"])

# Create server with specific host/port
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    host="127.0.0.1",  # Factory parameter
    port=8080          # Factory parameter
)

# TCP with mTLS (secure network communication)
configure(
    transports=["tcp"],
    auto_mtls=True,
    server_cert="file:///etc/ssl/server.pem",
    server_key="file:///etc/ssl/server.key",
    client_cert="file:///etc/ssl/client.pem"
)

server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    host="0.0.0.0",
    port=8443
)
```

## Unix Socket Configuration

### Basic Unix Socket Setup

```python
import os
import tempfile
from pathlib import Path
from pyvider.rpcplugin import configure

# Use temporary directory for socket
temp_dir = Path(tempfile.gettempdir())
socket_path = temp_dir / f"plugin-{os.getpid()}.sock"

configure(
    transports=["unix"],
    unix_socket_path=str(socket_path),
    unix_socket_permissions=0o600,  # Owner read/write only
    unix_socket_cleanup=True        # Auto-cleanup on exit
)
```

### Production Unix Socket Setup

```python
# Production configuration with proper permissions
configure(
    transports=["unix"],
    unix_socket_path="/var/run/myapp/plugin.sock",
    unix_socket_permissions=0o660,  # Owner/group read/write
    unix_socket_group="myapp-group",
    unix_socket_cleanup=True
)

# Ensure socket directory exists
socket_dir = Path("/var/run/myapp")
socket_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
```

### Unix Socket Security

```python
class SecureUnixSocketConfig:
    def __init__(self, app_name: str):
        self.app_name = app_name
        self.socket_dir = Path(f"/var/run/{app_name}")

    def setup_secure_socket(self):
        """Setup secure Unix socket configuration."""
        # Create secure socket directory
        self.socket_dir.mkdir(parents=True, exist_ok=True, mode=0o750)

        # Set directory ownership (requires root)
        if os.getuid() == 0:
            import pwd, grp
            app_user = pwd.getpwnam(f"{self.app_name}-user")
            app_group = grp.getgrnam(f"{self.app_name}-group")

            os.chown(self.socket_dir, app_user.pw_uid, app_group.gr_gid)

        socket_path = self.socket_dir / "plugin.sock"

        configure(
            transports=["unix"],
            unix_socket_path=str(socket_path),
            unix_socket_permissions=0o600,
            unix_socket_cleanup=True
        )

        return socket_path

# Usage
config = SecureUnixSocketConfig("myapp")
socket_path = config.setup_secure_socket()
```

## TCP Configuration

### Basic TCP Setup

```python
# Auto-assign port
configure(
    transports=["tcp"],
    tcp_host="127.0.0.1",  # Localhost only
    tcp_port=0,            # Auto-assign available port
    tcp_reuse_port=True    # Enable SO_REUSEPORT
)

# Fixed port
configure(
    transports=["tcp"],
    tcp_host="0.0.0.0",    # All interfaces (use with caution)
    tcp_port=8080,
    tcp_keepalive=True,
    tcp_keepalive_time=30,
    tcp_keepalive_interval=10
)
```

### TCP Performance Optimization

```python
# High-performance TCP configuration
configure(
    transports=["tcp"],
    tcp_host="127.0.0.1",
    tcp_port=0,

    # Socket options
    tcp_nodelay=True,       # Disable Nagle's algorithm
    tcp_reuse_port=True,    # Load balancing support
    tcp_keepalive=True,     # Connection health monitoring

    # Buffer sizes
    tcp_send_buffer_size=1024 * 1024,    # 1MB send buffer
    tcp_recv_buffer_size=1024 * 1024,    # 1MB receive buffer

    # Connection limits
    max_concurrent_connections=1000,
    connection_timeout=30.0
)
```

### TCP with Connection Pooling

```python
import asyncio

class TCPConnectionManager:
    """Manage TCP connections for high-throughput scenarios."""

    def __init__(self, max_connections: int = 100):
        self.max_connections = max_connections
        self.active_connections: dict[str, list] = {}
        self.connection_stats = {
            "total_connections": 0,
            "active_count": 0,
            "peak_concurrent": 0
        }

    async def handle_connection(self, reader, writer):
        """Handle incoming TCP connection."""
        client_addr = writer.get_extra_info('peername')
        connection_id = f"{client_addr[0]}:{client_addr[1]}"

        # Track connection
        self.connection_stats["total_connections"] += 1
        self.connection_stats["active_count"] += 1

        if self.connection_stats["active_count"] > self.connection_stats["peak_concurrent"]:
            self.connection_stats["peak_concurrent"] = self.connection_stats["active_count"]

        try:
            # Add to active connections
            if connection_id not in self.active_connections:
                self.active_connections[connection_id] = []
            self.active_connections[connection_id].append(writer)

            # Handle connection
            await self.process_connection(reader, writer)

        finally:
            # Cleanup connection
            if connection_id in self.active_connections:
                self.active_connections[connection_id].remove(writer)
                if not self.active_connections[connection_id]:
                    del self.active_connections[connection_id]

            self.connection_stats["active_count"] -= 1

    async def process_connection(self, reader, writer):
        """Process individual connection."""
        # This would be implemented by the plugin framework
        # Shown here for completeness
        pass

    def get_connection_stats(self) -> dict:
        """Get connection statistics."""
        return {
            **self.connection_stats,
            "active_connections_by_client": {
                client: len(conns)
                for client, conns in self.active_connections.items()
            }
        }

# Usage with server
connection_manager = TCPConnectionManager(max_connections=200)

configure(
    transports=["tcp"],
    tcp_connection_handler=connection_manager.handle_connection,
    max_concurrent_connections=200
)
```

## mTLS Configuration

### Basic mTLS Setup

```python
# Simple mTLS with self-signed certificates
configure(
    transports=["tcp"],
    auto_mtls=True,  # Use self-signed certificates
    tcp_host="127.0.0.1",
    tcp_port=8443
)
```

### Production mTLS Setup

```python
from pathlib import Path

def setup_production_mtls():
    """Setup production mTLS configuration."""
    cert_dir = Path("/etc/ssl/myapp")

    # Verify certificates exist
    server_cert = cert_dir / "server.pem"
    server_key = cert_dir / "server.key"
    client_cert = cert_dir / "client.pem"
    ca_cert = cert_dir / "ca.pem"

    for cert_file in [server_cert, server_key, client_cert, ca_cert]:
        if not cert_file.exists():
            raise FileNotFoundError(f"Certificate not found: {cert_file}")

    configure(
        transports=["tcp"],
        auto_mtls=True,
        server_cert=f"file://{server_cert}",
        server_key=f"file://{server_key}",
        client_cert=f"file://{client_cert}",
        ca_cert=f"file://{ca_cert}",

        # TLS settings
        tls_min_version="TLSv1.3",
        tls_ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM",
        tls_verify_hostname=False,  # For self-signed certs

        # mTLS specific
        require_client_cert=True,
        verify_client_cert=True
    )

# Usage
setup_production_mtls()
server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Certificate Management

```python
import ssl
from provide.foundation.crypto import Certificate

class CertificateManager:
    """Manage mTLS certificates for plugin servers."""

    def __init__(self, cert_dir: Path):
        self.cert_dir = Path(cert_dir)
        self.certificates = {}

    def load_certificates(self):
        """Load and validate certificates."""
        cert_files = {
            'server_cert': self.cert_dir / 'server.pem',
            'server_key': self.cert_dir / 'server.key',
            'client_cert': self.cert_dir / 'client.pem',
            'ca_cert': self.cert_dir / 'ca.pem'
        }

        for name, path in cert_files.items():
            if path.exists():
                cert = Certificate.from_file(path)

                # Validate certificate
                if cert.is_expired():
                    logger.warning(f"Certificate expired: {name}")
                elif cert.expires_within_days(30):
                    logger.warning(f"Certificate expires soon: {name}")

                self.certificates[name] = cert

    def create_ssl_context(self, is_server: bool = True) -> ssl.SSLContext:
        """Create SSL context for mTLS."""
        if is_server:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            # Load server certificate
            context.load_cert_chain(
                certfile=self.certificates['server_cert'].cert_path,
                keyfile=self.certificates['server_key'].key_path
            )

            # Require client certificates
            context.verify_mode = ssl.CERT_REQUIRED

            # Load CA for client verification
            if 'ca_cert' in self.certificates:
                context.load_verify_locations(
                    cafile=self.certificates['ca_cert'].cert_path
                )

        else:  # Client context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            # Load client certificate
            context.load_cert_chain(
                certfile=self.certificates['client_cert'].cert_path,
                keyfile=self.certificates['client_key'].key_path
            )

            # Load CA for server verification
            if 'ca_cert' in self.certificates:
                context.load_verify_locations(
                    cafile=self.certificates['ca_cert'].cert_path
                )

        # Use strong protocols and ciphers
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")

        return context

    def get_certificate_info(self) -> dict[str, dict]:
        """Get information about loaded certificates."""
        info = {}

        for name, cert in self.certificates.items():
            info[name] = {
                'subject': cert.subject,
                'issuer': cert.issuer,
                'serial_number': cert.serial_number,
                'not_valid_before': cert.not_valid_before,
                'not_valid_after': cert.not_valid_after,
                'is_expired': cert.is_expired(),
                'days_until_expiry': cert.days_until_expiry()
            }

        return info

# Usage
cert_manager = CertificateManager("/etc/ssl/myapp")
cert_manager.load_certificates()

# Get certificate status
cert_info = cert_manager.get_certificate_info()
logger.info(f"Certificate status: {cert_info}")

# Configure with certificate manager
ssl_context = cert_manager.create_ssl_context(is_server=True)
```

## Transport Performance Monitoring

### Performance Metrics

```python
import time
import asyncio
from dataclasses import dataclass

@dataclass
class TransportMetrics:
    """Transport performance metrics."""
    connections_total: int = 0
    connections_active: int = 0
    connections_peak: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    requests_total: int = 0
    requests_per_second: float = 0.0
    avg_request_duration: float = 0.0
    errors_total: int = 0

class TransportMonitor:
    """Monitor transport layer performance."""

    def __init__(self):
        self.metrics = TransportMetrics()
        self.request_durations: list[float] = []
        self.last_metrics_update = time.time()
        self.monitoring_active = False

    async def start_monitoring(self):
        """Start background metrics collection."""
        self.monitoring_active = True

        async def metrics_loop():
            while self.monitoring_active:
                await asyncio.sleep(60)  # Update every minute
                self.update_calculated_metrics()

        asyncio.create_task(metrics_loop())

    def record_connection(self, connected: bool = True):
        """Record connection event."""
        if connected:
            self.metrics.connections_total += 1
            self.metrics.connections_active += 1

            if self.metrics.connections_active > self.metrics.connections_peak:
                self.metrics.connections_peak = self.metrics.connections_active
        else:
            self.metrics.connections_active = max(0, self.metrics.connections_active - 1)

    def record_request(self, duration: float, bytes_sent: int = 0,
                      bytes_received: int = 0, error: bool = False):
        """Record request metrics."""
        self.metrics.requests_total += 1
        self.metrics.bytes_sent += bytes_sent
        self.metrics.bytes_received += bytes_received

        if error:
            self.metrics.errors_total += 1

        self.request_durations.append(duration)

        # Keep only recent durations (last 1000 requests)
        if len(self.request_durations) > 1000:
            self.request_durations = self.request_durations[-1000:]

    def update_calculated_metrics(self):
        """Update calculated metrics."""
        current_time = time.time()
        time_delta = current_time - self.last_metrics_update

        if time_delta > 0:
            # Calculate requests per second
            self.metrics.requests_per_second = self.metrics.requests_total / time_delta

        # Calculate average request duration
        if self.request_durations:
            self.metrics.avg_request_duration = sum(self.request_durations) / len(self.request_durations)

        self.last_metrics_update = current_time

    def get_metrics_summary(self) -> dict:
        """Get comprehensive metrics summary."""
        self.update_calculated_metrics()

        return {
            'transport': {
                'connections_total': self.metrics.connections_total,
                'connections_active': self.metrics.connections_active,
                'connections_peak': self.metrics.connections_peak,
            },
            'throughput': {
                'requests_total': self.metrics.requests_total,
                'requests_per_second': round(self.metrics.requests_per_second, 2),
                'bytes_sent': self.metrics.bytes_sent,
                'bytes_received': self.metrics.bytes_received,
            },
            'performance': {
                'avg_request_duration_ms': round(self.metrics.avg_request_duration * 1000, 2),
                'error_rate_percent': round((self.metrics.errors_total / max(1, self.metrics.requests_total)) * 100, 2),
            }
        }

# Integration with server
transport_monitor = TransportMonitor()

class MonitoredHandler(MyHandler):
    async def process_request(self, request, context):
        start_time = time.time()
        error = False

        try:
            response = await super().process_request(request, context)
            return response
        except Exception as e:
            error = True
            raise
        finally:
            duration = time.time() - start_time
            transport_monitor.record_request(
                duration=duration,
                bytes_sent=len(str(response)) if 'response' in locals() else 0,
                bytes_received=len(str(request)),
                error=error
            )

# Start monitoring
await transport_monitor.start_monitoring()
```

## Environment-Specific Configurations

### Development Configuration

```python
def setup_development_transport():
    """Development-optimized transport configuration."""
    configure(
        # Easy debugging
        transports=["tcp"],
        tcp_host="127.0.0.1",
        tcp_port=0,  # Auto-assign

        # No security for local dev
        auto_mtls=False,

        # Debug settings
        log_transport_details=True,
        enable_transport_reflection=True,

        # Relaxed timeouts
        connection_timeout=120.0,
        request_timeout=60.0
    )
```

### Production Configuration

```python
def setup_production_transport():
    """Production-optimized transport configuration."""
    configure(
        # Best performance
        transports=["unix"],
        unix_socket_path="/var/run/myapp/plugin.sock",
        unix_socket_permissions=0o600,

        # Security enabled
        auto_mtls=True,
        server_cert="file:///etc/ssl/server.pem",
        server_key="file:///etc/ssl/server.key",

        # Performance optimization
        max_concurrent_connections=1000,
        tcp_send_buffer_size=2 * 1024 * 1024,  # 2MB
        tcp_recv_buffer_size=2 * 1024 * 1024,  # 2MB

        # Production timeouts
        connection_timeout=30.0,
        request_timeout=30.0,

        # Resource limits
        max_message_size=10 * 1024 * 1024,  # 10MB
        compression="gzip"
    )
```

## Related Documentation

### Conceptual Foundation
- **[Transport Concepts](../concepts/transports.md)** - Understanding transport types, selection criteria, and performance characteristics
- **[Security Model](../concepts/security.md)** - How transport security integrates with the overall security architecture

### Configuration Resources
- **[Configuration Guide](../config/index.md)** - Environment-driven transport configuration patterns and best practices
- **[Configuration API Reference](../../reference/index.md)** - Programmatic transport configuration access and validation methods

### Security Integration
- **[Security Implementation Guide](../security/index.md)** - Complete security setup including transport-level security
- **[mTLS Configuration](../security/mtls.md)** - Detailed mutual TLS setup for secure transport

## Next Steps

- **[Async Patterns](async-patterns.md)** - Master concurrency and async programming
- **[Health Checks](health-checks.md)** - Implement monitoring and health checks
- **[Security](../security/index.md)** - Dive deeper into mTLS and security patterns
