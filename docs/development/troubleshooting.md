# Troubleshooting

This guide helps you diagnose and resolve common issues when developing with the Pyvider RPC Plugin framework.

## Common Issues

### 1. Connection Issues

#### Problem: "Connection refused" errors

**Symptoms:**

```
ConnectionRefusedError: [Errno 111] Connection refused
grpc._channel._InactiveRpcError: status = StatusCode.UNAVAILABLE
```

**Diagnosis:**

```python
import asyncio
import socket

async def diagnose_connection(host: str, port: int):
    """Diagnose connection issues."""
    print(f"🔍 Diagnosing connection to {host}:{port}")

    # Test basic network connectivity
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            print("✅ Network connection successful")
        else:
            print(f"❌ Network connection failed: {result}")
            return False
    except Exception as e:
        print(f"❌ Network error: {e}")
        return False
    finally:
        sock.close()

    return True
```

**Solutions:**

=== "Server Not Running"

    ```bash
    # Check if server process is running
    ps aux | grep python
    netstat -tlnp | grep :50051
    ```

=== "Wrong Host/Port"

    ```python
    # Verify server configuration
    config = ServerConfig.from_env()
    print(f"Server should be on {config.transport.host}:{config.transport.port}")
    ```

=== "Firewall Blocking"

    ```bash
    # Check firewall rules (Linux)
    sudo iptables -L -n

    # Check firewall rules (macOS)
    sudo pfctl -sr
    ```

=== "Network Binding"

    ```python
    # Server binding to all interfaces
    config = ServerConfig(
        transport=TransportConfig(
            host="0.0.0.0",  # Bind to all interfaces
            port=50051
        )
    )
    ```

#### Problem: "Address already in use"

**Symptoms:**

```
OSError: [Errno 98] Address already in use
```

**Solutions:**

```bash
# Find and kill process using port
lsof -i :50051
kill -9 <PID>

# Or use different port
config = ServerConfig(transport=TransportConfig(port=50052))
```

### 2. SSL/TLS Issues

#### Problem: SSL certificate verification failures

**Symptoms:**

```
ssl.SSLCertVerificationError: certificate verify failed
grpc._channel._InactiveRpcError: SSL handshake failed
```

**Diagnosis:**

```python
import ssl
import asyncio

async def diagnose_ssl(host: str, port: int, cert_file: str | None = None):
    """Diagnose SSL/TLS issues."""
    print(f"🔍 Diagnosing SSL connection to {host}:{port}")

    context = ssl.create_default_context()
    if cert_file:
        context.load_verify_locations(cert_file)

    try:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=context
        )
        print("✅ SSL connection successful")
        writer.close()
        await writer.wait_closed()
        return True
    except ssl.SSLError as e:
        print(f"❌ SSL error: {e}")
        return False
```

**Solutions:**

=== "Invalid Certificate Paths"

    ```python
    from pathlib import Path

    cert_file = Path("certs/server.pem")
    if not cert_file.exists():
        print(f"❌ Certificate file not found: {cert_file}")
    ```

=== "Self-Signed Certificates"

    ```python
    # Disable SSL verification (development only!)
    import ssl

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ```

=== "Generate Test Certificates"

    ```bash
    # Generate self-signed certificate for testing
    openssl req -x509 -newkey rsa:4096 \
      -keyout key.pem -out cert.pem -days 365 -nodes
    ```

### 3. Performance Issues

#### Problem: Slow RPC calls

**Diagnosis:**

```python
import time
import statistics
from typing import Any

class PerformanceDiagnostics:
    """Performance diagnostics tools."""

    def __init__(self, client):
        self.client = client
        self.call_times: list[float] = []

    async def benchmark_call(
        self,
        method_name: str,
        request: Any,
        iterations: int = 100
    ):
        """Benchmark RPC call performance."""
        print(f"🏃 Benchmarking {method_name} ({iterations} iterations)")

        for i in range(iterations):
            start_time = time.perf_counter()

            try:
                await self.client.call(method_name, request)
                end_time = time.perf_counter()
                self.call_times.append(end_time - start_time)
            except Exception as e:
                print(f"❌ Call {i+1} failed: {e}")

        self._analyze_performance()

    def _analyze_performance(self):
        """Analyze performance metrics."""
        if not self.call_times:
            return

        mean_time = statistics.mean(self.call_times)
        p95 = sorted(self.call_times)[int(0.95 * len(self.call_times))]

        print(f"\n📊 Performance Analysis:")
        print(f"  Mean:   {mean_time*1000:.2f}ms")
        print(f"  P95:    {p95*1000:.2f}ms")

        if mean_time > 1.0:
            print("⚠️  Average call time is high (>1s)")
```

**Solutions:**

=== "Connection Pooling"

    ```python
    from pyvider.client import ConnectionPool

    # Use connection pooling to reduce overhead
    pool = ConnectionPool(max_size=10)
    client = RPCPluginClient(connection_pool=pool)
    ```

=== "Request Batching"

    ```python
    # Batch multiple requests
    async def batch_requests(client, requests):
        tasks = []
        for request in requests:
            tasks.append(client.call("method", request))

        return await asyncio.gather(*tasks)
    ```

=== "Streaming for Large Data"

    ```python
    # Use streaming for large responses
    async def stream_large_data(client):
        async for chunk in client.stream_call("get_large_data", request):
            process_chunk(chunk)
    ```

#### Problem: Memory leaks

**Diagnosis:**

```python
import psutil
import gc

class MemoryMonitor:
    """Monitor memory usage."""

    def __init__(self):
        self.process = psutil.Process()
        self.initial_memory = self.process.memory_info().rss

    def check_memory_leak(self, threshold_mb: int = 100):
        """Check for potential memory leaks."""
        current_memory = self.process.memory_info().rss
        increase = (current_memory - self.initial_memory) / 1024 / 1024

        print(f"💾 Memory usage: {current_memory/1024/1024:.1f}MB")
        print(f"📈 Memory increase: {increase:.1f}MB")

        if increase > threshold_mb:
            print(f"⚠️  Potential memory leak detected (+{increase:.1f}MB)")
            gc.collect()
```

**Solutions:**

=== "Proper Resource Cleanup"

    ```python
    # Always use context managers
    async with RPCPluginClient() as client:
        result = await client.call("method", request)

    # Or explicit cleanup
    client = RPCPluginClient()
    try:
        await client.connect()
        result = await client.call("method", request)
    finally:
        await client.close()
    ```

=== "Connection Pooling"

    ```python
    # Reuse connections instead of creating new ones
    pool = ConnectionPool(max_size=10)
    # Use pool for multiple requests
    ```

### 4. Serialization Issues

#### Problem: Protobuf serialization errors

**Symptoms:**

```
google.protobuf.message.DecodeError: Error parsing message
TypeError: Couldn't build proto file into descriptor pool
```

**Diagnosis:**

```python
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import Message

def diagnose_protobuf_issue(message: Message):
    """Diagnose protobuf serialization issues."""
    print(f"🔍 Diagnosing protobuf message: {type(message).__name__}")

    try:
        # Test JSON serialization
        json_str = MessageToJson(message)
        print("✅ JSON serialization successful")

        # Test binary serialization
        binary_data = message.SerializeToString()
        print(f"✅ Binary serialization successful ({len(binary_data)} bytes)")

        # Test deserialization
        new_message = type(message)()
        new_message.ParseFromString(binary_data)
        print("✅ Binary deserialization successful")

    except Exception as e:
        print(f"❌ Serialization error: {e}")
```

**Solutions:**

=== "Version Mismatches"

    ```bash
    # Check protobuf versions
    pip list | grep protobuf

    # Regenerate protobuf files
    python -m grpc_tools.protoc --python_out=. --grpc_python_out=. *.proto
    ```

=== "Message Validation"

    ```python
    def validate_message(message):
        """Validate protobuf message."""
        try:
            message.SerializeToString()
            return True
        except Exception as e:
            print(f"Message validation failed: {e}")
            return False
    ```

=== "Field Type Mismatches"

    ```python
    # Ensure correct field types
    request = MyRequest(
        id=int(user_id),              # Ensure integer
        name=str(name),                # Ensure string
        timestamp=int(time.time()),    # Ensure integer timestamp
    )
    ```

### 5. Authentication Issues

#### Problem: JWT token validation failures

**Symptoms:**

```
jwt.InvalidTokenError: Invalid token
grpc.RpcError: UNAUTHENTICATED: Invalid token
```

**Diagnosis:**

```python
import jwt
import time

def diagnose_jwt_token(token: str, secret: str, algorithm: str = 'HS256'):
    """Diagnose JWT token issues."""
    print(f"🔍 Diagnosing JWT token")

    try:
        # Decode without verification first
        unverified = jwt.decode(token, options={"verify_signature": False})
        print("✅ Token structure is valid")
        print(f"Payload: {unverified}")

        # Check expiration
        if 'exp' in unverified:
            exp_time = unverified['exp']
            if exp_time < time.time():
                print(f"❌ Token expired")
            else:
                print(f"✅ Token valid until {time.ctime(exp_time)}")

        # Verify signature
        verified = jwt.decode(token, secret, algorithms=[algorithm])
        print("✅ Token signature is valid")
        return verified

    except jwt.ExpiredSignatureError:
        print("❌ Token has expired")
    except jwt.InvalidSignatureError:
        print("❌ Token signature is invalid")
    except jwt.InvalidTokenError as e:
        print(f"❌ Token is invalid: {e}")

    return None
```

**Solutions:**

=== "Token Expiration"

    ```python
    # Generate token with longer expiration
    payload = {
        'user_id': 123,
        'exp': int(time.time()) + 7200  # 2 hours
    }
    ```

=== "Secret Key Mismatches"

    ```python
    # Ensure consistent secret across client and server
    SECRET_KEY = os.getenv('PLUGIN_JWT_SECRET')
    if not SECRET_KEY:
        raise ValueError("PLUGIN_JWT_SECRET environment variable not set")
    ```

## Debugging Tools

### 1. Enable Debug Logging

```python
import logging

# Enable debug logging for pyvider
logging.getLogger('pyvider').setLevel(logging.DEBUG)

# Enable gRPC debug logging
logging.getLogger('grpc').setLevel(logging.DEBUG)

# Format debug output
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### 2. Network Debugging

```python
import asyncio
import socket

async def debug_network_connection(host: str, port: int):
    """Debug network connectivity."""
    print(f"🌐 Testing connection to {host}:{port}")

    # Test DNS resolution
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        print(f"✅ DNS resolution: {addr_info[0][4]}")
    except Exception as e:
        print(f"❌ DNS resolution failed: {e}")
        return

    # Test TCP connection
    try:
        reader, writer = await asyncio.open_connection(host, port)
        print("✅ TCP connection successful")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"❌ TCP connection failed: {e}")
```

### 3. RPC Call Tracing

```python
import functools
import time

def trace_rpc_calls(func):
    """Decorator to trace RPC calls."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        method_name = getattr(func, '__name__', 'unknown')

        print(f"🚀 Starting RPC call: {method_name}")

        try:
            result = await func(*args, **kwargs)
            duration = time.perf_counter() - start_time

            print(f"✅ RPC call completed: {method_name} ({duration:.3f}s)")
            return result

        except Exception as e:
            duration = time.perf_counter() - start_time

            print(f"❌ RPC call failed: {method_name} ({duration:.3f}s)")
            print(f"   Error: {e}")
            raise

    return wrapper
```

## Getting Help

### Communication Channels

- **GitHub Issues** - Report bugs and request features
- **GitHub Discussions** - Ask questions and share solutions
- **Documentation** - Comprehensive guides and API reference

### Diagnostic Information Collection

When reporting issues, include this diagnostic information:

```python
import sys
import platform
import pyvider
import grpc
import google.protobuf

def collect_diagnostic_info():
    """Collect system diagnostic information."""
    info = {
        'pyvider_version': pyvider.__version__,
        'python_version': sys.version,
        'platform': platform.platform(),
        'grpc_version': grpc.__version__,
        'protobuf_version': google.protobuf.__version__,
    }

    print("🔧 Diagnostic Information:")
    for key, value in info.items():
        print(f"  {key}: {value}")

    return info
```

### Minimal Reproduction Case

When reporting bugs, provide a minimal reproduction case:

```python
import asyncio
from pyvider.server import RPCPluginServer
from pyvider.client import RPCPluginClient

async def reproduce_issue():
    """Minimal case reproducing the issue."""
    # Server setup
    server = RPCPluginServer()
    # ... minimal server configuration

    # Client setup
    client = RPCPluginClient()
    # ... minimal client configuration

    # Reproduce the issue
    try:
        result = await client.call("method", request)
        print(f"Expected error, but got: {result}")
    except Exception as e:
        print(f"Issue reproduced: {e}")

if __name__ == "__main__":
    asyncio.run(reproduce_issue())
```

## Best Practices

1. **Start with the Basics** - Check network connectivity, configuration, and resource availability first
2. **Enable Logging** - Use debug logging to understand what's happening
3. **Isolate the Problem** - Create minimal reproduction cases
4. **Check Documentation** - Review relevant guides and API documentation
5. **Search Issues** - Look for similar reported issues
6. **Provide Context** - Include diagnostic information when reporting issues

Remember: systematic diagnosis is key to effective troubleshooting. Always check the most likely causes first before investigating less common issues.
