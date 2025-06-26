# Troubleshooting Guide - pyvider-rpcplugin

This guide helps you diagnose and resolve common issues with `pyvider-rpcplugin`.

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Connection Issues](#connection-issues)
- [Certificate & mTLS Problems](#certificate--mtls-problems)
- [Transport Layer Issues](#transport-layer-issues)
- [Performance Problems](#performance-problems)
- [Configuration Issues](#configuration-issues)
- [Error Messages](#error-messages)
- [Debugging Tools](#debugging-tools)
- [Common Patterns](#common-patterns)

## Quick Diagnostics

### Health Check Script

Run this script to quickly identify common issues:

```python
#!/usr/bin/env python3
"""Quick health check for pyvider-rpcplugin."""

import asyncio
import os
import socket
import ssl
from pathlib import Path

from pyvider.rpcplugin import plugin_server, plugin_client, create_basic_protocol
from pyvider.rpcplugin.config import RPCPluginConfig
from pyvider.telemetry import logger

async def health_check():
    """Comprehensive health check."""
    
    results = {
        "config": False,
        "certificates": False,
        "network": False,
        "server_start": False,
        "client_connect": False
    }
    
    # 1. Configuration Check
    try:
        config = RPCPluginConfig.instance()
        magic_cookie = config.get("PLUGIN_MAGIC_COOKIE_VALUE")
        transports = config.get("PLUGIN_SERVER_TRANSPORTS")
        
        logger.info("Configuration check", 
                   magic_cookie_set=bool(magic_cookie),
                   transports=transports)
        results["config"] = True
        
    except Exception as e:
        logger.error("Configuration check failed", error=str(e))
    
    # 2. Certificate Check (if mTLS enabled)
    try:
        auto_mtls = config.get("PLUGIN_AUTO_MTLS", False)
        if auto_mtls:
            server_cert = config.get("PLUGIN_SERVER_CERT")
            client_cert = config.get("PLUGIN_CLIENT_CERT")
            
            if server_cert and client_cert:
                logger.info("Certificate check", 
                           server_cert=bool(server_cert),
                           client_cert=bool(client_cert))
                results["certificates"] = True
            else:
                logger.warning("mTLS enabled but certificates not configured")
        else:
            results["certificates"] = True  # Not applicable
            
    except Exception as e:
        logger.error("Certificate check failed", error=str(e))
    
    # 3. Network Check
    try:
        # Test TCP socket binding
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        
        logger.info("Network check", available_port=port)
        results["network"] = True
        
    except Exception as e:
        logger.error("Network check failed", error=str(e))
    
    # 4. Server Start Check
    try:
        protocol = create_basic_protocol()
        
        class TestHandler:
            async def TestMethod(self, request, context):
                return type('TestReply', (), {'message': 'OK'})()
        
        server = plugin_server(
            protocol=protocol,
            handler=TestHandler(),
            transport="tcp",
            host="127.0.0.1",
            port=0
        )
        
        # Start server briefly
        server_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5)
        await server.stop()
        await server_task
        
        logger.info("Server start check passed")
        results["server_start"] = True
        
    except Exception as e:
        logger.error("Server start check failed", error=str(e))
    
    # 5. Client Connection Check
    try:
        # client = plugin_client(server_path="./dummy_server.sh") # Example for an executable
        # await client.start() # This would attempt to connect
        # await client.close()
        logger.info("Client creation check (conceptual: use with an actual executable)")
        results["client_connect"] = True
        
    except Exception as e:
        logger.error("Client creation check failed", error=str(e))
    
    # Summary
    passed = sum(results.values())
    total = len(results)
    
    logger.info("Health check summary", 
               passed=passed, 
               total=total, 
               status="PASS" if passed == total else "FAIL",
               results=results)
    
    return results

if __name__ == "__main__":
    asyncio.run(health_check())
```

### Environment Information

Collect environment information for debugging:

```bash
#!/bin/bash
# collect_env_info.sh - Collect environment information

echo "=== pyvider-rpcplugin Environment Information ==="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "Working Directory: $(pwd)"
echo ""

echo "=== Python Environment ==="
python --version
echo "Python executable: $(which python)"
echo ""

echo "=== Package Versions ==="
pip show pyvider-rpcplugin
pip show grpcio
pip show attrs
pip show structlog
echo ""

echo "=== Environment Variables ==="
env | grep -E "^PLUGIN_|^PYVIDER_" | sort
echo ""

echo "=== Network Information ==="
echo "Hostname: $(hostname)"
echo "IP addresses:"
ip addr show | grep -E "inet.*scope" || ifconfig | grep -E "inet.*netmask"
echo ""

echo "=== File Permissions ==="
if [ -d "/tmp" ]; then
    echo "Temp directory permissions:"
    ls -la /tmp/ | head -5
fi
echo ""

echo "=== Process Information ==="
echo "Current processes (grep python):"
ps aux | grep python | head -5
echo ""

echo "=== System Resources ==="
echo "Memory usage:"
free -h 2>/dev/null || vm_stat
echo "Disk usage:"
df -h . 2>/dev/null || du -sh .
```

## Connection Issues

### "Connection Refused" Errors

**Symptoms:**
```
TransportError: Connection refused to 127.0.0.1:50051
```

**Diagnosis:**
```python
import socket

def diagnose_connection_refused(host: str, port: int):
    """Diagnose connection refused errors."""
    
    # 1. Check if port is listening
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"✅ Port {port} is open on {host}")
        else:
            print(f"❌ Port {port} is not listening on {host}")
            print(f"Error code: {result}")
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
    finally:
        sock.close()
    
    # 2. Check what's listening on the port
    import subprocess
    try:
        if os.name == 'posix':  # Unix/Linux/macOS
            result = subprocess.run(['lsof', '-i', f':{port}'], 
                                  capture_output=True, text=True)
            if result.stdout:
                print(f"Processes listening on port {port}:")
                print(result.stdout)
            else:
                print(f"No processes listening on port {port}")
    except FileNotFoundError:
        print("lsof not available, cannot check listening processes")

# Usage
diagnose_connection_refused("127.0.0.1", 50051)
```

**Solutions:**
1. **Verify server is running:**
   ```python
   # Check server startup logs
   await server.serve()  # Should not return immediately
   ```

2. **Check port binding:**
   ```python
   # Use port 0 for auto-assignment
   server = plugin_server(protocol, handler, port=0)
   ```

3. **Verify host binding:**
   ```python
   # Bind to all interfaces
   server = plugin_server(protocol, handler, host="0.0.0.0")
   ```

### "Handshake Timeout" Errors

**Symptoms:**
```
HandshakeError: Handshake timeout after 10.0 seconds
```

**Diagnosis:**
```python
async def diagnose_handshake_timeout():
    """Diagnose handshake timeout issues."""
    
    config = RPCPluginConfig.instance()
    
    # Check handshake timeout setting
    timeout = config.get("PLUGIN_HANDSHAKE_TIMEOUT", 10.0)
    print(f"Handshake timeout: {timeout} seconds")
    
    # Check magic cookie configuration
    # PLUGIN_MAGIC_COOKIE is what the host provides (client behavior for this lib)
    # PLUGIN_MAGIC_COOKIE_VALUE is what the server expects
    # For a server checking a client, it would get PLUGIN_MAGIC_COOKIE from env
    # and compare it to its own PLUGIN_MAGIC_COOKIE_VALUE.
    # This diagnostic is a bit simplified.
    expected_cookie = config.get("PLUGIN_MAGIC_COOKIE_VALUE")
    provided_cookie_env_var_name = config.get("PLUGIN_MAGIC_COOKIE_KEY")
    # In a real scenario, the host (e.g. Terraform) sets env[PLUGIN_MAGIC_COOKIE_KEY]
    # For this check, we assume it's about self-consistency of server config
    print(f"Server expects cookie value: {expected_cookie}")
    print(f"Server expects cookie to be in env var named: {provided_cookie_env_var_name}")
    # To truly test, you'd simulate how a host provides the cookie.
    # For now, this part of the diagnostic is illustrative.
    
    # Check certificate configuration (if mTLS enabled)
    auto_mtls = config.get("PLUGIN_AUTO_MTLS", False)
    if auto_mtls:
        server_cert = config.get("PLUGIN_SERVER_CERT")
        client_cert = config.get("PLUGIN_CLIENT_CERT")
        
        if not server_cert or not client_cert:
            print("❌ mTLS enabled but certificates missing")
        else:
            print("✅ mTLS certificates configured")
```

**Solutions:**
1. **Increase timeout:**
   ```python
   configure(PLUGIN_HANDSHAKE_TIMEOUT=30.0)
   ```

2. **Fix magic cookie mismatch:**
   ```python
   # Ensure server's PLUGIN_MAGIC_COOKIE_VALUE matches what client sends
   # via environment variable named by PLUGIN_MAGIC_COOKIE_KEY.
   configure(PLUGIN_MAGIC_COOKIE_VALUE="same-cookie-for-client-and-server")
   ```

3. **Verify mTLS configuration:**
   ```python
   configure(
       PLUGIN_AUTO_MTLS=True,
       PLUGIN_SERVER_CERT="file:///path/to/server.crt", # For server
       PLUGIN_CLIENT_CERT="file:///path/to/client.crt"  # For client
       # Also check PLUGIN_SERVER_ROOT_CERTS and PLUGIN_CLIENT_ROOT_CERTS for CAs
   )
   ```

### Unix Socket Permission Issues

**Symptoms:**
```
TransportError: Permission denied: /tmp/rpc.sock
```

**Diagnosis:**
```python
import os
import stat

def diagnose_unix_socket_permissions(socket_path: str):
    """Diagnose Unix socket permission issues."""
    
    if not os.path.exists(socket_path):
        print(f"❌ Socket file does not exist: {socket_path}")
        return
    
    # Check file permissions
    file_stat = os.stat(socket_path)
    permissions = stat.filemode(file_stat.st_mode)
    
    print(f"Socket permissions: {permissions}")
    print(f"Owner UID: {file_stat.st_uid}")
    print(f"Group GID: {file_stat.st_gid}")
    print(f"Current UID: {os.getuid()}")
    print(f"Current GID: {os.getgid()}")
    
    # Check if socket is readable/writable
    readable = os.access(socket_path, os.R_OK)
    writable = os.access(socket_path, os.W_OK)
    
    print(f"Readable: {readable}")
    print(f"Writable: {writable}")
```

**Solutions:**
1. **Fix socket permissions:**
   ```python
   # Set proper permissions after socket creation
   os.chmod(socket_path, 0o600)  # Owner read/write only
   ```

2. **Use accessible directory:**
   ```python
   # Use user-writable directory
   socket_path = f"/tmp/{os.getuid()}_rpc.sock"
   server = plugin_server(protocol, handler, transport_path=socket_path)
   ```

## Certificate & mTLS Problems

### Certificate Validation Failures

**Symptoms:**
```
SecurityError: Certificate validation failed
```

**Diagnosis:**
```python
from pyvider.rpcplugin.crypto.certificate import Certificate
import ssl

def diagnose_certificate_issues(cert_path: str, ca_path: str = None):
    """Diagnose certificate validation issues."""
    
    try:
        # Load certificate
        cert = Certificate.load_from_file(cert_path)
        print(f"✅ Certificate loaded: {cert_path}")
        
        # Check expiration
        days_until_expiry = cert.days_until_expiry()
        if days_until_expiry <= 0:
            print(f"❌ Certificate expired {abs(days_until_expiry)} days ago")
        elif days_until_expiry <= 30:
            print(f"⚠️ Certificate expires in {days_until_expiry} days")
        else:
            print(f"✅ Certificate valid for {days_until_expiry} days")
        
        # Check certificate chain (if CA provided)
        if ca_path:
            valid_chain = Certificate.verify_certificate_chain(cert_path, ca_path)
            if valid_chain:
                print("✅ Certificate chain valid")
            else:
                print("❌ Certificate chain validation failed")
        
        # Check certificate details
        print(f"Subject: {cert.subject}")
        print(f"Issuer: {cert.issuer}")
        print(f"Serial: {cert.serial_number}")
        
    except Exception as e:
        print(f"❌ Certificate diagnosis failed: {e}")

# Usage
diagnose_certificate_issues("/path/to/cert.crt", "/path/to/ca.crt")
```

**Solutions:**
1. **Regenerate expired certificates:**
   ```python
   # Generate new certificate (using corrected API)
   # Ensure ca_cert is your loaded CA Certificate object
   new_server_cert = Certificate.create_signed_certificate(
       ca_certificate=ca_cert, # Certificate object of the CA
       common_name="your-server.com",
       organization_name="Your Org", # organization_name is required
       validity_days=90,
       is_client_cert=False # For a server certificate
       # key_type, ecdsa_curve, etc., can also be specified if non-default
   )
   # new_server_cert.cert and new_server_cert.key contain the PEM data
   # Example saving:
   # with open("new_server.crt", "w") as f: f.write(new_server_cert.cert)
   # if new_server_cert.key:
   #     with open("new_server.key", "w") as f: f.write(new_server_cert.key)
   ```

2. **Fix certificate chain:**
   ```python
   # Ensure certificate is signed by the correct CA (using corrected API)
   # Ensure ca_cert is your loaded CA Certificate object
   new_server_cert = Certificate.create_signed_certificate(
       ca_certificate=ca_cert,  # Use same CA for client validation
       common_name="server.example.com",
       organization_name="Your Org", # Required
       validity_days=90,
       is_client_cert=False # For a server certificate
   )
   # Save new_server_cert.cert and new_server_cert.key as needed
   ```

### mTLS Handshake Failures

**Symptoms:**
```
ssl.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Diagnosis:**
```python
import ssl
import socket

def test_mtls_connection(host: str, port: int, cert_file: str, key_file: str, ca_file: str):
    """Test mTLS connection manually."""
    
    try:
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
        # For client-side, Purpose.SERVER_AUTH is correct. Server loads CA to verify client.
        # Client loads CA to verify server.
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.check_hostname = True # Should generally be True
        
        # Create connection
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock: # server_hostname is important for SNI and validation
                print(f"✅ mTLS connection successful to {host}:{port}")
                print(f"   Protocol: {ssock.version()}")
                print(f"   Cipher: {ssock.cipher()}")
                
                # Get peer certificate
                peer_cert = ssock.getpeercert()
                print(f"   Peer certificate subject: {peer_cert.get('subject')}")
                
    except Exception as e:
        print(f"❌ mTLS connection failed to {host}:{port}: {e}")

# Usage example (ensure paths are correct and certs are valid for the roles)
# test_mtls_connection("127.0.0.1", 50051, "client.crt", "client.key", "ca.crt")
```

**Solutions:**
1. **Verify certificate chain:**
   ```bash
   # Verify server certificate against its CA
   openssl verify -CAfile /path/to/ca.crt /path/to/server.crt
   # Verify client certificate against its CA (if using mTLS)
   openssl verify -CAfile /path/to/ca.crt /path/to/client.crt
   ```

2. **Check certificate Subject Alternative Names (SANs):**
   The hostname/IP the client connects to must be present in the server certificate's SANs.
   ```bash
   # Check SAN entries in server.crt
   openssl x509 -in /path/to/server.crt -text -noout | grep -A1 "Subject Alternative Name"
   ```

3. **Regenerate certificate chain with correct parameters:**
   ```python
   # Ensure ca_cert is a Certificate object representing your CA
   ca_cert = Certificate.create_ca(
       common_name="My Example CA",
       organization_name="My Org", # Required
       validity_days=365
   )
   
   server_cert = Certificate.create_signed_certificate(
       ca_certificate=ca_cert,
       common_name="rpc.example.com", # This (or SANs) must match what client connects to
       organization_name="My Org",    # Required
       alt_names=["rpc.example.com", "localhost", "127.0.0.1"], # Add all relevant SANs
       validity_days=90,
       is_client_cert=False
   )
   
   client_cert = Certificate.create_signed_certificate(
       ca_certificate=ca_cert,
       common_name="my-client-id",
       organization_name="My Org", # Required
       validity_days=30,
       is_client_cert=True
   )
   # Remember to save these certs (.cert and .key attributes) and distribute appropriately.
   ```

## Transport Layer Issues

### Unix Socket "File Not Found" Errors

**Symptoms:**
```
TransportError: Unix socket not found: /tmp/rpc.sock
```

**Solutions:**
1. **Check socket creation:**
   ```python
   # Ensure socket is created before client connects
   # server = plugin_server(protocol, handler, transport="unix")
   # Server must be running for client to connect.
   # Client (for executable) would be:
   # client = plugin_client(server_path="/path/to/executable")
   # await client.start()
   print("Note: Client connection requires a running server or executable.")
   ```

2. **Use absolute paths:**
   ```python
   import tempfile
   
   # Use absolute path
   socket_path = os.path.join(tempfile.gettempdir(), "rpc.sock")
   server = plugin_server(protocol, handler, transport_path=socket_path)
   ```

### TCP Port Already in Use

**Symptoms:**
```
TransportError: Address already in use: 127.0.0.1:50051
```

**Diagnosis:**
```bash
# Find what's using the port
lsof -i :50051
netstat -tulpn | grep :50051
```

**Solutions:**
1. **Use different port:**
   ```python
   server = plugin_server(protocol, handler, port=50052)
   ```

2. **Use auto-assigned port:**
   ```python
   server = plugin_server(protocol, handler, port=0)
   # Get actual port after startup
   actual_port = server.transport.port
   ```

3. **Enable port reuse:**
   ```python
   # For development only
   import socket
   
   class ReusableTCPTransport(TCPSocketTransport):
       def __init__(self, *args, **kwargs):
           super().__init__(*args, **kwargs)
           self.socket_options = [
               (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
           ]
   ```

## Performance Problems

### High Latency

**Diagnosis:**
```python
import time
import asyncio

async def measure_rpc_latency(client, num_requests: int = 100):
    """Measure RPC latency."""
    
    latencies = []
    
    for i in range(num_requests):
        start_time = time.time()
        
        try:
            # Make RPC call
            stub = YourServiceStub(client.channel)
            response = await stub.YourMethod(YourRequest())
            
            end_time = time.time()
            latency_ms = (end_time - start_time) * 1000
            latencies.append(latency_ms)
            
        except Exception as e:
            print(f"Request {i} failed: {e}")
    
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]
        
        print(f"Average latency: {avg_latency:.2f}ms")
        print(f"P95 latency: {p95_latency:.2f}ms")
        print(f"Min latency: {min(latencies):.2f}ms")
        print(f"Max latency: {max(latencies):.2f}ms")
```

**Solutions:**
1. **Use Unix sockets for local communication:**
   ```python
   # Unix sockets are faster than TCP for local IPC
   server = plugin_server(protocol, handler, transport="unix")
   ```

2. **Optimize serialization:**
   ```python
   # Use smaller message sizes
   # Enable compression for large messages (Note: compression is a gRPC channel arg, not a top-level configure key)
   # Example: channel = grpc.aio.secure_channel(target, credentials, compression=grpc.Compression.Gzip)
   print("Note: Compression is a gRPC channel option, not directly via rpcplugin.configure.")
   ```

3. **Connection pooling:**
   ```python
   # Connection pooling is a client-side application pattern.
   # RPCPluginClient itself manages a single connection to a plugin executable.
   # If you need to talk to multiple plugin instances or manage multiple
   # connections, your application would manage multiple RPCPluginClient instances.
   # (Conceptual example of managing multiple clients was in README.md)
   print("Note: Connection pooling is an application-level pattern.")
   ```

### Memory Leaks

**Diagnosis:**
```python
import psutil
import asyncio

async def monitor_memory_usage(duration_seconds: int = 60):
    """Monitor memory usage over time."""
    
    process = psutil.Process()
    start_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    print(f"Initial memory usage: {start_memory:.2f} MB")
    
    for i in range(duration_seconds):
        await asyncio.sleep(1)
        current_memory = process.memory_info().rss / 1024 / 1024
        
        if i % 10 == 0:  # Print every 10 seconds
            print(f"Memory usage after {i}s: {current_memory:.2f} MB")
    
    final_memory = process.memory_info().rss / 1024 / 1024
    memory_increase = final_memory - start_memory
    
    print(f"Final memory usage: {final_memory:.2f} MB")
    print(f"Memory increase: {memory_increase:.2f} MB")
    
    if memory_increase > 50:  # More than 50MB increase
        print("⚠️ Potential memory leak detected")
```

**Solutions:**
1. **Ensure proper cleanup:**
   ```python
   # Always close clients and servers
   # For RPCPluginClient (executable plugins):
   # client = plugin_client(command=["./my_plugin_executable"]) # Use 'command'
   # try:
   #     await client.start()
   #     # Use client
   # finally:
   #     if client: # Check if client was successfully created
   #         await client.close()
   
   # Correct usage of async with client instance:
   # client_instance = plugin_client(command=["./my_plugin_executable"])
   # async with client_instance:
   #    # client_instance.start() is called by __aenter__
   #    # logger.info(f"Client active, connected to: {client_instance.target_endpoint}")
   #    # ... use client_instance.grpc_channel ...
   # # client_instance.close() is called by __aexit__
   print("Note: Ensure client.close() is called, or use async with on an RPCPluginClient instance for proper cleanup.")
   ```

2. **Monitor connection pools:**
   ```python
   # If implementing application-level pooling of RPCPluginClient instances:
   # configure(...) does not have a 'max_connections' key for this.
   # Monitoring would be part of your custom pool logic.
   
   # Monitor pool usage (conceptual)
   logger.info("Connection pool status", 
              active=pool.active_connections,
              max=pool.max_connections)
   ```

## Configuration Issues

### Server Fails to Start Due to mTLS Requirements

**Symptoms:**
- Server exits prematurely.
- Error logs indicate `SecurityError: Server certificate or key not configured for mTLS/TLS.`
- Or, `Error starting gRPC server: PemSslCredentialsOptions.private_key must be a string` if paths are missing but expected.

**Diagnosis:**
- Check the server's configuration for `PLUGIN_AUTO_MTLS`. If it's `True` (which is the default if not overridden by environment variable or `configure()` call):
    - The server *requires* valid paths for `PLUGIN_SERVER_CERT` (its own certificate) and `PLUGIN_SERVER_KEY` (its private key).
    - For mutual TLS (mTLS, where the server also verifies the client), `PLUGIN_CLIENT_ROOT_CERTS` (the CA(s) to trust for client certificates) must also be set.
- If these are not set, the server cannot start in secure mode.

**Solutions:**
1.  **Run Insecurely (for development/testing or if mTLS is not needed):**
    Explicitly set `PLUGIN_AUTO_MTLS` to `False`.
    ```bash
    export PLUGIN_AUTO_MTLS=False
    # Then run your server script
    ```
    Or, at the beginning of your server script:
    ```python
    from pyvider.rpcplugin import configure
    configure(PLUGIN_AUTO_MTLS=False)
    ```

2.  **Provide Correct Certificates for mTLS:**
    Ensure all required certificate paths are correctly configured via environment variables or `configure()`:
    ```python
    # Example using configure()
    configure(
        PLUGIN_AUTO_MTLS=True,
        PLUGIN_SERVER_CERT="file:///path/to/your/server.crt",
        PLUGIN_SERVER_KEY="file:///path/to/your/server.key",
        PLUGIN_CLIENT_ROOT_CERTS="file:///path/to/your/ca_to_verify_clients.crt"
    )
    ```
    Ensure the certificate files exist at the specified paths and are readable by the server process. Refer to `docs/security.md` and `examples/05_security_mtls.py` for certificate generation.

### Environment Variable Not Found

**Symptoms:**
```
KeyError: 'PLUGIN_MAGIC_COOKIE_VALUE'
```

**Diagnosis:**
```python
def diagnose_config_issue():
    """Diagnose configuration issues."""
    
    from pyvider.rpcplugin.config import CONFIG_SCHEMA
    
    missing_required = []
    
    for key, meta in CONFIG_SCHEMA.items():
        if meta.get("required", False):
            value = os.environ.get(key)
            if value is None:
                missing_required.append(key)
                print(f"❌ Missing required config: {key}")
                print(f"   Description: {meta.get('description', 'No description')}")
                print(f"   Default: {meta.get('default', 'No default')}")
            else:
                print(f"✅ Found config: {key} = {value}")
    
    if missing_required:
        print(f"\nSet missing environment variables:")
        for key in missing_required:
            print(f"export {key}='your-value-here'")

diagnose_config_issue()
```

**Solutions:**
1. **Set required environment variables:**
   ```bash
   export PLUGIN_MAGIC_COOKIE_VALUE="your-secret-cookie"
   export PLUGIN_LOG_LEVEL="INFO"
   ```

2. **Use configuration file:**
   ```python
   from pyvider.rpcplugin.config import load_config_from_file
   load_config_from_file("production.env")
   ```

3. **Programmatic configuration:**
   ```python
   configure(
       PLUGIN_MAGIC_COOKIE_VALUE="your-secret-cookie",
       PLUGIN_PROTOCOL_VERSIONS=[1],
       PLUGIN_SERVER_TRANSPORTS=["unix", "tcp"] # Or PLUGIN_CLIENT_TRANSPORTS
   )
   ```

## Error Messages

### Common Error Patterns

| Error Pattern | Likely Cause | Solution |
|--------------|--------------|----------|
| `Connection refused` | Server not running | Start server, check port |
| `Handshake timeout` | Magic cookie mismatch | Verify magic cookie config |
| `Certificate verify failed` | mTLS misconfiguration | Check certificate chain |
| `Permission denied` | File/socket permissions | Fix file permissions |
| `Address already in use` | Port conflict | Use different port |
| `No such file or directory` | Unix socket missing | Check socket path |
| `SSL: WRONG_VERSION_NUMBER` | HTTP vs HTTPS mismatch | Use correct protocol |
| `UNAVAILABLE: DNS resolution failed` | Network connectivity | Check network/DNS |

### Debug Logging

Enable debug logging for detailed troubleshooting:

```python
from pyvider.rpcplugin import configure

# Enable debug logging
configure(PLUGIN_LOG_LEVEL="DEBUG")

# Or set the environment variable before running your application:
# export PLUGIN_LOG_LEVEL="DEBUG"
```

## Debugging Tools

### gRPC Debug Tools

```python
# Enable gRPC debug logging
import os
os.environ["GRPC_VERBOSITY"] = "DEBUG"
os.environ["GRPC_TRACE"] = "all"

# gRPC reflection for debugging
from grpc_reflection.v1alpha import reflection
from grpc_reflection.v1alpha import reflection_pb2_grpc

# Add reflection to server
reflection.enable_server_reflection(service_names, server)
```

### Network Debugging

```bash
# Test network connectivity
telnet 127.0.0.1 50051

# Monitor network traffic
sudo tcpdump -i any -A 'port 50051'

# Check SSL/TLS handshake
openssl s_client -connect 127.0.0.1:50051 -cert client.crt -key client.key
```

### Process Debugging

```bash
# Monitor system calls
strace -p <pid> -f -e trace=network

# Monitor file operations
lsof -p <pid> -r 1

# Memory profiling
python -m memory_profiler your_script.py

# CPU profiling
python -m cProfile -o profile.stats your_script.py
```

## Common Patterns

### Retry Logic for Transient Failures

```python
import asyncio
import random

async def with_exponential_backoff(
    operation,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0
):
    """Execute operation with exponential backoff."""
    
    for attempt in range(max_retries + 1):
        try:
            return await operation()
        except (TransportError, HandshakeError) as e:
            if attempt == max_retries:
                raise
            
            # Exponential backoff with jitter
            delay = min(base_delay * (2 ** attempt), max_delay)
            jitter = random.uniform(0, 0.1) * delay
            total_delay = delay + jitter
            
            logger.warning(
                f"Operation failed, retrying in {total_delay:.2f}s",
                attempt=attempt + 1,
                max_retries=max_retries,
                error=str(e)
            )
            
            await asyncio.sleep(total_delay)

# Usage
await with_exponential_backoff(lambda: client.connect(endpoint))
```

### Circuit Breaker Pattern

```python
from enum import Enum
import time

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    async def call(self, operation):
        """Execute operation with circuit breaker protection."""
        
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.timeout:
                self.state = CircuitState.HALF_OPEN
            else:
                raise CircuitBreakerError("Circuit breaker is OPEN")
        
        try:
            result = await operation()
            
            # Reset on success
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                logger.warning("Circuit breaker opened", failures=self.failure_count)
            
            raise

# Usage
breaker = CircuitBreaker(failure_threshold=3, timeout=30.0)
result = await breaker.call(lambda: client.call_service())
```

This troubleshooting guide provides comprehensive coverage of common issues and their solutions. For additional help, check the [API Reference](api-reference.md) and [examples](../examples/) directory.
