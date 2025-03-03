---
title: Handshake Protocol
description: How clients and servers establish communication
---

# Handshake Protocol

The handshake protocol is the elaborate greeting ritual between client and server—think of it as the digital equivalent of those complex handshakes you see athletes perform, except with more security and fewer opportunities to embarrass yourself on national television.

## Purpose of the Handshake

The handshake serves several critical functions:

1. **Verification**: Confirming that the server is a legitimate plugin
2. **Capability Negotiation**: Determining which features both sides support
3. **Transport Establishment**: Setting up the communication channel
4. **Certificate Exchange**: Sharing security credentials (for mTLS)

Without this handshake, the client and server would be like two people speaking different languages, on different phones, trying to arrange a meeting at different cafes—unlikely to succeed.

## Handshake Sequence

The handshake follows a specific sequence of steps:

### 1. Environment Setup

The client sets up environment variables for the server before launching it:

```python
env = os.environ.copy()
env.update({
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "1,2,3,4,5,6,7",
    "PLUGIN_TRANSPORTS": "unix,tcp",
    "PLUGIN_CLIENT_CERT": "<PEM-encoded certificate if using mTLS>"
})
```

These environment variables tell the server:
- How to authenticate itself (magic cookie)
- Which protocol versions the client supports
- Which transport mechanisms the client supports
- The client's certificate for mutual authentication

### 2. Server Startup

The client launches the server as a subprocess:

```python
process = subprocess.Popen(
    ["python", "plugin.py"],
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
```

The server starts up and immediately checks the environment variables.

### 3. Magic Cookie Validation

The server verifies the magic cookie to ensure it's being launched as a plugin:

```python
cookie_key = os.getenv("PLUGIN_MAGIC_COOKIE_KEY")
cookie_value = os.getenv("PLUGIN_MAGIC_COOKIE")
cookie_provided = os.getenv(cookie_key)

if cookie_provided != cookie_value:
    raise HandshakeError("Invalid magic cookie")
```

This is like checking a secret password—if it doesn't match, the server exits immediately. It prevents random programs from accidentally being used as plugins.

### 4. Protocol Negotiation

The server selects the highest protocol version it shares with the client:

```python
client_versions = [int(v) for v in os.getenv("PLUGIN_PROTOCOL_VERSIONS").split(",")]
server_versions = [1, 2, 3, 4, 5, 6, 7]  # Versions the server supports

for version in sorted(client_versions, reverse=True):
    if version in server_versions:
        negotiated_version = version
        break
else:
    raise ProtocolError("No compatible protocol version")
```

It's like finding out which language both you and your conversation partner speak fluently.

### 5. Transport Selection

The server selects a transport method supported by both sides:

```python
client_transports = os.getenv("PLUGIN_TRANSPORTS").split(",")
server_transports = ["unix", "tcp"]  # Transports the server supports

if "unix" in client_transports and "unix" in server_transports and platform != "Windows":
    negotiated_transport = "unix"
elif "tcp" in client_transports and "tcp" in server_transports:
    negotiated_transport = "tcp"
else:
    raise TransportError("No compatible transport")
```

This determines how they'll communicate—like choosing between email, phone, or carrier pigeon based on what's available to both parties.

### 6. Listener Creation

The server creates a listener for the selected transport:

```python
if negotiated_transport == "unix":
    transport = UnixSocketTransport()
    endpoint = await transport.listen()
else:  # tcp
    transport = TCPSocketTransport()
    endpoint = await transport.listen()
```

The server is now ready to accept connections on the specified endpoint.

### 7. Certificate Generation (if using mTLS)

If mutual TLS is enabled, the server generates its certificate:

```python
if auto_mtls:
    server_cert = Certificate(generate_keypair=True)
    cert_data = server_cert.cert
else:
    cert_data = None
```

This is the server's digital ID card that it will present to the client.

### 8. Handshake Response

The server formats a handshake response and writes it to stdout:

```python
# Format: CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
response = f"1|{negotiated_version}|{negotiated_transport}|{endpoint}|grpc|{cert_data or ''}"
sys.stdout.write(response + "\n")
sys.stdout.flush()
```

This response contains all the information the client needs to connect.

### 9. Client Processing

The client reads the handshake response from the server's stdout:

```python
line = await asyncio.wait_for(
    loop.run_in_executor(None, lambda: process.stdout.readline()),
    timeout=10.0
)
response = line.decode().strip()
```

### 10. Connection Establishment

The client parses the response and connects to the endpoint:

```python
core_version, protocol_version, network, address, protocol, server_cert = parse_handshake_response(response)

if network == "tcp":
    transport = TCPSocketTransport()
else:  # unix
    transport = UnixSocketTransport()

await transport.connect(address)
```

### 11. Secure Channel Creation

Finally, the client creates a secure gRPC channel:

```python
if server_cert:
    creds = grpc.ssl_channel_credentials(
        root_certificates=server_cert.encode(),
        private_key=client_key.encode(),
        certificate_chain=client_cert.encode()
    )
    channel = grpc.secure_channel(address, creds)
else:
    channel = grpc.insecure_channel(address)
```

## Handshake Response Format

The handshake response is a single line with pipe-separated fields:

```
CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
```

For example:
```
1|6|unix|/tmp/plugin-12345.sock|grpc|MIICTzCCAbGgAwIBAgIRAJP/P1+ifqlE5YkcTaXW890wCgYI...
```

Each field has specific meaning:

- **CORE_VERSION**: Always "1" for the current handshake protocol
- **PLUGIN_VERSION**: The negotiated protocol version (e.g., "6")
- **NETWORK**: The transport type ("tcp" or "unix")
- **ADDRESS**: The endpoint address (path or host:port)
- **PROTOCOL**: Always "grpc" for the current implementation
- **TLS_CERT**: Base64-encoded server certificate (if using mTLS)

## Error Handling

The handshake can fail in several ways:

- **Invalid Magic Cookie**: Server exits immediately
- **No Compatible Protocol Version**: Server exits with error
- **No Compatible Transport**: Server exits with error
- **Transport Creation Failure**: Server exits with error
- **Certificate Generation Failure**: Server exits with error
- **Handshake Timeout**: Client raises exception

Each error results in early termination, preventing an invalid setup from proceeding. It's like TSA security at airports—either you pass all the checkpoints, or you don't fly at all.

## Next Steps

Now that you understand how clients and servers establish communication, learn about:

- [Security Model](security.md) to explore the authentication mechanisms
- [gRPC Interface](grpc-interface.md) to learn how services are defined
- [Plugin Server Implementation](../guides/server-implementation.md) to see how to implement a plugin server
