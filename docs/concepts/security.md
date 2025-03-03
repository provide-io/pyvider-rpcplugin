---
title: Security Model
description: Authentication and encryption in Pyvider RPC Plugin
---

# Security Model

The security model in Pyvider RPC Plugin ensures that communication between client and server is both authenticated and encrypted. It's like having a soundproof room with guards checking IDs at both doors—nobody gets in without proper credentials, and nobody can eavesdrop on the conversation.

## Mutual TLS Authentication

The primary security mechanism is mutual TLS (mTLS), where both client and server authenticate each other using X.509 certificates. This bidirectional authentication ensures that:

1. The client knows it's talking to the intended server
2. The server knows it's talking to the intended client
3. All communication is encrypted

This is different from standard TLS (as used in HTTPS), where typically only the server authenticates to the client. With mTLS, both parties check each other's ID cards.

## Certificate Management

### Certificate Generation

When auto-mTLS is enabled, both client and server generate ephemeral certificates:

```python
# Client-side
client_cert = Certificate(
    generate_keypair=True,
    key_type="ecdsa",
    common_name="localhost"
)

# Server-side
server_cert = Certificate(
    generate_keypair=True,
    key_type="ecdsa",
    common_name="localhost"
)
```

These certificates include:
- A private key (RSA or ECDSA)
- A self-signed X.509 certificate with proper extensions
- A common name of "localhost" (since communication is local)
- Key usage flags for digital signatures and key encipherment

Think of these as temporary, automatically generated passports that only last for the duration of the conversation.

### Certificate Exchange

The certificate exchange happens during the handshake:

1. **Client to Server**: The client passes its certificate to the server via the `PLUGIN_CLIENT_CERT` environment variable.
2. **Server to Client**: The server includes its certificate in the handshake response on stdout.

```
# Handshake response format
CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
```

This exchange of certificates is like showing your credentials before entering a secured facility, except happening automatically and cryptographically.

### Certificate Validation

Once certificates are exchanged, each side validates the other's certificate:

```python
# Client-side validation
channel = grpc.secure_channel(
    endpoint,
    grpc.ssl_channel_credentials(
        root_certificates=server_cert.encode(),
        private_key=client_key.encode(),
        certificate_chain=client_cert.encode()
    )
)

# Server-side validation
server = grpc.server(...)
server.add_secure_port(
    endpoint,
    grpc.ssl_server_credentials(
        [(server_key.encode(), server_cert.encode())],
        root_certificates=client_cert.encode(),
        require_client_auth=True
    )
)
```

The validation ensures:
- The certificate is properly formatted
- The certificate hasn't expired
- The certificate is cryptographically valid
- The certificate matches the expected one from the exchange

## Security Configurations

Several security configurations are available:

### Auto mTLS (Default)

The auto-mTLS mode handles everything automatically:
- Generates temporary certificates
- Manages certificate exchange
- Sets up secure channels with proper validation

This is the easiest and recommended approach—like having a security system that automatically arms itself when you leave and disarms when you return.

### Manual Certificate Management

For advanced use cases, you can manually provide certificates:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={
        "PLUGIN_CLIENT_CERT": my_cert_pem,
        "PLUGIN_CLIENT_KEY": my_key_pem
    }
)

server = RPCPluginServer(
    protocol=MyProtocol(),
    handler=MyHandler(),
    config={
        "PLUGIN_SERVER_CERT": server_cert_pem,
        "PLUGIN_SERVER_KEY": server_key_pem
    }
)
```

This allows for using persistent certificates, certificate chains, or integration with certificate management systems—like bringing your own custom-designed security badge instead of using the standard visitor pass.

### Insecure Mode (Not Recommended)

For testing or in fully trusted environments, you can disable security:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={"PLUGIN_AUTO_MTLS": "false"}
)
```

This is like leaving your door unlocked—convenient, but not recommended unless you live in an exceptionally safe neighborhood with trustworthy neighbors.

## Certificate Implementation

The `Certificate` class handles all aspects of certificate management:

```python
class Certificate:
    """Encapsulates X.509 certificate functionality."""
    
    def __init__(
        self,
        cert: str | None = None,
        key: str | None = None,
        generate_keypair: bool = False,
        key_type: str = "ecdsa",
        key_size: int = 2048,
        ecdsa_curve: str = "secp384r1",
        common_name: str = "localhost",
        alt_names: list[str] = None,
        organization_name: str = "HashiCorp",
        **kwargs
    ) -> None:
        # Handles loading or generating certificates
```

Key features include:
- Support for both RSA (2048, 3072, 4096 bit) and ECDSA (secp256r1, secp384r1, secp521r1)
- PEM format handling
- Certificate validation
- Trust chain management
- Detailed logging of certificate operations

## Security Considerations

When using Pyvider RPC Plugin, keep these security considerations in mind:

1. **Process Isolation**: Even with mTLS, plugins run with the same user permissions as the host. Use OS-level isolation mechanisms for additional security.

2. **Certificate Handling**: Temporary certificates are stored in memory only. Never write private keys to disk.

3. **Environment Variables**: Environment variables used for certificate exchange are sensitive. Ensure they aren't logged or exposed.

4. **Go Compatibility**: When working with go-plugin, use ECDSA with secp521r1 curve for maximum compatibility.

5. **Certificate Reuse**: By default, each connection uses fresh certificates. If reusing certificates, ensure proper key management practices.

## Next Steps

Now that you understand the security model, explore:

- [Transport Layer](transport.md) to learn about the secured communication channels
- [gRPC Interface](grpc-interface.md) to see how secured services are defined
- [Server Implementation](../guides/server-implementation.md) for practical security configuration
