# Auto mTLS Implementation Specifications

## Core Requirements

### Certificate Generation

```python
def generate_cert() -> Tuple[bytes, bytes]:
    """
    Generate temporary certificate for plugin authentication.
    Returns (cert_pem, private_key_pem)
    """
```

#### Key Generation Parameters

- **Algorithm**: ECDSA with P-521 curve (SECP521R1)
- **Source**: Must use cryptographically secure random number generator
- **Format**: Both cert and key must be PEM encoded

#### Certificate Parameters

- **Serial Number**: 128-bit random number
- **Subject/Issuer**:
  - Common Name: "localhost"
  - Organization: "HashiCorp"
- **Validity Period**:
  - Not Before: Current time minus 30 seconds
  - Not After: Current time plus 30 years (262980 hours)
- **DNS Names**: ["localhost"]
- **Extended Key Usage**:
  - Client Authentication
  - Server Authentication
- **Key Usage**:
  - Digital Signature
  - Key Encipherment
  - Key Agreement
  - Certificate Sign
- **Basic Constraints**:
  - CA: TRUE
  - Must be marked as valid

### TLS Configuration

#### Server Side

```python
def create_server_tls_config(client_cert_pem: str) -> SSLContext:
    """Create server TLS configuration with client verification."""
```

Requirements:
1. Parse client certificate from PEM
2. Create certificate pool with client cert
3. Generate server certificate/key pair
4. Configure TLS settings:
   - Minimum Version: TLS 1.2
   - Client Auth: Required and Verified
   - Client CA Pool: Contains client cert
   - Root CA Pool: Contains client cert
   - Server Name: "localhost"

#### Client Side

```python
def create_client_tls_config(server_cert_b64: str) -> SSLContext:
    """Create client TLS configuration with server verification."""
```

Requirements:

1. Generate client certificate/key pair
2. Parse server certificate from base64 (no padding)
3. Configure TLS settings:
   - Minimum Version: TLS 1.2
   - Client Auth: Required
   - Root CA Pool: Contains server cert
   - Server Name: "localhost"

### Handshake Protocol

#### Certificate Exchange

1. Client generates certificate/key pair
2. Client sets PLUGIN_CLIENT_CERT environment variable with PEM cert
3. Server reads PLUGIN_CLIENT_CERT
4. Server generates certificate/key pair
5. Server returns base64 encoded certificate (no padding) in handshake

#### Server Response Format

```
CoreProtocolVersion|PluginProtocolVersion|Network|Address|Protocol|ServerCert
```

Example:
```
1|5|unix|/tmp/plugin123.sock|grpc|MIIBIjANBgkqhkiG9w...
```

## Implementation Notes

### Critical Requirements

1. Base64 encoding of server certificate MUST NOT include padding within the handshake
2. Serial numbers MUST be randomly generated
3. Certificates MUST be self-signed
4. Client MUST verify server cert matches received cert
5. Server MUST verify client cert matches environment variable

### Error Handling

1. Invalid certificate format
2. Certificate verification failure
3. TLS handshake timeout
4. Protocol version mismatch
5. Network errors

### Security Considerations

1. Private keys must never be written to disk
2. Certificates are temporary and single-use
3. No external CA trust
4. Verify all certificate fields
5. Implement proper cleanup

## Default Configuration

```python
TLS_CONFIG = {
    'curve': 'secp521r1',
    'min_version': 'TLS1_2',
    'verify_mode': 'CERT_REQUIRED',
    'server_name': 'localhost',
    'check_hostname': True,
    'handshake_timeout': 30.0,
}
```

## Integration Points

### Environment Variables

```python
REQUIRED_ENV = {
    'PLUGIN_CLIENT_CERT': 'PEM encoded client certificate',
    'PLUGIN_PROTOCOL_VERSIONS': 'Comma separated versions',
    'PLUGIN_MAGIC_COOKIE_KEY': 'Authentication key',
    'PLUGIN_MAGIC_COOKIE_VALUE': 'Authentication value',
}
```

### gRPC Integration

```python
def create_grpc_channel(tls_config: SSLContext) -> grpc.Channel:
    """Create secure gRPC channel with TLS config."""
    credentials = grpc.ssl_channel_credentials(
        root_certificates=tls_config.get_ca_certs(),
        private_key=tls_config.get_private_key(),
        certificate_chain=tls_config.get_certificate()
    )
    return grpc.secure_channel(target, credentials)
```

### Cross-Platform Considerations

1. Unix socket permissions on Unix systems
2. TCP fallback on Windows
3. Path handling differences
4. Process isolation variations
5. Entropy source availability

## Testing Requirements

1. Certificate Generation
   - Verify all required fields
   - Check key usage flags
   - Validate validity periods
   - Test with different curves

2. TLS Configuration
   - Verify minimum version
   - Check client authentication
   - Test certificate validation
   - Verify hostname checking

3. Protocol Compatibility
   - Test with go-plugin
   - Verify handshake protocol
   - Check certificate exchange
   - Validate gRPC integration

4. Error Handling
   - Invalid certificates
   - Network failures
   - Protocol mismatches
   - Resource cleanup
