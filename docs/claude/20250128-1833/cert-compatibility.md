# Certificate Compatibility Strategy: go-plugin and Python gRPC

## Problem Statement

1. **go-plugin Constraints**:
   - Uses `secp521r1` curve exclusively
   - Curve selection is hardcoded
   - Cannot be configured externally

2. **Python gRPC Constraints**:
   - Cannot connect to servers using `secp521r1` certificates
   - Built-in SSL handling cannot be modified
   - No OpenSSL context access

3. **Key Discovery**:
   - A Python client using `secp521r1` CAN connect to a `secp384r1` server
   - This suggests a possible workaround

## Solution Strategy

### 1. Client-Side Implementation
```python
def generate_client_keypair():
    """Generate client certificates using secp521r1"""
    # Must use P-521 for client certs to match go-plugin expectations
    return ec.generate_private_key(
        ec.SECP521R1(),
        default_backend()
    )

def create_client_certificate(private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Create client certificate using secp521r1"""
    return create_self_signed_x509_certificate(
        private_key=private_key,
        common_name="localhost",
        alt_names=["localhost"],
        organization_name="HashiCorp"
    )
```

### 2. Server-Side Implementation
```python
def generate_server_keypair():
    """Generate server certificates using secp384r1"""
    # Use P-384 for server to ensure Python gRPC can connect
    return ec.generate_private_key(
        ec.SECP384R1(),
        default_backend()
    )

def create_server_certificate(private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """Create server certificate using secp384r1"""
    return create_self_signed_x509_certificate(
        private_key=private_key,
        common_name="localhost",
        alt_names=["localhost"],
        organization_name="HashiCorp"
    )
```

### 3. Test Implementation

```python
@pytest.fixture(scope="module")
def certificates():
    """Generate both client and server certificates"""
    # Client certs (P-521 for go-plugin compatibility)
    client_key = generate_client_keypair()
    client_cert = create_client_certificate(client_key)
    
    # Server certs (P-384 for Python gRPC compatibility)
    server_key = generate_server_keypair()
    server_cert = create_server_certificate(server_key)
    
    return {
        "client": {
            "key": client_key,
            "cert": client_cert,
            "pem": client_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "key_pem": client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        },
        "server": {
            "key": server_key,
            "cert": server_cert,
            "pem": server_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "key_pem": server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        }
    }

@pytest.mark.asyncio
async def test_certificate_compatibility(certificates):
    """Test certificate compatibility between client and server"""
    # Setup client (using P-521)
    client_config = {
        "cert_pem": certificates["client"]["pem"],
        "key_pem": certificates["client"]["key_pem"]
    }
    
    # Setup server (using P-384)
    server_config = {
        "cert_pem": certificates["server"]["pem"],
        "key_pem": certificates["server"]["key_pem"]
    }
    
    # Test connection
    async with setup_test_server(server_config) as server:
        async with setup_test_client(client_config) as client:
            assert await client.connect()
```

### 4. Handshake Modification

```python
async def perform_handshake(self):
    """Modified handshake to handle certificate curve differences"""
    try:
        # Generate P-521 client certificate for go-plugin
        client_key = generate_client_keypair()
        client_cert = create_client_certificate(client_key)
        
        # Set environment for go-plugin
        os.environ["PLUGIN_CLIENT_CERT"] = client_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        
        # Perform handshake
        await self._perform_handshake()
        
        # Server will return P-384 certificate during TLS handshake
        # Python gRPC will handle this automatically
        
    except Exception as e:
        logger.error(f"Handshake failed: {e}")
        raise HandshakeError(f"Handshake failed: {e}")
```

## Implementation Notes

1. **Certificate Generation**:
   - Always use `secp521r1` for client certificates
   - Always use `secp384r1` for server certificates
   - Keep certificate generation separate from usage

2. **Testing Considerations**:
   - Test both certificate types explicitly
   - Verify curve types in tests
   - Test full handshake flow

3. **Error Handling**:
   - Add specific error messages for certificate issues
   - Log curve types during connection attempts
   - Add diagnostic information to exceptions

4. **Security Considerations**:
   - Both curves provide adequate security
   - Document curve usage in security documentation
   - Monitor for any changes in go-plugin certificate handling

## Migration Path

1. Update all certificate generation code
2. Modify test fixtures
3. Update handshake implementation
4. Add logging and monitoring
5. Update documentation

This solution should allow the Python client to work with go-plugin while maintaining compatibility and security.
