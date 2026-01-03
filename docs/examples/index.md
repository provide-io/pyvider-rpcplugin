# Examples

Practical examples and code snippets demonstrating common Pyvider RPC Plugin patterns and use cases.

## Quick Reference

| Example | Description | Complexity | Lines |
|---------|-------------|------------|-------|
| [Quick Start](quick-start/) | Focused code samples for specific features | 🟢 Beginner | ~20-30 each |
| [Echo Service](echo-example/) | Complete RPC service from basic to production | 🟢-🟡 Beginner to Advanced | ~570 |

## Getting Started

### New to pyvider-rpcplugin?

Start here to learn the fundamentals:

1. **[Quick Start Examples](quick-start/)** - Six focused examples covering:
   - Basic client and server setup
   - Health checks and rate limiting
   - TCP transport configuration
   - Custom protocol implementation

2. **[Echo Service Example](echo-example/)** - Complete service demonstrating:
   - Unary RPC patterns
   - Streaming (server, client, bidirectional)
   - Error handling and retry logic
   - Production features (health, rate limiting, metrics, security)

### Learning Paths

=== "Beginner Track"

    **Goal**: Understand core plugin lifecycle and basic patterns

    1. **[Quick Start: Basic Server](quick-start/#basic-server)** - Minimal server (15 lines)
    2. **[Quick Start: Basic Client](quick-start/#basic-client)** - Minimal client (20 lines)
    3. **[Echo Service: Basic Setup](echo-example/#basic-setup)** - Complete RPC service
    4. **[Quick Start: Health Checks](quick-start/#health-checks)** - Production monitoring
    5. **[Quick Start: Rate Limiting](quick-start/#rate-limiting)** - Service protection

    **Next**: Explore streaming patterns in the Echo Service example

=== "Intermediate Track"

    **Goal**: Master streaming, transports, and custom protocols

    1. **[Echo Service: Streaming Patterns](echo-example/#streaming-patterns)** - Server/client/bidirectional streaming
    2. **[Quick Start: TCP Transport](quick-start/#tcp-transport)** - Cross-platform communication
    3. **[Quick Start: Custom Protocol](quick-start/#custom-protocol)** - Integrate your gRPC services
    4. **[Echo Service: Error Handling](echo-example/#error-handling)** - Robust error management

    **Next**: Study production deployment in the Configuration Guide

=== "Advanced Track"

    **Goal**: Build production-focused, observable, secure services

    1. **[Echo Service: Production Features](echo-example/#production-features)** - Health, rate limiting, metrics, mTLS
    2. **[Echo Service: Testing](echo-example/#testing)** - Unit and integration test patterns
    3. **[Advanced Topics Guide](../guide/advanced/)** - Observability, performance tuning
    4. **[Security Guide](../guide/security/)** - Comprehensive mTLS setup

    **Next**: Implement custom middleware and observability

## Example Structure

### Quick Start Examples

Six focused examples (15-30 lines each) demonstrating specific features:

```python
# Basic Server (15 lines)
async def main():
    protocol = plugin_protocol()
    handler = object()
    server = plugin_server(protocol=protocol, handler=handler)
    await server.serve()
```

See **[Quick Start Examples](quick-start/)** for all patterns.

### Echo Service Example

Comprehensive example (576 lines) covering:

- **Basic Setup** - Unary RPC with client/server implementation
- **Streaming Patterns** - Server, client, and bidirectional streaming
- **Error Handling** - Validation, retry, graceful degradation
- **Production Features** - Health, rate limiting, metrics, mTLS, testing

See **[Echo Service Example](echo-example/)** for complete details.

## Running Examples

### Installation

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Install dependencies
uv sync
```

### Quick Start Examples

```bash
# Basic client (launches basic_server.py automatically)
python examples/short/basic_client.py

# Health check server
python examples/short/health_check.py

# Rate limited server
python examples/short/rate_limiting.py

# TCP transport server
python examples/short/tcp_transport.py

# Custom protocol server
python examples/short/custom_protocol.py
```

### Echo Service Example

```bash
# Run echo client (launches echo_server.py automatically)
python examples/echo_client.py
```

Expected output:
```
2025-01-15 10:30:45.123 [info     ] Client will use server script: .../examples/echo_server.py
2025-01-15 10:30:45.200 [info     ] Starting Echo Plugin Server...
2025-01-15 10:30:45.201 [info     ] EchoService handler registered with gRPC server
2025-01-15 10:30:45.250 [info     ] Client started and connected successfully
2025-01-15 10:30:45.251 [info     ] Sending Echo request to server: 'Hello from pyvider client!'
```

## Example Files Reference

### Documentation vs. Actual Code

!!! tip "Simplified Examples vs. Runnable Files"
    Documentation examples are **simplified for teaching**. Actual files in `examples/` include:

    - `example_utils.configure_for_example()` for environment setup
    - Comprehensive error handling and logging
    - Production-focused patterns and best practices

    Here's the mapping:

    | Documentation | Actual File | Notes |
    |--------------|-------------|-------|
    | Basic plugin | `dummy_server.py` | Minimal server with BasicRPCPluginProtocol |
    | Basic client | `quick_start_client.py` | Client that launches `dummy_server.py` |
    | Echo server | `echo_server.py` ✓ | Matches documentation (production patterns) |
    | Echo client | `echo_client.py` ✓ | Matches documentation (class-based) |

### Available Files

```
examples/
├── short/                           # Quick start examples (15-30 lines)
│   ├── basic_client.py              # Minimal client connection
│   ├── basic_server.py              # Minimal server setup
│   ├── health_check.py              # Health check implementation
│   ├── rate_limiting.py             # Rate limiting example
│   ├── tcp_transport.py             # TCP transport configuration
│   └── custom_protocol.py           # Custom protocol example
├── echo_server.py                   # Echo service server (comprehensive)
├── echo_client.py                   # Echo service client (production-focused)
├── quick_start_client.py            # Basic client launching dummy_server.py
├── dummy_server.py                  # Minimal plugin server
├── proto/                           # Protocol Buffer definitions
│   └── echo.proto                   # Echo service definition
├── example_utils.py                 # Shared utilities for examples
└── run_all_examples.py              # Script to run all examples
```

See the [repository](https://github.com/provide-io/pyvider-rpcplugin/tree/main/examples) for additional advanced examples.

## Common Issues

### Import Errors
If you get "ModuleNotFoundError":
- Ensure you're running from the project root directory
- Run `uv sync` to install dependencies
- The `example_utils.configure_for_example()` call should handle path setup

### Connection Issues
If client can't connect to server:
- Check server logs for errors (logs go to stderr)
- Verify no other process is using the socket/port
- Try increasing timeout: `await asyncio.wait_for(client.start(), timeout=30.0)`

### Transport Issues
If Unix sockets or TCP transport fails:
- **Unix sockets**: Not available on Windows - use TCP instead
- **TCP**: Check firewall allows the port
- **Port conflicts**: Try different port or use `port=0` for automatic assignment
- Verify port availability: `lsof -i :50051`

## Next Steps

### Explore Guides

- **[Server Guide](../guide/server/)** - Server-side patterns and optimization
- **[Client Guide](../guide/client/)** - Client-side patterns and error handling
- **[Configuration Guide](../guide/config/)** - Environment-driven configuration
- **[Security Guide](../guide/security/)** - Comprehensive mTLS setup
- **[Advanced Topics](../guide/advanced/)** - Observability, performance, custom protocols

### Study Concepts

- **[RPC Architecture](../guide/concepts/rpc-architecture/)** - Understanding the plugin model
- **[Transport Configuration](../guide/concepts/transports/)** - Unix sockets vs TCP
- **[Security Model](../guide/concepts/security/)** - Authentication and encryption

### Get Help

- **[API Reference](../reference/)** - Technical API documentation
- **[GitHub Issues](https://github.com/provide-io/pyvider-rpcplugin/issues)** - Report bugs
- **[GitHub Discussions](https://github.com/provide-io/pyvider-rpcplugin/discussions)** - Ask questions

## Contributing Examples

We welcome contributions! Please:

1. Follow the established structure and naming conventions
2. Include comprehensive documentation and comments
3. Add appropriate error handling and logging
4. Test examples on multiple platforms (Linux, macOS, Windows where applicable)
5. Submit a pull request with your example

See the [Contributing Guide](../development/contributing/) for details.
