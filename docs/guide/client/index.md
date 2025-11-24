# Client Development

Build robust, production-ready plugin clients with comprehensive guides covering setup, resilience, and advanced patterns.

## Quick Start

```python
import asyncio
from pyvider.rpcplugin import plugin_client
from calculator_pb2_grpc import CalculatorStub
from calculator_pb2 import AddRequest

async def main():
    async with plugin_client(command=["python", "calculator.py"]) as client:
        await client.start()

        stub = CalculatorStub(client.grpc_channel)
        result = await stub.Add(AddRequest(a=5, b=3))
        print(f"Result: {result.result}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Documentation Structure

### [Client Development Guide](client-guide/)

**Core Topics:**
- Quick start and basic setup
- Client architecture and lifecycle
- Configuration patterns (client vs plugin)
- Context managers and manual lifecycle
- Advanced patterns (multi-plugin, connection pooling)
- Best practices and troubleshooting

**Perfect for:** Getting started, understanding fundamentals, basic configuration

### [Connection Resilience](resilience/)

**Core Topics:**
- Exception handling and error hierarchy
- Retry strategies (exponential backoff, jitter, circuit breaker)
- Connection management and health monitoring
- Auto-reconnection patterns
- Connection pooling and load balancing
- Best practices for fault-tolerant clients

**Perfect for:** Building production-ready, fault-tolerant clients

### [Direct Connections](direct-connections/)

**Core Topics:**
- Connecting to existing servers (TCP, Unix sockets)
- Environment-based configuration
- Load balancing across multiple servers
- mTLS security for direct connections
- Service discovery integration
- Best practices for microservices

**Perfect for:** Microservices, distributed systems, container deployments

## Learning Paths

=== "Beginner"

    **Goal:** Build your first working plugin client

    1. [Client Guide: Quick Start](client-guide/#quick-start)
    2. [Client Guide: Client Patterns](client-guide/#client-patterns)
    3. [Client Guide: Configuration](client-guide/#configuration)
    4. [Examples: Quick Start](../../examples/quick-start/)
    5. [Examples: Echo Service](../../examples/echo-example/)

    **Next:** Add error handling and retry logic

=== "Intermediate"

    **Goal:** Build resilient, production-ready clients

    1. [Resilience: Exception Handling](resilience/#exception-handling)
    2. [Resilience: Retry Strategies](resilience/#retry-strategies)
    3. [Resilience: Connection Management](resilience/#connection-management)
    4. [Client Guide: Advanced Patterns](client-guide/#advanced-patterns)
    5. [Configuration Guide](../config/)

    **Next:** Implement advanced patterns for microservices

=== "Advanced"

    **Goal:** Master distributed systems and microservices patterns

    1. [Direct Connections](direct-connections/)
    2. [Resilience: Circuit Breaker](resilience/#retry-strategies)
    3. [Resilience: Connection Pooling](resilience/#connection-management)
    4. [Security: mTLS](../security/mtls/)
    5. [Advanced Topics](../advanced/)

    **Next:** Implement service mesh integration

## Common Patterns

### Basic Client with Retry

```python
async def robust_client():
    max_retries = 3

    for attempt in range(max_retries):
        try:
            async with plugin_client(command=["python", "plugin.py"]) as client:
                await client.start()

                stub = CalculatorStub(client.grpc_channel)
                result = await stub.Add(AddRequest(a=5, b=3))
                return result

        except (TransportError, HandshakeError) as e:
            if attempt < max_retries - 1:
                delay = 2 ** attempt
                logger.warning(f"Retry in {delay}s (attempt {attempt + 1}/{max_retries})")
                await asyncio.sleep(delay)
            else:
                raise
```

See [Connection Resilience](resilience/) for comprehensive retry patterns.

### Direct Connection to Existing Server

```python
async def connect_to_service():
    # Connect to running server (no subprocess)
    client = await plugin_client(
        host="plugin-service.internal",
        port=50051,
        skip_subprocess=True
    )

    try:
        stub = CalculatorStub(client.grpc_channel)
        result = await stub.Add(AddRequest(a=10, b=5))
        return result
    finally:
        await client.close()
```

See [Direct Connections](direct-connections/) for microservices patterns.

### Connection Pool for High Performance

```python
from pyvider.rpcplugin import plugin_client

class ClientPool:
    def __init__(self, command: list[str], size: int = 5):
        self.command = command
        self.size = size
        self.connections = []

    async def initialize(self):
        for _ in range(self.size):
            client = plugin_client(command=self.command)
            await client.start()
            self.connections.append(client)

    async def acquire(self):
        # Return available connection
        return self.connections.pop() if self.connections else None

    async def release(self, client):
        # Return to pool
        self.connections.append(client)
```

See [Connection Resilience](resilience/#connection-management) for complete implementation.

## Related Documentation

- **[Server Development](../server/)** - Build plugin servers
- **[Security Guide](../security/)** - mTLS and authentication
- **[Configuration Guide](../config/)** - Environment-driven configuration
- **[Advanced Topics](../advanced/)** - Observability, performance tuning
- **[Examples](../../examples/)** - Complete working examples

## Next Steps

1. **Read [Client Development Guide](client-guide/)** - Understand fundamentals
2. **Study [Connection Resilience](resilience/)** - Add fault tolerance
3. **Explore [Examples](../../examples/)** - See complete implementations
4. **Review [Security Guide](../security/)** - Secure your clients
