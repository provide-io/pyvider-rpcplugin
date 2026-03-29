# Direct Connections

Connect directly to running plugin servers without launching subprocesses - ideal for microservices, distributed systems, and server-to-server communication.

## Overview

Direct connections enable clients to connect to already-running plugin servers via network protocols (TCP or Unix sockets), bypassing subprocess management.

**Use Cases:**
- Microservice architectures and service meshes
- Load-balanced plugin pools
- Cross-machine/cross-container communication
- Development and testing environments
- Server-to-server communication patterns

## Basic Patterns

=== "TCP Connection"

    Connect directly to a TCP server:

    ```python
    from pyvider.rpcplugin import plugin_client
    from calculator_pb2_grpc import CalculatorStub
    from calculator_pb2 import AddRequest

    async def connect_to_tcp_server():
        """Connect directly to a TCP server."""

        # Connect to running server
        client = await plugin_client(
            host="localhost",
            port=50051,
            skip_subprocess=True  # Direct connection
        )

        try:
            # Use gRPC stub as normal
            stub = CalculatorStub(client.grpc_channel)
            result = await stub.Add(AddRequest(a=5, b=3))
            print(f"Result: {result.result}")

        finally:
            await client.close()
    ```

=== "Unix Socket"

    Connect via Unix domain socket (Linux/macOS only):

    ```python
    async def connect_unix_socket():
        """Connect via Unix domain socket."""

        client = await plugin_client(
            unix_socket="/tmp/plugin.sock",
            skip_subprocess=True
        )

        try:
            stub = CalculatorStub(client.grpc_channel)
            result = await stub.Add(AddRequest(a=10, b=5))
            return result
        finally:
            await client.close()
    ```

=== "Environment-Based"

    Configure from environment variables:

    ```python
    import os
    from dataclasses import dataclass

    @dataclass
    class DirectConnectionConfig:
        """Configuration for direct connections."""

        host: str = os.environ.get("PLUGIN_SERVER_HOST", "localhost")
        port: int = int(os.environ.get("PLUGIN_SERVER_PORT", "50051"))
        timeout: float = float(os.environ.get("PLUGIN_TIMEOUT", "30.0"))

        # mTLS configuration
        client_cert: str | None = os.environ.get("PLUGIN_CLIENT_CERT")
        client_key: str | None = os.environ.get("PLUGIN_CLIENT_KEY")
        ca_cert: str | None = os.environ.get("PLUGIN_CA_CERT")

    # Usage
    config = DirectConnectionConfig()
    client = await plugin_client(
        host=config.host,
        port=config.port,
        skip_subprocess=True,
        timeout=config.timeout
    )
    ```

## Advanced Patterns

=== "Load Balancing"

    Distribute requests across multiple servers:

    ```python
    import random

    class LoadBalancedClient:
        """Client with load balancing across servers."""

        def __init__(self, endpoints: list[dict]):
            """
            Args:
                endpoints: [{"host": "server1", "port": 50051, "weight": 2}, ...]
            """
            self.endpoints = endpoints
            self.clients = []
            self.weights = []

        async def connect_all(self):
            """Connect to all endpoints."""
            for endpoint in self.endpoints:
                client = await plugin_client(
                    host=endpoint["host"],
                    port=endpoint["port"],
                    skip_subprocess=True
                )
                self.clients.append(client)
                self.weights.append(endpoint.get("weight", 1))

        async def call(self, stub_class, method_name: str, request):
            """Make load-balanced RPC call."""
            # Weighted random selection
            client = random.choices(self.clients, weights=self.weights)[0]

            try:
                stub = stub_class(client.grpc_channel)
                method = getattr(stub, method_name)
                return await method(request)
            except Exception as e:
                # Retry on different server
                for other_client in self.clients:
                    if other_client != client:
                        try:
                            stub = stub_class(other_client.grpc_channel)
                            method = getattr(stub, method_name)
                            return await method(request)
                        except:
                            continue
                raise

    # Usage
    endpoints = [
        {"host": "server1", "port": 50051, "weight": 3},
        {"host": "server2", "port": 50051, "weight": 2},
        {"host": "server3", "port": 50051, "weight": 1}
    ]

    lb_client = LoadBalancedClient(endpoints)
    await lb_client.connect_all()

    result = await lb_client.call(CalculatorStub, "Add", AddRequest(a=5, b=3))
    ```

=== "Connection Pooling"

    See [Connection Resilience](resilience.md) for complete connection pool implementation with health monitoring.

## Security

=== "mTLS Configuration"

    Secure direct connections with mTLS:

    ```python
    import ssl
    from pathlib import Path

    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_cert_chain("/etc/ssl/client.pem", "/etc/ssl/client.key")
    ssl_context.load_verify_locations("/etc/ssl/ca.pem")
    ssl_context.check_hostname = True

    # Connect with mTLS
    client = await plugin_client(
        host="secure.example.com",
        port=443,
        skip_subprocess=True,
        ssl_context=ssl_context
    )
    ```

    See [Security Guide](../security/) for comprehensive mTLS setup.

=== "Authentication"

    Add authentication to direct connections:

    ```python
    class AuthenticatedClient:
        """Direct client with authentication."""

        def __init__(self, host: str, port: int, api_key: str):
            self.host = host
            self.port = port
            self.api_key = api_key
            self.token = None

        async def connect(self):
            """Connect and authenticate."""
            self.client = await plugin_client(
                host=self.host,
                port=self.port,
                skip_subprocess=True
            )

            # Authenticate to get token
            stub = AuthStub(self.client.grpc_channel)
            auth_response = await stub.Authenticate(
                AuthRequest(api_key=self.api_key)
            )
            self.token = auth_response.token

        async def call(self, stub_class, method_name: str, request):
            """Make authenticated call."""
            if not self.token:
                await self.connect()

            # Add auth token to metadata
            metadata = [("authorization", f"Bearer {self.token}")]

            stub = stub_class(self.client.grpc_channel)
            method = getattr(stub, method_name)
            return await method(request, metadata=metadata)
    ```

## Service Discovery

Integrate with service registries for dynamic endpoint discovery:

```python
async def discover_and_connect(service_name: str):
    """Discover service via Consul and connect."""
    import consul.aio

    # Discover service
    c = consul.aio.Consul(host="localhost", port=8500)
    _, services = await c.health.service(service_name, passing=True)

    if not services:
        raise Exception(f"No healthy {service_name} instances found")

    # Connect to first available
    service = services[0]
    client = await plugin_client(
        host=service["Service"]["Address"],
        port=service["Service"]["Port"],
        skip_subprocess=True
    )

    return client
```

See [Connection Resilience](resilience.md) for complete service discovery patterns and health monitoring.

## Best Practices

1. **Use Environment Variables** - Configure host/port from environment
2. **Implement Health Checks** - Monitor connection health
3. **Add Retry Logic** - Handle transient failures (see [Resilience Guide](resilience.md))
4. **Secure with mTLS** - Always use encryption for production
5. **Pool Connections** - Reuse connections efficiently
6. **Load Balance** - Distribute load across multiple servers
7. **Service Discovery** - Integrate with service registries
8. **Monitor Metrics** - Track connection performance

## Next Steps

- **[Connection Resilience](resilience.md)** - Health monitoring, retry logic, connection pools
- **[Client Development Guide](client-guide.md)** - Basic client setup and configuration
- **[Security Guide](../security/)** - Comprehensive mTLS setup
- **[Examples](../../examples/)** - Complete working examples
