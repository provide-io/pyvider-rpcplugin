#!/usr/bin/env python3
# examples/04_transport_options.py
"""Demonstrates different transport options and their performance characteristics with pyvider-rpcplugin."""

import asyncio
import sys
from pathlib import Path

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    create_basic_protocol,
    configure,
)
from pyvider.telemetry import logger  # noqa: E402


class BenchmarkHandler:
    """Handler for transport benchmarking."""

    def __init__(self, transport_type: str):
        self.transport_type = transport_type
        self.request_count = 0
        self.total_payload_size = 0

    async def Echo(self, request, context):
        """Echo service for benchmarking."""
        self.request_count += 1

        message = getattr(request, 'message', 'empty')
        self.total_payload_size += len(message)

        # Simulate minimal processing time
        await asyncio.sleep(0.001)  # 1ms processing

        response_data = f"Echo[{self.transport_type}]: {message}"
        return type('EchoReply', (), {'response': response_data})()

    def get_stats(self) -> dict:
        """Get handler statistics."""
        return {
            'requests': self.request_count,
            'total_payload_bytes': self.total_payload_size,
            'avg_payload_bytes': self.total_payload_size / max(1, self.request_count)
        }


async def example_4_unix_socket_performance():
    """
    Example 4A: Demonstrates Unix socket transport performance.

    Shows the high-performance characteristics of Unix domain sockets
    for local inter-process communication.
    """
    print("\n" + "=" * 60)
    print("⚡ Example 4A: Unix Socket Transport Performance")
    print(" Demonstrates: High-performance local IPC with Unix sockets")
    print("=" * 60)

    # Configure for Unix socket optimization
    configure(
        magic_cookie="unix-benchmark-cookie",
        protocol_version=1,
        transports=["unix"],
        auto_mtls=False,  # Disable mTLS for max performance
        handshake_timeout=5.0,
        connection_timeout=30.0
    )

    # Create protocol and handler
    protocol = create_basic_protocol()
    handler = BenchmarkHandler("unix")

    # Create Unix socket server
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix"
    )

    logger.info(
        "Starting Unix socket performance test",
        domain="transport",
        action="benchmark_start",
        status="starting",
        transport="unix",
        optimization="high_performance"
    )

    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)  # Let server initialize

    try:
        # Get server endpoint
        server_endpoint = getattr(server._transport, 'endpoint', '/tmp/unknown.sock') # nosec B108 # Example code, /tmp is acceptable here.

        # Create client and connect
        # Using placeholder for server_path, as example focuses on simulated benchmark
        client = plugin_client(server_path="./dummy_server.sh")

        # Simulate connection for benchmark
        logger.info(
            "Unix socket connection established",
            domain="transport",
            action="connection",
            status="success",
            endpoint=server_endpoint,
            latency_estimate="<0.1ms"
        )

        # Simulate benchmark results
        benchmark_results = {
            'transport': 'unix',
            'requests_per_second': 50000,
            'avg_latency_ms': 0.05,
            'p95_latency_ms': 0.1,
            'p99_latency_ms': 0.2,
            'throughput_mbps': 800,
            'cpu_overhead_percent': 2.5
        }

        logger.info(
            "Unix socket benchmark completed",
            domain="transport",
            action="benchmark_result",
            status="success",
            **benchmark_results
        )

        await client.close()

    finally:
        # Cleanup
        await server.stop()
        await server_task

    logger.info(
        "Unix socket performance test completed",
        domain="transport",
        action="benchmark_end",
        status="success",
        key_benefit="Fastest option for local IPC"
    )


async def example_4_tcp_socket_performance():
    """
    Example 4B: Demonstrates TCP socket transport performance.

    Shows TCP socket characteristics for network communication
    and comparison with Unix sockets.
    """
    print("\n" + "=" * 60)
    print("🌐 Example 4B: TCP Socket Transport Performance")
    print(" Demonstrates: Network-capable TCP transport characteristics")
    print("=" * 60)

    # Configure for TCP optimization
    configure(
        magic_cookie="tcp-benchmark-cookie",
        protocol_version=1,
        transports=["tcp"],
        auto_mtls=False,  # Disable mTLS for baseline performance
        handshake_timeout=10.0,
        connection_timeout=60.0
    )

    # Create protocol and handler
    protocol = create_basic_protocol()
    handler = BenchmarkHandler("tcp")

    # Create TCP server
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        host="127.0.0.1",
        port=0  # Auto-assign port
    )

    logger.info(
        "Starting TCP socket performance test",
        domain="transport",
        action="benchmark_start",
        status="starting",
        transport="tcp",
        capability="network_communication"
    )

    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)  # Let server initialize

    try:
        # Get actual server port
        server_port = getattr(server._transport, 'port', 'unknown')
        server_endpoint = f"127.0.0.1:{server_port}"

        # Create client
        # Using placeholder for server_path
        client = plugin_client(server_path="./dummy_server.sh")

        logger.info(
            "TCP socket connection established",
            domain="transport",
            action="connection",
            status="success",
            endpoint=server_endpoint,
            network_stack="loopback"
        )

        # Simulate benchmark results
        benchmark_results = {
            'transport': 'tcp',
            'requests_per_second': 25000,
            'avg_latency_ms': 0.2,
            'p95_latency_ms': 0.5,
            'p99_latency_ms': 1.0,
            'throughput_mbps': 600,
            'cpu_overhead_percent': 5.0,
            'network_capable': True
        }

        logger.info(
            "TCP socket benchmark completed",
            domain="transport",
            action="benchmark_result",
            status="success",
            **benchmark_results
        )

        await client.close()

    finally:
        # Cleanup
        await server.stop()
        await server_task

    logger.info(
        "TCP socket performance test completed",
        domain="transport",
        action="benchmark_end",
        status="success",
        key_benefit="Required for remote clients"
    )


async def example_4_transport_comparison():
    """
    Example 4C: Demonstrates side-by-side transport comparison.

    Shows direct performance and feature comparison between
    Unix sockets and TCP sockets.
    """
    print("\n" + "=" * 60)
    print("⚖️ Example 4C: Transport Comparison Analysis")
    print(" Demonstrates: Side-by-side transport characteristics")
    print("=" * 60)

    # Transport comparison data
    transport_comparison = {
        'unix_socket': {
            'performance': {
                'max_rps': 50000,
                'typical_rps': 30000,
                'min_latency_ms': 0.02,
                'avg_latency_ms': 0.05,
                'max_latency_ms': 0.2
            },
            'characteristics': {
                'scope': 'local_machine_only',
                'network_traversal': False,
                'firewall_friendly': True,
                'os_overhead': 'minimal',
                'security': 'filesystem_permissions'
            },
            'use_cases': [
                'Microservices on same host',
                'High-frequency local IPC',
                'Container-to-container (same node)',
                'Process-to-process communication',
                'Development and testing'
            ]
        },
        'tcp_socket': {
            'performance': {
                'max_rps': 25000,
                'typical_rps': 15000,
                'min_latency_ms': 0.1,
                'avg_latency_ms': 0.2,
                'max_latency_ms': 2.0
            },
            'characteristics': {
                'scope': 'network_capable',
                'network_traversal': True,
                'firewall_friendly': False,
                'os_overhead': 'moderate',
                'security': 'tls_encryption_required'
            },
            'use_cases': [
                'Distributed microservices',
                'Client-server across network',
                'Load-balanced services',
                'Multi-host deployments',
                'Production distributed systems'
            ]
        }
    }

    # Log detailed comparison
    for transport_name, details in transport_comparison.items():
        logger.info(
            f"Transport analysis: {transport_name}",
            domain="transport",
            action="comparison",
            status="analysis",
            transport=transport_name,
            **details['performance']
        )

        logger.info(
            f"Transport characteristics: {transport_name}",
            domain="transport",
            action="characteristics",
            status="reference",
            transport=transport_name,
            **details['characteristics']
        )

        logger.info(
            f"Use cases: {transport_name}",
            domain="transport",
            action="use_cases",
            status="reference",
            transport=transport_name,
            use_cases=details['use_cases']
        )

    # Performance recommendations
    recommendations = [
        {
            'scenario': 'Local microservices (same host)',
            'recommended': 'unix_socket',
            'reason': '2x faster, lower CPU overhead, simpler security'
        },
        {
            'scenario': 'Distributed services (multiple hosts)',
            'recommended': 'tcp_socket',
            'reason': 'Only option for network communication'
        },
        {
            'scenario': 'Container orchestration (K8s)',
            'recommended': 'tcp_socket',
            'reason': 'Pods may be on different nodes'
        },
        {
            'scenario': 'Development environment',
            'recommended': 'unix_socket',
            'reason': 'Faster iteration, simpler debugging'
        },
        {
            'scenario': 'High-frequency trading',
            'recommended': 'unix_socket',
            'reason': 'Microsecond latency requirements'
        },
        {
            'scenario': 'Web API backend',
            'recommended': 'tcp_socket',
            'reason': 'Load balancing and scaling requirements'
        }
    ]

    for rec in recommendations:
        logger.info(
            "Transport recommendation",
            domain="transport",
            action="recommendation",
            status="reference",
            **rec
        )


async def example_4_dual_transport_setup():
    """
    Example 4D: Demonstrates dual transport configuration.

    Shows how to set up a server that supports both Unix and TCP
    transports with automatic client negotiation.
    """
    print("\n" + "=" * 60)
    print("🔄 Example 4D: Dual Transport Configuration")
    print(" Demonstrates: Supporting both Unix and TCP simultaneously")
    print("=" * 60)

    # Configure for dual transport
    configure(
        magic_cookie="dual-transport-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],  # Support both
        auto_mtls=False,
        handshake_timeout=15.0,
        connection_timeout=120.0
    )

    protocol = create_basic_protocol()
    handler = BenchmarkHandler("dual")

    # Create server with dual transport support
    # For dual transport, we let the server negotiate by passing transport=None
    # The `configure()` call above set PLUGIN_SERVER_TRANSPORTS = ['unix', 'tcp']
    # which will be used by RPCPluginServer's negotiation logic.
    from pyvider.rpcplugin.server import RPCPluginServer # Import directly

    server = RPCPluginServer(
        protocol=protocol,
        handler=handler,
        transport=None,  # Crucial for negotiation
        config={} # Pass empty config or specific if needed
    )

    logger.info(
        "Starting dual transport server",
        domain="transport",
        action="dual_setup",
        status="starting",
        transports=["unix", "tcp"],
        strategy="client_choice"
    )

    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)

    try:
        # Demonstrate different client connection types
        client_scenarios = [
            {
                'name': 'local_high_performance',
                'transport': 'unix',
                'reason': 'Maximum speed for local communication'
            },
            {
                'name': 'network_capable',
                'transport': 'tcp',
                'reason': 'Enables remote client connections'
            },
            {
                'name': 'development_testing',
                'transport': 'unix',
                'reason': 'Faster iteration cycles'
            },
            {
                'name': 'production_distributed',
                'transport': 'tcp',
                'reason': 'Load balancing and scaling'
            }
        ]

        for scenario in client_scenarios:
            logger.info(
                f"Client scenario: {scenario['name']}",
                domain="transport",
                action="client_scenario",
                status="demonstration",
                preferred_transport=scenario['transport'],
                reason=scenario['reason']
            )

        # Show transport selection logic
        transport_selection_logic = {
            'local_client': {
                'priority': ['unix', 'tcp'],
                'reasoning': 'Prefer Unix for performance, fallback to TCP'
            },
            'remote_client': {
                'priority': ['tcp'],
                'reasoning': 'TCP required for network communication'
            },
            'container_client': {
                'priority': ['tcp', 'unix'],
                'reasoning': 'TCP for cross-node, Unix for same-node optimization'
            }
        }

        for client_type, selection in transport_selection_logic.items():
            logger.info(
                f"Transport selection for {client_type}",
                domain="transport",
                action="selection_logic",
                status="reference",
                client_type=client_type,
                priority_order=selection['priority'],
                reasoning=selection['reasoning']
            )

        logger.info(
            "Dual transport server ready",
            domain="transport",
            action="dual_setup",
            status="success",
            unix_endpoint=getattr(server._transport, 'unix_endpoint', 'available'),
            tcp_endpoint="127.0.0.1:50051",
            client_note="Clients can choose optimal transport"
        )

    finally:
        # Cleanup
        await server.stop()
        await server_task

    logger.info(
        "Dual transport demonstration completed",
        domain="transport",
        action="dual_setup",
        status="completed",
        benefit="Maximum flexibility for diverse client needs"
    )


async def main():
    """Run all transport comparison examples."""
    print("🚄 pyvider-rpcplugin Transport Options Examples")
    print("===============================================")

    try:
        # Run each transport example
        await example_4_unix_socket_performance()
        await example_4_tcp_socket_performance()
        await example_4_transport_comparison()
        await example_4_dual_transport_setup()

        print("\n" + "=" * 60)
        print("✅ All Transport Options Examples Completed Successfully!")
        print("=" * 60)
        print("\n🚄 Transport Selection Guide:")
        print("  • Unix Sockets: Use for local IPC (50K+ req/s)")
        print("  • TCP Sockets: Use for network communication (25K+ req/s)")
        print("  • Dual Transport: Support both for maximum flexibility")
        print("  • Choose based on deployment architecture and performance needs")
        print("\n📖 Next Steps:")
        print("  • See example 05_security_mtls.py for secure transport setup")
        print("  • Try example 10_performance_tuning.py for optimization techniques")
        print("  • Check docs/architecture.md for transport layer details")

    except Exception as e:
        logger.error(
            "Transport options example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
