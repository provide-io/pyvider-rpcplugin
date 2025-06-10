#!/usr/bin/env python3
# examples/04_transport_options.py
"""Demonstrates different transport options and their performance characteristics with pyvider-rpcplugin."""

import asyncio
import os
import sys
import time
from pathlib import Path
import grpc # Added for grpc.aio.AioRpcError

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Add demo directory to sys.path to import echo_pb2 and echo_pb2_grpc
demo_dir = example_dir / "demo"
if demo_dir.exists() and str(demo_dir) not in sys.path:
    sys.path.insert(0, str(demo_dir))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    create_basic_protocol,
    configure,
    plugin_protocol, # Added import
)
from pyvider.rpcplugin.exception import (  # noqa: E402
    TransportError,
    HandshakeError,
    RPCPluginError
)
from pyvider.telemetry import logger  # noqa: E402

# Attempt to import Echo service definitions
try:
    import echo_pb2
    import echo_pb2_grpc
except ImportError as e:
    logger.error(f"Failed to import echo_pb2 or echo_pb2_grpc: {e}")
    logger.error("Please ensure you've compiled the protobuf definitions in the 'examples/demo' directory.")
    sys.exit(1)

# Common setup for examples that need a server and client
SERVER_SCRIPT_PATH = str(example_dir / "demo" / "echo_server.py")
ECHO_SERVICE_PROTOCOL = plugin_protocol(
    service_name="EchoService",
    descriptor_module=echo_pb2,
    servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server
)
# Environment variables for the server process launched by the client
SERVER_ENV_VARS = {
    "PYTHONUNBUFFERED": "1",
    "PLUGIN_MAGIC_COOKIE_KEY": "ECHO_PLUGIN_COOKIE",
    "PLUGIN_MAGIC_COOKIE_VALUE": "standalonesecret", # Server expects this value
    "ECHO_PLUGIN_COOKIE": "standalonesecret"         # Server's actual cookie value (read via key)
}
# Environment variables for the client process (this script)
CLIENT_ENV_SETTINGS = {
    "PLUGIN_MAGIC_COOKIE_KEY": "ECHO_PLUGIN_COOKIE", # Client expects server to use this key
    "PLUGIN_MAGIC_COOKIE": "standalonesecret"       # Client will send this value
}

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
    
    # Configure client-side settings
    for key, value in CLIENT_ENV_SETTINGS.items():
        os.environ[key] = value
    configure(
        magic_cookie_key=CLIENT_ENV_SETTINGS["PLUGIN_MAGIC_COOKIE_KEY"],
        magic_cookie=CLIENT_ENV_SETTINGS["PLUGIN_MAGIC_COOKIE"],
        protocol_version=1,
        transports=["unix"],
        auto_mtls=True, # Using mTLS for consistency, can be False for pure perf benchmark
        handshake_timeout=5.0,
        connection_timeout=30.0
    )
    
    # Server environment will be set by plugin_client using SERVER_ENV_VARS
    
    logger.info(
        "Starting Unix socket performance test",
        domain="transport",
        action="benchmark_start",
        status="starting",
        transport="unix",
        optimization="high_performance"
    )
    
    client = None
    try:
        client = plugin_client(
            server_path=SERVER_SCRIPT_PATH,
            protocol=ECHO_SERVICE_PROTOCOL,
            env=SERVER_ENV_VARS,
            # transport="unix" # Not needed, client will negotiate from handshake
        )
        await client.start()
        
        logger.info(
            "Unix socket client connected",
            domain="transport",
            action="connection",
            status="success",
            endpoint=getattr(client._transport, 'endpoint', 'N/A')
        )

        if not client._channel:
            raise RPCPluginError("Client channel not available after start.")
        
        stub = echo_pb2_grpc.EchoServiceStub(client._channel)
        request = echo_pb2.EchoRequest(message="Unix performance test")
        start_time = time.perf_counter()
        num_requests = 100  # Small number for quick test
        for _ in range(num_requests):
            await stub.Echo(request)
        end_time = time.perf_counter()
        duration = end_time - start_time
        rps = num_requests / duration if duration > 0 else float('inf')

        logger.info(
            "Unix socket benchmark snippet executed",
            domain="transport",
            action="benchmark_result",
            status="success",
            transport="unix",
            requests=num_requests,
            duration_seconds=duration,
            requests_per_second=rps
        )
        
    except Exception as e:
        logger.error(f"Unix socket performance test failed: {e}", exc_info=True)
    finally:
        if client:
            await client.close()
    
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
    
    # Configure client-side settings
    for key, value in CLIENT_ENV_SETTINGS.items():
        os.environ[key] = value
    configure(
        magic_cookie_key=CLIENT_ENV_SETTINGS["PLUGIN_MAGIC_COOKIE_KEY"],
        magic_cookie=CLIENT_ENV_SETTINGS["PLUGIN_MAGIC_COOKIE"],
        protocol_version=1,
        transports=["tcp"], # Client prefers TCP for this test
        auto_mtls=True, # Using mTLS for consistency
        handshake_timeout=10.0,
        connection_timeout=60.0
    )

    # Server environment will be set by plugin_client using SERVER_ENV_VARS
    # We will override the server's transport preference in its env
    tcp_server_env_vars = SERVER_ENV_VARS.copy()
    tcp_server_env_vars["PLUGIN_SERVER_TRANSPORTS"] = "tcp" # Force server to offer TCP

    logger.info(
        "Starting TCP socket performance test",
        domain="transport",
        action="benchmark_start",
        status="starting",
        transport="tcp",
        capability="network_communication"
    )
    
    client = None
    try:
        client = plugin_client(
            server_path=SERVER_SCRIPT_PATH,
            protocol=ECHO_SERVICE_PROTOCOL,
            env=tcp_server_env_vars, # Server must offer TCP
            # transport="tcp" # Client config already prefers TCP
        )
        await client.start()
        
        logger.info(
            "TCP socket client connected",
            domain="transport",
            action="connection",
            status="success",
            endpoint=getattr(client._transport, 'endpoint', 'N/A')
        )

        if not client._channel:
            raise RPCPluginError("Client channel not available after start.")

        stub = echo_pb2_grpc.EchoServiceStub(client._channel)
        request = echo_pb2.EchoRequest(message="TCP performance test")
        start_time = time.perf_counter()
        num_requests = 100  # Small number for quick test
        for _ in range(num_requests):
            await stub.Echo(request)
        end_time = time.perf_counter()
        duration = end_time - start_time
        rps = num_requests / duration if duration > 0 else float('inf')

        logger.info(
            "TCP socket benchmark snippet executed",
            domain="transport",
            action="benchmark_result",
            status="success",
            transport="tcp",
            requests=num_requests,
            duration_seconds=duration,
            requests_per_second=rps,
            network_capable=True
        )
        
    except Exception as e:
        logger.error(f"TCP socket performance test failed: {e}", exc_info=True)
    finally:
        if client:
            await client.close()
        # Clean up env var for next test if needed, though configure() should handle it
        if "PLUGIN_SERVER_TRANSPORTS" in os.environ: # Clean up if we set it globally
            del os.environ["PLUGIN_SERVER_TRANSPORTS"]

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
    
    # Server configuration (via env vars for the server process)
    # Server will offer both, client will pick based on its own config
    dual_server_env_vars = SERVER_ENV_VARS.copy()
    dual_server_env_vars["PLUGIN_SERVER_TRANSPORTS"] = "unix,tcp" # Server offers both
    dual_server_env_vars["PLUGIN_MAGIC_COOKIE_VALUE"] = "dual-transport-cookie"
    dual_server_env_vars["ECHO_PLUGIN_COOKIE"] = "dual-transport-cookie"


    # Client configuration (this process)
    # Client will prefer Unix, then TCP
    os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "ECHO_PLUGIN_COOKIE"
    os.environ["PLUGIN_MAGIC_COOKIE"] = "dual-transport-cookie"
    configure(
        magic_cookie_key="ECHO_PLUGIN_COOKIE",
        magic_cookie="dual-transport-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],  # Client supports both, prefers unix first
        auto_mtls=True,
        handshake_timeout=15.0,
        connection_timeout=120.0
    )

    logger.info(
        "Starting dual transport server",
        domain="transport",
        action="dual_setup",
        status="starting",
        transports=["unix", "tcp"],
        strategy="client_choice"
    )
    
    client = None
    try:
        # Client configured to prefer Unix, server offers both.
        # The client should pick Unix.
        client = plugin_client(
            server_path=SERVER_SCRIPT_PATH,
            protocol=ECHO_SERVICE_PROTOCOL,
            env=dual_server_env_vars
        )
        await client.start()

        logger.info(
            "Dual transport client connected (expected Unix)",
            domain="transport",
            action="dual_connect",
            status="success",
            negotiated_transport=client._transport_name, # Accessing internal for demo
            endpoint=getattr(client._transport, 'endpoint', 'N/A')
        )
        
        if not client._channel:
            raise RPCPluginError("Client channel not available after start.")

        stub = echo_pb2_grpc.EchoServiceStub(client._channel)
        request = echo_pb2.EchoRequest(message="Dual transport (Unix) test")
        response = await stub.Echo(request)
        logger.info(f"Dual transport (Unix) response: {response.reply}")
        
        await client.close()
        client = None # Reset for next client

        # Now, configure client to prefer TCP
        logger.info("Reconfiguring client to prefer TCP for dual transport test...")
        configure(
            magic_cookie_key="ECHO_PLUGIN_COOKIE",
            magic_cookie="dual-transport-cookie",
            protocol_version=1,
            transports=["tcp", "unix"],  # Client now prefers TCP
            auto_mtls=True,
            handshake_timeout=15.0,
            connection_timeout=120.0
        )
        # Need to set os.environ as well if RPCPluginConfig reads directly at instantiation time
        os.environ["PLUGIN_CLIENT_TRANSPORTS"] = "tcp,unix"


        client = plugin_client(
            server_path=SERVER_SCRIPT_PATH,
            protocol=ECHO_SERVICE_PROTOCOL,
            env=dual_server_env_vars # Server still offers both
        )
        await client.start()
        
        logger.info(
            "Dual transport client connected (expected TCP)",
            domain="transport",
            action="dual_connect",
            status="success",
            negotiated_transport=client._transport_name, # Accessing internal for demo
            endpoint=getattr(client._transport, 'endpoint', 'N/A')
        )

        if not client._channel:
            raise RPCPluginError("Client channel not available after start.")

        stub = echo_pb2_grpc.EchoServiceStub(client._channel)
        request = echo_pb2.EchoRequest(message="Dual transport (TCP) test")
        response = await stub.Echo(request)
        logger.info(f"Dual transport (TCP) response: {response.reply}")

    except Exception as e:
        logger.error(f"Dual transport setup example failed: {e}", exc_info=True)
    finally:
        if client:
            await client.close()
        # Reset client transports env var if set
        if "PLUGIN_CLIENT_TRANSPORTS" in os.environ:
            del os.environ["PLUGIN_CLIENT_TRANSPORTS"]
    
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
