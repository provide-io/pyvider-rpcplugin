# Chapter 4: Understanding Transports

`pyvider.rpcplugin` supports two primary transport mechanisms for communication between the host application and the plugin:

*   **Unix Domain Sockets (UDS)**:
    *   **Pros**: Highest performance for Inter-Process Communication (IPC) on the same machine. Bypasses the network stack. Sockets are filesystem objects, allowing for filesystem-based permissions.
    *   **Cons**: Limited to communication between processes on the same host. Path length limitations on some systems.
    *   **Use Cases**: Ideal for plugins that always run on the same machine as the host application, where maximum performance and low latency are critical. This is the default preferred transport if available during negotiation.

*   **TCP Sockets**:
    *   **Pros**: Enables communication across a network, allowing plugins to run on different machines than the host. Standard and widely understood.
    *   **Cons**: Higher overhead and latency compared to UDS due to network stack involvement, even on localhost. Requires careful port management.
    *   **Use Cases**: When plugins need to be distributed across different hosts, or if UDS are not suitable for the environment.

The choice of transport is typically negotiated during the handshake. The server announces its supported transports (e.g., `["unix", "tcp"]`), and the client selects one based on its own preferences or capabilities.

## Example: Transport Options (`examples/ch04_transport_options_demo.py`)

This example demonstrates the direct instantiation and configuration of `TCPSocketTransport` and `UnixSocketTransport` objects. While `plugin_server` and `plugin_client` often handle transport creation internally, understanding these classes is useful for custom scenarios or direct transport manipulation.

```python
#!/usr/bin/env python3
# examples/ch04_transport_options_demo.py
import asyncio
import tempfile
from pathlib import Path
from example_utils import configure_for_example, get_example_port

configure_for_example()

from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.telemetry import logger

async def tcp_transport_demo():
    logger.info("🌐 TCP Transport Demo")
    # Directly instantiate TCPSocketTransport
    # port=0 would mean an OS-assigned ephemeral port if this transport were to listen.
    port = get_example_port() # Get a likely available port for demo
    transport = TCPSocketTransport(host="127.0.0.1", port=port)
    logger.info(f"📡 TCP transport configured: {transport}") # Logs the repr
    # To actually use it for listening:
    # endpoint = await transport.listen()
    # logger.info(f"TCP server would listen on: {endpoint}")
    # await transport.close()
    logger.info("✅ TCP transport demo completed")

async def unix_transport_demo():
    logger.info("🔌 Unix Socket Transport Demo")
    with tempfile.NamedTemporaryFile(suffix=".sock", delete=False) as tmp:
        socket_path = tmp.name

    # Directly instantiate UnixSocketTransport
    transport = UnixSocketTransport(path=socket_path)
    logger.info(f"📁 Unix socket transport configured: {transport}") # Logs the repr
    # To actually use it for listening:
    # endpoint = await transport.listen()
    # logger.info(f"Unix server would listen on: {endpoint}")
    # await transport.close()

    Path(socket_path).unlink(missing_ok=True) # Ensure cleanup
    logger.info("✅ Unix transport demo completed")

async def main():
    logger.info("🚀 Transport Options Comparison")
    await tcp_transport_demo()
    await unix_transport_demo()
    logger.info("💡 Transport Selection Guidelines:")
    logger.info("  🌐 TCP: Network communication, multiple hosts.")
    logger.info("  🔌 Unix: Local communication, better performance, default preference.")
    logger.info("✅ Transport comparison completed")

if __name__ == "__main__":
    asyncio.run(main())
```

This example shows:
*   How to create `TCPSocketTransport` with a specific host and port.
*   How to create `UnixSocketTransport` with a specific file path for the socket.
*   It highlights that these transport objects encapsulate the configuration for their respective communication methods.
