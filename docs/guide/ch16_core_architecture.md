# Chapter 16: Core Architecture

The `pyvider.rpcplugin` framework facilitates communication between a host application (client) and one or more plugin processes (servers). Here's an overview of its architecture:

**1. Client-Server Model:**
*   **Host Application (Client)**: Initiates and manages plugins. Uses `RPCPluginClient` to launch plugin executables as subprocesses.
*   **Plugin (Server)**: An external executable that runs an `RPCPluginServer`. It exposes services via gRPC.

**2. Process Launch & Handshake:**
*   When `RPCPluginClient.start()` is called:
    1.  The client launches the plugin executable command as a subprocess.
    2.  Essential environment variables (magic cookie, certificate info if mTLS) are passed to the plugin process.
    3.  The plugin server (`RPCPluginServer`), upon starting, performs its side of the handshake:
        *   Validates the magic cookie received from the environment.
        *   Determines its available transports (Unix socket, TCP) and a suitable endpoint.
        *   Negotiates a common protocol version with the client (implicitly, as the client parses what the server offers).
        *   If mTLS is enabled, it prepares its SSL/TLS credentials.
        *   It then prints a specially formatted **handshake string** to its standard output. This string contains:
            `CORE_VERSION|PLUGIN_VERSION|NETWORK_TYPE|NETWORK_ADDRESS|PROTOCOL_NAME|TLS_CERT_BODY`
    4.  The `RPCPluginClient` reads this handshake string from the plugin's stdout.
    5.  The client parses this string to:
        *   Verify the core protocol version.
        *   Determine the plugin's protocol version.
        *   Identify the network type (`tcp` or `unix`) and address (e.g., `/tmp/socket.sock` or `127.0.0.1:12345`) to connect to.
        *   Get the server's TLS certificate if mTLS is active.
    6.  The client then establishes a gRPC connection to this negotiated endpoint, performing a TLS handshake if mTLS is enabled.

**3. Transport Layer:**
*   **`RPCPluginTransport` (Base Class)**: Defines the interface for transport implementations.
*   **`UnixSocketTransport`**: Uses Unix Domain Sockets for efficient local IPC. Preferred for same-host communication. Handles socket file creation, permissions, and cleanup.
*   **`TCPSocketTransport`**: Uses TCP/IP sockets for network communication (localhost or remote). Handles port binding (can use ephemeral ports).
*   The actual transport mechanism is chosen during the handshake based on server capabilities and client preferences (though client preference isn't explicitly configurable beyond what it supports from the server's announcement).

**4. Protocol Layer (gRPC):**
*   All RPC communication happens over gRPC.
*   Services are defined using `.proto` files, which are compiled into Python code (`_pb2.py` for messages, `_pb2_grpc.py` for stubs and servicers).
*   **`RPCPluginProtocol` (Base Class)**: Your plugin server implements this to tell `RPCPluginServer` about its gRPC services (how to get descriptors and add servicers).
*   **Handler/Servicer**: Your actual service logic, inheriting from the generated gRPC `YourServiceServicer` class.

**5. Security Model:**
*   **Magic Cookie**: A shared secret (`PLUGIN_MAGIC_COOKIE_VALUE` set by the client, read by the server via `PLUGIN_MAGIC_COOKIE_KEY` env var) to prevent unauthorized processes from connecting to a plugin intended for a specific host.
*   **mTLS (Mutual TLS)**:
    *   Enabled by `PLUGIN_AUTO_MTLS="True"`.
    *   Requires both client and server to have certificates signed by a trusted CA (or be self-signed and trusted directly).
    *   Client verifies server's certificate against `PLUGIN_SERVER_ROOT_CERTS`.
    *   Server verifies client's certificate against `PLUGIN_CLIENT_ROOT_CERTS`.
    *   The `crypto.Certificate` class provides utilities for generating and managing these certificates.
    *   The server's certificate (body only, no PEM headers) is transmitted during the initial non-gRPC handshake if mTLS is active.
*   **Process Isolation**: Plugins run as separate processes, limiting the blast radius of a plugin crash.

**6. Configuration (`RPCPluginConfig`):**
*   A singleton (`rpcplugin_config`) manages all settings.
*   Configuration is loaded from environment variables (prefixed with `PLUGIN_`), with type conversion and validation.
*   The `configure()` function provides a simplified way to set common options programmatically.
*   Settings include timeouts, mTLS paths, logging levels, transport preferences, etc.

**7. Standard Services:**
*   `pyvider.rpcplugin` includes standard gRPC services for:
    *   **Stdio**: Streaming stdout/stderr from the plugin to the client.
    *   **Broker**: For managing multiple logical connections or sub-services over a single plugin connection (less commonly used with the typical host-launches-plugin model).
    *   **Controller**: For the client to send control commands to the plugin (e.g., graceful shutdown).
    *   **Health**: Standard gRPC health checking service.

This architecture provides a robust, secure, and performant way to build and manage plugin systems in Python.

A visual representation of the architecture:

```mermaid
graph TB
    ClientApp[Host Application (Client)] -- Manages & Launches --> PluginProcess[Plugin Process (Server)]

    subgraph PluginProcess
        RPCPluginServer[RPCPluginServer Instance]
        UserHandler[User's gRPC Handler/Servicer]
        UserProtocol[User's RPCPluginProtocol Impl.]
        TransportServer[Transport Listener (UDS/TCP)]
        InternalGrpcServer[Internal grpc.aio.Server]
    end

    subgraph ClientApp
        RPCPluginClient[RPCPluginClient Instance]
        UserStub[User's gRPC Stub]
        TransportClient[Transport Connector (UDS/TCP)]
    end

    ClientApp -- Uses --> RPCPluginClient
    RPCPluginClient -- Spawns & Configures --> PluginProcess
    RPCPluginClient -- Manages --> TransportClient
    TransportClient -- Connects to --> TransportServer

    PluginProcess -- Contains --> RPCPluginServer
    RPCPluginServer -- Uses --> UserProtocol
    RPCPluginServer -- Uses --> UserHandler
    RPCPluginServer -- Manages --> TransportServer
    RPCPluginServer -- Manages --> InternalGrpcServer
    UserProtocol -- Registers --> UserHandler -- Implements Service Logic --> InternalGrpcServer

    UserStub -- Makes RPC Calls via --> RPCPluginClient
    RPCPluginClient -- Forwards Calls via --> TransportClient

    style ClientApp fill:#ddeeff,stroke:#333,stroke-width:2px
    style PluginProcess fill:#ffeebb,stroke:#333,stroke-width:2px
```
