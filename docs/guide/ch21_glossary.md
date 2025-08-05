# Chapter 21: Glossary

This glossary defines key terms and concepts used throughout the `pyvider.rpcplugin` documentation and codebase.

*   **API (Application Programming Interface)**: A contract that allows software components to communicate with each other, defining the types of calls or requests that can be made, how to make them, the data formats that should be used, etc.

*   **Async/Await**: Keywords in Python used for asynchronous programming with `asyncio`. `async def` defines a coroutine (an awaitable function), and `await` pauses the execution of the coroutine until the awaited operation (typically I/O-bound) completes.

*   **attrs**: A Python package that helps in writing concise and correct classes with less boilerplate. Used by `pyvider.rpcplugin` for some data classes.

*   **CA (Certificate Authority)**: An entity that issues digital certificates. CAs are a critical part of Public Key Infrastructure (PKI) and are used in TLS/mTLS to verify the authenticity of certificates.

*   **Client (Host Application)**: In the context of `pyvider.rpcplugin`, this is the main application that initiates communication with and typically manages the lifecycle (launching, stopping) of one or more plugin processes.

*   **Configuration Schema (`CONFIG_SCHEMA`)**: A dictionary within `pyvider.rpcplugin.config` that defines all recognized `PLUGIN_` prefixed configuration variables, their types, default values, and descriptions.

*   **`configure()` function**: A helper function in `pyvider.rpcplugin.config` for programmatically setting multiple common configuration options.

*   **gRPC (gRPC Remote Procedure Calls)**: A high-performance, open-source, universal RPC framework developed by Google. `pyvider.rpcplugin` uses gRPC as its underlying mechanism for communication between the client and plugin server.

*   **Handler (Servicer)**: In gRPC terminology, a "servicer" is the server-side implementation of the RPC methods defined in a `.proto` service definition. In `pyvider.rpcplugin`, this is often referred to as the "handler".

*   **Handshake**: The initial, out-of-band (not over gRPC) communication process between the `RPCPluginClient` and `RPCPluginServer` when a plugin is launched. It involves:
    1.  The server printing a formatted string to its standard output.
    2.  The client reading and parsing this string.
    This process negotiates the core protocol version, application protocol version, transport type (TCP/Unix), network address, and exchanges the server's TLS certificate if mTLS is enabled. It's also authenticated using a magic cookie.

*   **IPC (Inter-Process Communication)**: Mechanisms that allow different processes, potentially running on the same machine or across a network, to exchange data and synchronize their actions.

*   **Magic Cookie**: A shared secret string used for basic authentication during the handshake. The client is configured with a `PLUGIN_MAGIC_COOKIE_VALUE` (the secret string) and a `PLUGIN_MAGIC_COOKIE_KEY` (the name of an environment variable). The client sets this environment variable for the plugin server process, with the `PLUGIN_MAGIC_COOKIE_VALUE` as its value. The server, also configured with the same `PLUGIN_MAGIC_COOKIE_KEY` and expected `PLUGIN_MAGIC_COOKIE_VALUE`, reads the environment variable and verifies its value. This helps ensure the plugin is run by a trusted host.

*   **mTLS (Mutual Transport Layer Security)**: A security protocol where both the client and the server authenticate each other using X.509 digital certificates before establishing a secure, encrypted communication channel.

*   **Plugin**: An external program or script that runs in its own process and provides specific services or functionality to a host application. In `pyvider.rpcplugin`, plugins run an `RPCPluginServer`.

*   **`.proto` file**: A text file using Protocol Buffer language to define service interfaces (RPC methods) and the structure of data messages that are exchanged.

*   **Protocol Buffers (Protobufs)**: A language-neutral, platform-neutral, extensible mechanism developed by Google for serializing structured data. It's used by gRPC to define services and message formats, offering efficient serialization and type safety.

*   **`RPCPluginClient`**: The core class in `pyvider.rpcplugin` used by the host application to launch, manage, and communicate with a plugin executable.

*   **`RPCPluginProtocol`**: An abstract base class in `pyvider.rpcplugin`. Implementations of this class bridge user-defined gRPC services (handlers/servicers) with the `RPCPluginServer`, telling it how to register and expose those services.

*   **`RPCPluginServer`**: The core class in `pyvider.rpcplugin` used within a plugin executable to set up and run the gRPC server, handle the handshake, and manage the plugin's lifecycle.

*   **`rpcplugin_config`**: The singleton instance of `RPCPluginConfig` that holds all global configuration settings for `pyvider.rpcplugin`.

*   **Serialization**: The process of converting a data structure or object into a format (e.g., a byte stream) that can be stored or transmitted, and then reconstructed later (deserialization). Protocol Buffers handle this for gRPC.

*   **Stub (Client Stub)**: In gRPC, a client-side object generated from a `.proto` file. It provides methods that mirror the server's RPC methods. Calling a method on a stub triggers the RPC call to the server.

*   **Transport**: The underlying communication mechanism used for sending data between the client and server. `pyvider.rpcplugin` supports:
    *   **TCP Sockets**: For network-based communication.
    *   **Unix Domain Sockets (UDS)**: For efficient IPC on the same machine.

*   **UDS (Unix Domain Socket)**: A data communications endpoint for exchanging data between processes executing on the same host operating system, represented as a file in the filesystem.
