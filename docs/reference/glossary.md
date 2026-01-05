# Glossary

**Path:** [Home](../index.md) → [Reference](index.md) → Glossary

## Core Terms

### Foundation

The infrastructure library (`provide.foundation`) that provides configuration management, structured logging, cryptography utilities, and rate limiting for Pyvider RPC Plugin.

### gRPC

Google Remote Procedure Call - A high-performance, open-source RPC framework that uses Protocol Buffers for serialization and HTTP/2 for transport.

### Handler

The class that implements your plugin's business logic, processing incoming RPC requests and returning responses.

### Host Application

The main program that launches and communicates with plugins via RPC.

### Magic Cookie

A shared secret string used during the handshake process to authenticate that a plugin connection is legitimate and trusted.

### mTLS

Mutual Transport Layer Security - A security protocol where both client and server authenticate each other using X.509 certificates.

### Plugin

A separate process that provides specific functionality to a host application via RPC communication.

### Protocol

The interface definition that specifies what RPC methods are available and how messages are structured.

### Protocol Buffers (protobuf)

Google's language-neutral, platform-neutral mechanism for serializing structured data, used to define RPC services and messages.

### Pyvider RPC Plugin

The complete framework for building RPC-based plugin systems in Python, built on top of Foundation.

### RPC

Remote Procedure Call - A protocol that allows a program to execute procedures in another address space (typically on another machine).

### Transport

The underlying communication mechanism used for RPC (Unix domain sockets or TCP sockets).

## Configuration Terms

### Environment Variable

Configuration values set in the system environment, following the pattern `PLUGIN_*` for Pyvider RPC Plugin settings.

### RPCPluginConfig

The configuration class that extends Foundation's `RuntimeConfig` to provide type-safe access to plugin configuration.

### RuntimeConfig

Foundation's base configuration class that provides validation, type conversion, and environment loading.

## Transport Terms

### TCP Socket

Transmission Control Protocol socket - Network communication protocol that works across machines and networks.

### Unix Domain Socket

Inter-process communication socket that works only on the same machine but offers better performance than TCP for local communication.

### Transport Layer

The abstraction layer that handles the actual network communication between host and plugin.

## Security Terms

### Certificate

X.509 digital certificate used for authentication in mTLS connections.

### Certificate Authority (CA)

An entity that issues and validates digital certificates.

### Handshake

The initial connection process where host and plugin authenticate each other and negotiate communication parameters.

### Private Key

The secret cryptographic key used with a certificate for authentication and encryption.

### Process Isolation

Running plugins as separate OS processes to prevent crashes or security issues from affecting the host application.

## Development Terms

### Async/Await

Python's asynchronous programming model used throughout Pyvider RPC Plugin for concurrent operations.

### Factory Function

Helper functions like `plugin_server()` and `plugin_client()` that simplify creating server and client instances.

### Service

A collection of related RPC methods defined in a Protocol Buffer file.

### Servicer

The gRPC term for a class that implements the server-side logic for a service.

### Stub

The gRPC client-side proxy that provides methods for calling remote procedures.

## Lifecycle Terms

### Graceful Shutdown

The process of cleanly stopping a plugin or host, ensuring all resources are properly released.

### Health Check

A mechanism to verify that a plugin is running and responsive, using the gRPC Health Checking Protocol.

### Hot Reload

The ability to update and restart plugins without stopping the host application.

### Subprocess Management

The system for launching, monitoring, and terminating plugin processes.

## Performance Terms

### Batch Processing

Processing multiple requests together for improved efficiency.

### Connection Pool

A cache of reusable connections to improve performance and reduce overhead.

### Rate Limiting

Controlling the rate of requests using Foundation's token bucket algorithm to prevent overload.

### Streaming

Sending or receiving data in chunks rather than all at once, supported by gRPC for large datasets.

## Error Handling Terms

### Circuit Breaker

A pattern that prevents cascading failures by stopping requests to a failing service.

### Retry Logic

Automatic retry of failed requests with configurable backoff strategies.

### Structured Logging

Foundation's logging system that includes contextual information with every log message.

### Timeout

Maximum time allowed for an operation before it's considered failed.

## Usage Conventions

### Consistent Terms

- Use "**magic cookie**" (not "magic cookie value" or "authentication secret")
- Use "**Unix domain sockets**" (not "Unix sockets")
- Use "**TCP sockets**" (not "TCP transport")
- Use "**Foundation**" (capitalized when referring to the library)
- Use "**Pyvider RPC Plugin**" (full name for the framework)

### Configuration Format

Environment variables with JSON arrays must be properly quoted:

```bash
# Correct
export PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'

# Wrong
export PLUGIN_SERVER_TRANSPORTS=["unix", "tcp"]
export PLUGIN_SERVER_TRANSPORTS="unix,tcp"
```

______________________________________________________________________

**Navigation:** [Previous: Reference](index.md) | [Home](../index.md)