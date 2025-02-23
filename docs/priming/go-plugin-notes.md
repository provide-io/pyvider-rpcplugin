# Core Protocol Implementation Details

## Protocol Versioning

1. Core Protocol Version: 1 (constant, increment breaks compatibility)
2. Plugin Protocol Versions: Negotiated between client/server:

   ```go
   SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]  
   ```

   - Server picks highest mutual version supported by both sides
   - Must match exactly on handshake

## Handshake Protocol Details

1. Server validates `PLUGIN_MAGIC_COOKIE` environment variable provided by client

2. Client must write handshake line to stdout in format:

   ```
   CORE_PROTOCOL_VERSION|PLUGIN_PROTOCOL_VERSION|NETWORK|ADDRESS|PROTOCOL_TYPE|TLS_CERT
   ```

3. Network Types:

   - Unix: Creates temp file with random name
   - TCP: Uses random available port between configured min/max
   
4. Socket Configuration:

   - TCP: Defaults to `127.0.0.1`
   - Unix: Creates socket in configured temp directory
   - Unix sockets support configurable group ownership 

## Transport Behaviors

### TCP Transport

1. Port Selection Logic:

   ```go
   // Try ports in sequence until one works
   for port := minPort; port <= maxPort; port++ {
       address := fmt.Sprintf("127.0.0.1:%d", port)
       listener, err := net.Listen("tcp", address)
       if err == nil {
           return listener, nil
       }
   }
   ```

### Unix Socket Transport

1. Socket Creation:

   - Creates temp file
   - Removes file
   - Creates Unix domain socket at same path
   - Optional group ownership settings

2. Socket Cleanup:

   ```go
   // Wrapped listener removes socket file on close
   func (l *rmListener) Close() error {
       l.Listener.Close()
       return os.Remove(path)
   }
   ```

## Connection Management

1. Connection Timeouts:

   - Handshake timeout: 5 seconds
   - RPC timeout: Configurable, defaults to 60 seconds
   - Keep alive enabled for TCP connections

2. Error Handling:

   ```go
   // Core error types
   HandshakeError    // Handshake protocol errors
   ProtocolError     // Protocol version mismatch 
   TransportError    // Network transport errors
   SecurityError     // TLS/certificate errors
   ```

3. Cleanup Behaviors:

   - Proper socket file cleanup
   - Process termination
   - Stream closure
   - Resource cleanup

## Protocol Multiplexing Support

1. GRPC Multiplexing:

   - Optional feature for GRPC transport
   - Controlled by environment variable
   - Separate control and data streams
   - Backwards compatible

   ```go
   if os.Getenv("PLUGIN_MULTIPLEX_GRPC") != "" {
       // Enable multiplexing
   }
   ```

2. Stream Management:

   - Stream IDs start at 1 and increment
   - Bidirectional streaming supported
   - Independent flow control per stream

## Process Control

1. Signal Handling:

   - Captures and ignores SIGINT
   - Clean shutdown on SIGTERM
   - Process exit codes preserved

2. Reattachment Support:

   - Can reattach to existing process
   - Requires process ID and network address
   - Validates connection on reattach

## Client-Server Communication

1. Standard Streams:

   - Stdout used for handshake
   - Stderr forwarded to host
   - Optional stream sync support
   - Buffered stream handling

2. RPC Methods:

   - Ping for health check
   - Shutdown for clean exit
   - Stream multiplexing control
   - Plugin dispenser

## Logging Integration

1. Built-in Logging:

   - JSON formatted by default
   - Structured logging support
   - Level-based filtering
   - Plugin stderr capture

## Environment Variables

Required:

```go
PLUGIN_MAGIC_COOKIE_KEY     // Cookie key for validation
PLUGIN_MAGIC_COOKIE        // Cookie value for validation
PLUGIN_PROTOCOL_VERSIONS   // Supported versions
PLUGIN_TRANSPORTS         // Supported transports
```

Optional:

```go
PLUGIN_MIN_PORT          // Minimum TCP port
PLUGIN_MAX_PORT         // Maximum TCP port
PLUGIN_MULTIPLEX_GRPC  // Enable GRPC multiplexing
PLUGIN_UNIX_SOCKET_GROUP // Unix socket group
```

These details should be considered essential implementation requirements for Python compatibility with the Go plugin system.
