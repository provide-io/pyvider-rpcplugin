# Chapter 20: Troubleshooting

This chapter provides guidance on common issues you might encounter while using `pyvider.rpcplugin`, along with general debugging tips.

## Common Issues and Solutions

**1. Handshake Failures (`HandshakeError`)**

Handshake errors occur during the initial establishment of a connection between the client (host application) and the plugin server.

*   **Magic Cookie Mismatch**:
    *   **Symptom**: Error message similar to: `"[HandshakeError] Magic cookie mismatch. Expected: 'expected_value', Received: 'wrong_value'."`
    *   **Cause**: This usually means a mismatch in the magic cookie's secret value or the environment variable name used to pass it. Specifically:
        *   The **client** is configured with a `PLUGIN_MAGIC_COOKIE_KEY` (e.g., `"ACTUAL_COOKIE_ENV_VAR"`) and a `PLUGIN_MAGIC_COOKIE_VALUE` (e.g., `"the_secret"`). The client will set `ACTUAL_COOKIE_ENV_VAR="the_secret"` in the plugin server's environment.
        *   The **server** is also configured with its own `PLUGIN_MAGIC_COOKIE_KEY` (which must match the client's, e.g., `"ACTUAL_COOKIE_ENV_VAR"`) and its own expected `PLUGIN_MAGIC_COOKIE_VALUE` (e.g., `"the_secret"`).
        *   A mismatch occurs if the server's expected `PLUGIN_MAGIC_COOKIE_VALUE` does not match the value it reads from the environment variable (named by its `PLUGIN_MAGIC_COOKIE_KEY`). Or, if the `PLUGIN_MAGIC_COOKIE_KEY` itself differs between client and server configuration, the server might be looking at the wrong environment variable or none at all.
    *   **Solution**:
        1.  Ensure the `PLUGIN_MAGIC_COOKIE_KEY` is configured identically on both the client (for setting the environment variable) and the server (for reading it).
        2.  Ensure the `PLUGIN_MAGIC_COOKIE_VALUE` is configured identically on both the client (as the value to send) and the server (as the value to expect).
        3.  Check for typos, case sensitivity issues, or extra whitespace in these configuration values.

*   **Protocol Version Mismatch**:
    *   **Symptom**: Error message like `"[HandshakeError] No mutually supported protocol version."`
    *   **Cause**: The client and server do not share any common application-level protocol versions.
    *   **Solution**: Check the `PLUGIN_PROTOCOL_VERSIONS` configuration on both the client and server. This should be a comma-separated list of integers (e.g., `"1,2"`). Ensure there's at least one overlapping version number.

*   **mTLS Certificate Issues**:
    *   **Symptom**: Errors often wrapped in `HandshakeError` or `SecurityError`, with messages related to certificate validation, loading, trust, or TLS handshake failures (e.g., "SSL routines", "certificate verify failed").
    *   **Causes & Solutions**:
        *   **Incorrect File Paths**: Ensure `PLUGIN_SERVER_CERT`, `PLUGIN_SERVER_KEY`, `PLUGIN_CLIENT_ROOT_CERTS` (on server), `PLUGIN_CLIENT_CERT`, `PLUGIN_CLIENT_KEY`, `PLUGIN_SERVER_ROOT_CERTS` (on client) point to valid PEM files using `file:///path/to/file.pem` URI format or are direct PEM strings.
        *   **Malformed PEMs**: Certificates or keys might be corrupted or not in proper PEM format. Validate them using tools like `openssl x509 -in cert.pem -text -noout`.
        *   **Trust Issues**:
            *   The server's certificate must be signed by a CA present in the client's `PLUGIN_SERVER_ROOT_CERTS`.
            *   The client's certificate must be signed by a CA present in the server's `PLUGIN_CLIENT_ROOT_CERTS`.
        *   **Expired Certificates**: Check validity periods.
        *   **Private Key Mismatch**: Ensure the private key corresponds to the public certificate.
        *   **Insufficient Permissions**: The process might not have read access to certificate/key files.

*   **Handshake Timeout**:
    *   **Symptom**: `"[HandshakeError] Timed out waiting for handshake response from plugin."`
    *   **Cause**: The plugin executable either failed to start, crashed immediately upon launch, or did not print the complete handshake string to its standard output within the `PLUGIN_HANDSHAKE_TIMEOUT` period (library default is 10s, examples default to 5s via `example_utils.py`).
    *   **Solution**:
        *   Check logs from the plugin server for startup errors.
        *   Verify the plugin command is correct and the executable has permissions.
        *   Ensure the plugin is compatible and correctly implements the handshake output.
        *   If the plugin legitimately takes longer to initialize and print the handshake, consider increasing `PLUGIN_HANDSHAKE_TIMEOUT` via environment variable or client configuration.

**2. Transport Errors (`TransportError`)**

These errors relate to the underlying network communication layer (Unix sockets or TCP).

*   **Connection Refused**:
    *   **Symptom**: Client fails to connect to the address announced by the server during handshake.
    *   **Cause**: The plugin server process might not be listening on the expected address/port, a firewall could be blocking the connection, or the address announced/parsed was incorrect.
    *   **Solution**: Verify server logs to ensure it started and is listening on the correct interface and port/socket path. Check for firewall rules. Debug the handshake string parsing on the client side.
*   **Unix Domain Socket (UDS) Specific Issues**:
    *   **"Socket file does not exist"**: The path announced by the server or used by the client is incorrect or the socket file was prematurely removed.
    *   **"Path exists but is not a socket"**: A regular file or directory exists at the expected socket path.
    *   **Permission Errors**: The client or server process lacks necessary permissions to create, bind to, or connect to the socket file. Check directory and socket file permissions.
    *   **Stale Socket Files**: `RPCPluginServer` attempts to remove stale socket files on startup. If this fails, manual removal might be needed.
*   **TCP Socket Specific Issues**:
    *   **"Address already in use"**: Another process is already using the TCP port the server is trying to bind to.
    *   **Solution**: Choose a different port, stop the conflicting process, or configure the server to use port `0` to dynamically select an available (ephemeral) port (the client will learn this port via the handshake).

**3. Configuration Errors (`ConfigError`)**

*   **Symptom**: Errors like `"[ConfigError] Missing required configuration key: FOO_BAR."`, `"[ConfigError] Invalid value format for configuration key 'BAZ'. Expected type 'int'..."`, or `"[ConfigError] Attempted to set an unknown configuration key: 'QUX'."`
*   **Cause**: Missing or incorrectly formatted environment variables, or typos in programmatic configuration.
*   **Solution**: Refer to **Chapter 18: Configuration Variables** for a complete list of valid keys, their expected types, and default values. Double-check environment variable names and values.

**4. gRPC Errors (`grpc.RpcError` / `grpc.aio.AioRpcError`)**

These errors occur *after* a successful connection and handshake, during an actual RPC call.

*   **Common `grpc.StatusCode`s and Potential Causes**:
    *   `UNAVAILABLE`: Server process might have crashed, restarted, or there's a network interruption. Often retryable.
    *   `UNIMPLEMENTED`: The client called an RPC method that is not implemented on the server (check `.proto` definitions and server-side handler).
    *   `INTERNAL`: An unhandled exception occurred within the server's RPC method implementation. Check server logs for details.
    *   `DEADLINE_EXCEEDED`: The RPC call took longer than the client-side or server-side timeout.
    *   `PERMISSION_DENIED` / `UNAUTHENTICATED`: Issues with authentication or authorization at the gRPC service level (beyond the initial mTLS handshake).
    *   `NOT_FOUND`: A resource requested by the RPC call was not found on the server.
*   **Solution**:
    *   Examine `error.code()` and `error.details()` for specific information.
    *   Check server-side logs for corresponding error messages and stack traces, especially for `INTERNAL` errors.
    *   Verify that request messages are correctly populated by the client.

**5. Server Shutdown / Interrupts (Ctrl-C)**

*   **Server Not Exiting Promptly on Ctrl-C**:
    *   **Behavior**: The `RPCPluginServer` is designed for robust shutdown. When Ctrl-C (SIGINT) is pressed, it initiates a graceful shutdown. This involves stopping the gRPC server (which may have a grace period, e.g., 0.5 seconds by default in `RPCPluginServer.stop()`), closing transports, and cleaning up resources. This process can take a moment.
    *   **Symptom**: Server seems to hang after one Ctrl-C, or requires multiple presses to exit.
    *   **Cause**:
        *   The graceful shutdown process is taking time (e.g., waiting for active requests to complete during the gRPC server's grace period, or transport cleanup delays).
        *   Standard Python/asyncio signal handling can sometimes require a second Ctrl-C to interrupt a process if it's busy or in the middle of certain operations, forcing a more abrupt `KeyboardInterrupt` exception.
    *   **Solution**:
        *   Allow a few seconds for graceful shutdown after the first Ctrl-C.
        *   If the process appears unresponsive, a second Ctrl-C may be necessary to raise a `KeyboardInterrupt` more forcefully.
        *   If issues persist with graceful shutdown not completing, check for custom tasks or operations in your server code that might not be handling `asyncio.CancelledError` correctly during shutdown, thus blocking the completion of `server.stop()`.

## General Debugging Tips

1.  **Enable Debug Logging**:
    *   Set `PLUGIN_LOG_LEVEL="DEBUG"` for both the client (host application) and the plugin server process. This provides verbose logging from `pyvider.rpcplugin` and `pyvider.telemetry`.
    *   The emoji matrix (`PLUGIN_SHOW_EMOJI_MATRIX="true"`) can help visually trace operations.
2.  **Isolate the Problem**:
    *   **Server Standalone**: If possible, try running your plugin server script directly (e.g., `python my_plugin_server.py`). If it has basic environment variable defaults (like `examples/ch05_echo_server.py` does), it should start and print its handshake string. This helps verify the server can initialize correctly.
    *   **Client with Dummy Server**: Test your client application against the `examples/ch02_dummy_server.py` to ensure the client's launch and basic handshake logic is working.
    *   **Direct gRPC Connection**: For a running server, use a tool like `grpcurl` or a minimal direct `grpc.aio` client (like `examples/ch08_direct_client_connection.py`) to test gRPC connectivity and specific RPC methods, bypassing the `pyvider.rpcplugin` client-side handshake initially.
3.  **Check `example_utils.py`**: If you are running or adapting the provided examples, ensure `example_utils.configure_for_example()` is called at the beginning of your scripts. This helper sets up Python paths and some default configurations (like disabling mTLS for basic examples) that are important for the examples to run correctly.
4.  **Simplify**: When troubleshooting, start with the simplest possible configuration:
    *   Disable mTLS (`PLUGIN_AUTO_MTLS="false"` on both client and server).
    *   Use Unix domain sockets first, as they have fewer external dependencies than TCP (like firewalls).
    *   Use a very simple "hello world" or "echo" gRPC service.
    *   Once the basic setup works, incrementally add features like mTLS or more complex services.
5.  **Environment Variables**: Double-check that environment variables are correctly set and propagated to the plugin subprocess, especially `PLUGIN_MAGIC_COOKIE_KEY` and `PLUGIN_MAGIC_COOKIE_VALUE`. The client uses its `PLUGIN_MAGIC_COOKIE_VALUE` to set an environment variable (named by its `PLUGIN_MAGIC_COOKIE_KEY`) for the server. The server reads this environment variable (using its own `PLUGIN_MAGIC_COOKIE_KEY` config) and compares the value to its own `PLUGIN_MAGIC_COOKIE_VALUE` config.
6.  **File Paths**: For configurations involving file paths (certificates, Unix sockets), ensure paths are absolute or correctly relative, and that the processes have the necessary read/write/execute permissions. Remember that `file:///` URIs are supported.
7.  **Python Path (`sys.path`)**: If your plugin has local dependencies or is part of a larger project structure, ensure `PYTHONPATH` is set correctly for the plugin subprocess so it can find its modules. The `examples/example_utils.py` script attempts to manage this for the examples.
