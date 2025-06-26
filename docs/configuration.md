# Environment Variable Configuration

This document details all environment variables used to configure the Pyvider RPC Plugin system. These variables allow for fine-grained control over plugin behavior, security, and communication parameters.

## Configuration Methods

There are several ways to configure the Pyvider RPC Plugin system, each with its own use cases.

### 1. Environment Variables (Directly Set)

You can set configuration options by exporting environment variables in your shell. The RPC plugin system will automatically pick these up on initialization. These variables typically use the `PLUGIN_` prefix.

**Example:**
```bash
export PLUGIN_MAGIC_COOKIE_VALUE="mysecretcookie"
export PLUGIN_AUTO_MTLS="true" # Booleans are typically "true" or "false" as strings
export PLUGIN_HANDSHAKE_TIMEOUT="20.5"
export PLUGIN_LOG_LEVEL="DEBUG"
export PLUGIN_SERVER_TRANSPORTS="unix,tcp" # Lists are often comma-separated
```
This method is common for containerized environments and CI/CD pipelines.

### 2. Programmatic Configuration (`configure()` function)

You can configure the system directly in your Python code using the `configure()` function. This is useful for dynamic configurations or when environment variable-based setup is not suitable. Values set via `configure()` affect the in-memory state of the `RPCPluginConfig` singleton.

```python
from pyvider.rpcplugin import configure

configure(
    PLUGIN_MAGIC_COOKIE_VALUE="programmatic-cookie-example", # Use PLUGIN_ prefixed keys
    PLUGIN_AUTO_MTLS=True,
    PLUGIN_HANDSHAKE_TIMEOUT=25.0,
    PLUGIN_LOG_LEVEL="DEBUG",
    PLUGIN_SERVER_TRANSPORTS=["unix"], # Example: configure server transports
    PLUGIN_CLIENT_TRANSPORTS=["unix"]  # Example: configure client transports
)
# The RPCPluginConfig singleton is now updated.
```

## Order of Precedence

The configuration system applies values in the following general order, with later steps overriding earlier ones for the in-memory config state:

1.  **Schema Defaults**: The hardcoded default values defined in `CONFIG_SCHEMA`. These are applied first.
2.  **Environment Variables**: Values present in the environment when the `RPCPluginConfig` singleton is first initialized will override the schema defaults.
3.  **Programmatic `configure()` Calls**: Values passed to `configure()` directly update the in-memory `RPCPluginConfig` state, overriding any values loaded from previous steps (defaults or environment variables). `configure()` does *not* change environment variables themselves.

The `RPCPluginConfig` singleton is initialized once, loading from environment variables at that time. Subsequent calls to `configure()` modify this live instance.

### Configuration via Factory Functions (`plugin_server`, `plugin_client`)

When using factory functions like `plugin_server()` or `plugin_client()`, you can pass a `config: dict[str, Any]` parameter.

-   **`PLUGIN_` prefixed keys**: If you provide keys in this dictionary that start with `PLUGIN_` (e.g., `{"PLUGIN_LOG_LEVEL": "DEBUG"}`), these will be passed to an internal call to `pyvider.rpcplugin.configure()` during the setup of that specific server or client instance. This allows for instance-specific overrides of global configurations for settings like logging, timeouts, etc., for that instance's initialization.
-   **Non-`PLUGIN_` prefixed keys**: Keys that do not start with `PLUGIN_` (e.g., `{"APP_CUSTOM_SETTING": "value"}`) are typically stored as part of the server or client instance's `self.config` attribute. These are not automatically processed by the core `pyvider.rpcplugin` configuration system but can be accessed by your application code (e.g., your custom protocol or handler) from the instance if needed.
-   **gRPC Specific Options**: To pass options directly to the underlying gRPC server (like `max_concurrent_streams`), you might need to use a specific `PLUGIN_` prefixed variable designed for this, such as `PLUGIN_GRPC_OPTIONS`, which would then be interpreted by the server setup logic. Refer to specific documentation for such advanced gRPC configurations.

This `config` parameter provides a way to customize behavior on a per-instance basis when creating clients or servers.

## Magic Cookie Authentication Flow

The "magic cookie" is a shared secret used to verify that the plugin executable was indeed launched by a trusted host application and not by some other means. It's a basic authentication mechanism. Here's how the related configuration variables interact:

*   The **Host Application (Server)**, when preparing to launch a plugin, configures two main variables for itself:
    *   `PLUGIN_MAGIC_COOKIE_KEY`: This defines the *name* of the environment variable the server expects the plugin to have set. For example, if `PLUGIN_MAGIC_COOKIE_KEY` is set to `"MY_PLUGIN_AUTH_TOKEN"`, the server will look for an environment variable named `MY_PLUGIN_AUTH_TOKEN` in the plugin's environment. The default is `"PLUGIN_MAGIC_COOKIE"`.
    *   `PLUGIN_MAGIC_COOKIE_VALUE`: This defines the *expected secret value* of that environment variable. For example, `"supersecretvalue123"`.

*   When the **Host Application launches a Plugin Executable**:
    *   It is the host's responsibility to ensure that the plugin process is started with an environment variable set correctly. The name of this environment variable must match the host's `PLUGIN_MAGIC_COOKIE_KEY`, and its value must match the host's `PLUGIN_MAGIC_COOKIE_VALUE`.
    *   Example: If the server is configured with `PLUGIN_MAGIC_COOKIE_KEY="AUTH_TOKEN"` and `PLUGIN_MAGIC_COOKIE_VALUE="secretXYZ"`, then the plugin executable must be launched with `AUTH_TOKEN="secretXYZ"` in its environment. The `plugin_client()` factory (if used to prepare the command to launch a plugin) automatically sets the environment variable named by `PLUGIN_MAGIC_COOKIE_KEY` to the value of `PLUGIN_MAGIC_COOKIE_VALUE` from its own configuration when launching the plugin subprocess.

*   **Server-Side Validation** (performed by `validate_magic_cookie` in `handshake.py` which is called by `RPCPluginServer`):
    1.  The server retrieves the expected secret value from its own `PLUGIN_MAGIC_COOKIE_VALUE` configuration.
    2.  It retrieves the name of the key it expects the plugin to provide from its own `PLUGIN_MAGIC_COOKIE_KEY` configuration.
    3.  The validation logic then attempts to get the actual cookie value provided by the plugin. This is typically done by reading the environment variable whose name was specified by `PLUGIN_MAGIC_COOKIE_KEY` *from the plugin's environment*. (In `pyvider-rpcplugin`, this check is performed by the server based on its configuration, assuming the plugin's environment variable was set by the launching mechanism).
    4.  **Fallback**: If the environment variable specified by `PLUGIN_MAGIC_COOKIE_KEY` is *not found* (e.g., `os.getenv(server_config.magic_cookie_key())` returns `None`), the server-side validation logic will then use the value of its own `PLUGIN_MAGIC_COOKIE` configuration setting as the "cookie provided by the plugin".
    5.  This "provided cookie" (either from the plugin's environment via `PLUGIN_MAGIC_COOKIE_KEY` or from the server's `PLUGIN_MAGIC_COOKIE` as a fallback) is then compared against the server's expected `PLUGIN_MAGIC_COOKIE_VALUE`. If they match, the handshake continues.

*   **Simplified Configuration (`configure()` helper)**:
    *   When you use `configure(magic_cookie="some_value")`, this helper function sets both `PLUGIN_MAGIC_COOKIE_VALUE` and `PLUGIN_MAGIC_COOKIE` to `"some_value"` in the configuration of the Python process where `configure()` was called.
    *   This is convenient for scenarios where the same application instance might conceptually act as both a host and a plugin (e.g., in tests, or if the plugin is a Python script run via `subprocess` where its environment is directly controllable), or to ensure the fallback mechanism works as expected if the primary environment variable (`PLUGIN_MAGIC_COOKIE_KEY`) isn't set for the plugin.

For robust security, ensure `PLUGIN_MAGIC_COOKIE_VALUE` is a strong, unique secret, and that the plugin executable's environment is correctly populated with this secret under the variable name specified by `PLUGIN_MAGIC_COOKIE_KEY`.

## Detailed Environment Variable List

Below is a detailed list of all supported environment variables, their purposes, types, and default values.

### `PLUGIN_AUTO_MTLS`
- **Description**: Flag to enable automatic mTLS (true/false). If set to true:
  - A **server** will enforce mTLS if `PLUGIN_SERVER_CERT`, `PLUGIN_SERVER_KEY`, and `PLUGIN_CLIENT_ROOT_CERTS` are correctly configured. It will use its own cert/key for its identity and `PLUGIN_CLIENT_ROOT_CERTS` to verify clients.
  - A **client** (if it's a `pyvider-rpcplugin` based executable) will attempt mTLS if `PLUGIN_CLIENT_CERT`, `PLUGIN_CLIENT_KEY`, and `PLUGIN_SERVER_ROOT_CERTS` are configured. It uses its cert/key for its identity and `PLUGIN_SERVER_ROOT_CERTS` to verify the server.
- **Type**: `bool`
- **Default**: `"true"`
- **`.env` Alias**: `PYVIDER_AUTO_MTLS`

### `PLUGIN_CLIENT_CERT`
- **Description**: Path to the client's own identity certificate file (PEM format, or `file://<path>`). Used by the client (if it's a `pyvider-rpcplugin` based executable) to present its identity to the server during mTLS.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_CERT`

### `PLUGIN_CLIENT_ENDPOINT`
- **Description**: Client endpoint for connection.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_ENDPOINT`

### `PLUGIN_CLIENT_KEY`
- **Description**: Path to the client's private key file (PEM format, or `file://<path>`). Used by the client (if it's a `pyvider-rpcplugin` based executable) along with its certificate (`PLUGIN_CLIENT_CERT`) for mTLS.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_KEY`

### `PLUGIN_CLIENT_ROOT_CERTS`
- **Description**: Path to CA certificate file(s) (PEM format, or `file://<path>`) that the **server** uses to verify client certificates in an mTLS setup. This is a server-side setting, used when `PLUGIN_AUTO_MTLS` is true on the server to enable mTLS.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_ROOT_CERTS`

### `PLUGIN_CLIENT_TRANSPORTS`
- **Description**: List of transports supported by the client.
- **Type**: `list_str`
- **Default**: `["unix", "tcp"]`
- **`.env` Alias**: `PYVIDER_CLIENT_TRANSPORTS`
- **Valid Values**: `["unix"]`, `["tcp"]`, `["unix", "tcp"]`, `["tcp", "unix"]`

### `PLUGIN_CONNECTION_TIMEOUT`
- **Description**: Timeout in seconds for connection operations.
- **Type**: `float`
- **Default**: `30.0`
- **`.env` Alias**: `PYVIDER_CONNECTION_TIMEOUT`

### `PLUGIN_CORE_VERSION`
- **Description**: The core RPC Plugin version. This rarely changes.
- **Type**: `int`
- **Default**: `1`

### `PLUGIN_HANDSHAKE_TIMEOUT`
- **Description**: Timeout in seconds for handshake operations.
- **Type**: `float`
- **Default**: `10.0`
- **`.env` Alias**: `PYVIDER_HANDSHAKE_TIMEOUT`

### `PLUGIN_LOG_LEVEL`
- **Description**: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
- **Type**: `str`
- **Default**: `"INFO"`
- **`.env` Alias**: `PYVIDER_LOG_LEVEL`
- **Valid Values**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

### `PLUGIN_MAGIC_COOKIE_KEY`
- **Description**: Specifies the **name** of the environment variable that the plugin host (e.g., your main application using `RPCPluginServer`) expects the plugin executable to provide. The actual secret cookie value will be read by the server from the environment variable with this name in the plugin's runtime environment.
- **Type**: `str`
- **Default**: `"PLUGIN_MAGIC_COOKIE"` (This implies the host should set an environment variable literally named `PLUGIN_MAGIC_COOKIE` for the plugin executable, containing the secret value.)

### `PLUGIN_MAGIC_COOKIE_VALUE`
- **Description**: Specifies the **secret value** that the plugin host (server) expects for authentication. This value is compared against the value provided by the plugin executable (which the server obtains by reading the environment variable named by `PLUGIN_MAGIC_COOKIE_KEY` from the plugin's environment, or by using the fallback `PLUGIN_MAGIC_COOKIE`).
- **Type**: `str`
- **Default**: `"rpcplugin-default-cookie"`
- **`.env` Alias**: `PYVIDER_MAGIC_COOKIE`, `PYVIDER_MAGIC_COOKIE_VALUE` (Note: `PYVIDER_MAGIC_COOKIE` is often used as a shorthand for setting this expected value in `.env` files, which then maps to `PLUGIN_MAGIC_COOKIE_VALUE`.)

### `PLUGIN_MAGIC_COOKIE`
- **Description**: This variable serves as a **fallback value** for the cookie provided by the plugin executable. During server-side validation, if the environment variable specified by `PLUGIN_MAGIC_COOKIE_KEY` (e.g., `PLUGIN_MAGIC_COOKIE`) is *not found* in the plugin's environment, the value of this `PLUGIN_MAGIC_COOKIE` variable (from the server's own configuration) will be used as the 'provided cookie' for comparison against `PLUGIN_MAGIC_COOKIE_VALUE`. Typically, the primary mechanism should be the host setting the correct environment variable for the plugin as specified by `PLUGIN_MAGIC_COOKIE_KEY`.
- **Type**: `str`
- **Default**: `"rpcplugin-default-cookie"`

### `PLUGIN_PROTOCOL_VERSIONS`
- **Description**: List of supported protocol versions.
- **Type**: `list_int`
- **Default**: `[1]`
- **`.env` Alias**: `PYVIDER_PROTOCOL_VERSIONS`

### `PLUGIN_SERVER_CERT`
- **Description**: Path to the server's own identity certificate file (PEM format, or `file://<path>`). Used by the server to present its identity to clients. Required for any form of TLS (including mTLS).
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_CERT`

### `PLUGIN_SERVER_ENDPOINT`
- **Description**: Server endpoint for connection (host:port for TCP, path for Unix).
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_ENDPOINT`

### `PLUGIN_SERVER_KEY`
- **Description**: Path to the server's private key file (PEM format, or `file://<path>`). Used by the server along with its certificate (`PLUGIN_SERVER_CERT`). Required for any form of TLS (including mTLS).
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_KEY`

### `PLUGIN_SERVER_ROOT_CERTS`
- **Description**: Path to CA certificate file(s) (PEM format, or `file://<path>`) that the **client** uses to verify the server's certificate in an mTLS or server-auth TLS setup. This is a client-side setting.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_ROOT_CERTS`

### `PLUGIN_SERVER_TRANSPORTS`
- **Description**: List of transports supported by the server.
- **Type**: `list_str`
- **Default**: `["unix", "tcp"]`
- **`.env` Alias**: `PYVIDER_SERVER_TRANSPORTS`
- **Valid Values**: `["unix"]`, `["tcp"]`, `["unix", "tcp"]`, `["tcp", "unix"]`

### `PLUGIN_SHOW_EMOJI_MATRIX`
- **Description**: Show emoji matrix in logs for better visual tracking.
- **Type**: `bool`
- **Default**: `"true"`
- **`.env` Alias**: `PYVIDER_SHOW_EMOJI_MATRIX`

### `SUPPORTED_PROTOCOL_VERSIONS`
- **Description**: The Plugin Protocol Versions that `rpcplugin` will support.
- **Type**: `list_int`
- **Default**: `[1, 2, 3, 4, 5, 6, 7]`
