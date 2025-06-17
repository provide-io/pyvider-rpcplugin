# Environment Variable Configuration

This document details all environment variables used to configure the Pyvider RPC Plugin system. These variables allow for fine-grained control over plugin behavior, security, and communication parameters.

They can be set directly in your shell environment or loaded from configuration files (`.env`, `json`, `yaml`) as described in the main README.

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

### 2. Configuration Files

Configuration can be loaded from files using the `load_config_from_file(config_file_path: str)` function. This is a powerful way to manage settings for different environments or to centralize configuration.

**Behavior of `load_config_from_file()`:**
1.  **File Reading**: It accepts a path to a configuration file. Supported formats are:
    *   `.env`: Standard dotenv file format.
    *   `.json`: JSON formatted configuration.
    *   `.yaml` or `.yml`: YAML formatted configuration. (Requires `PyYAML` to be installed).
2.  **Parsing and Key Mapping**:
    *   **`.env` files**: Parsed line by line. Lines starting with `#` or empty lines are ignored. `KEY=VALUE` pairs are processed. Keys prefixed with `PYVIDER_` are mapped to their corresponding `PLUGIN_` equivalents (e.g., `PYVIDER_LOG_LEVEL` becomes `PLUGIN_LOG_LEVEL`). Other keys are used as-is. Values can optionally be quoted (quotes are stripped).
    *   **`.json` and `.yaml`/`.yml` files**: Parsed using standard library `json` or `PyYAML` (if available). Keys from these files are mapped from common shorter names to their `PLUGIN_` prefixed environment variable names (e.g., a top-level JSON key `log_level` becomes `PLUGIN_LOG_LEVEL`). Refer to `KEY_MAPPING_JSON_YAML` in `config.py` for the specific mappings. Unmapped keys are typically uppercased and used directly.
3.  **Environment Variable Setting**:
    *   For each key-value pair derived from the file (after key mapping), an environment variable is set using `os.environ[key] = str(value)`.
    *   If a value from a JSON or YAML file is a list, it's converted into a comma-separated string before being set as an environment variable (e.g., `["unix", "tcp"]` becomes `"unix,tcp"`).
4.  **Configuration Reload**: After processing the entire file and setting all corresponding environment variables, the function calls `RPCPluginConfig.instance().reload()`. This forces the singleton configuration object to re-read all its values from the (now updated) environment variables and schema defaults.

**YAML Support Note**: If you intend to use `.yaml` or `.yml` configuration files, you must have the `PyYAML` library installed in your Python environment (`pip install pyyaml`). If `PyYAML` is not found when `load_config_from_file()` attempts to process a YAML file, a warning will be logged, and the processing of that specific YAML file will be skipped. Other file types will still be processed if specified.

**Note on Key Mappings (Conceptual):** The system uses internal mappings like `KEY_MAPPING_JSON_YAML` (for JSON/YAML short keys to `PLUGIN_` keys) and `KEY_MAPPING_DOTENV` (for `PYVIDER_` to `PLUGIN_` keys). While you don't interact with these mappings directly, understanding they exist helps clarify how file keys translate to environment variables. You can always use the canonical `PLUGIN_` prefixed keys directly in any file type if you prefer to bypass the mapping.

#### a. JSON File

Create a JSON file (e.g., `config.json`):
```json
{
  "magic_cookie": "json-cookie-example",
  "auto_mtls": true,
  "handshake_timeout": 22.0,
  "log_level": "DEBUG",
  "server_transports": ["unix", "tcp"]
}
```
Load it in Python:
```python
from pyvider.rpcplugin.config import load_config_from_file

load_config_from_file("config.json")
# The RPCPluginConfig singleton is now updated.
```

#### b. YAML File

Create a YAML file (e.g., `config.yaml`):
```yaml
magic_cookie: yaml-cookie-example
auto_mtls: false
handshake_timeout: 23.0
log_level: WARNING
server_transports:
  - unix
  - tcp
```
Load it in Python:
```python
from pyvider.rpcplugin.config import load_config_from_file

load_config_from_file("config.yaml")
# The RPCPluginConfig singleton is now updated.
```

#### c. .env File

Create a `.env` file (e.g., `.env` or `custom.env`):
```env
# Uses PYVIDER_ prefix which maps to PLUGIN_ counterparts
PYVIDER_MAGIC_COOKIE="dotenv-cookie-example"
PYVIDER_AUTO_MTLS="true"

# Can also use PLUGIN_ prefix directly
PLUGIN_HANDSHAKE_TIMEOUT="24.0"
PLUGIN_SERVER_TRANSPORTS="unix,tcp" # Comma-separated for lists
PLUGIN_LOG_LEVEL="INFO"
```
Load it in Python:
```python
from pyvider.rpcplugin.config import load_config_from_file

load_config_from_file(".env")
# Or load_config_from_file("custom.env")
# The RPCPluginConfig singleton is now updated.
```

### 3. Programmatic Configuration (`configure()` function)

You can configure the system directly in your Python code using the `configure()` function. This is useful for dynamic configurations or when file/environment variable-based setup is not suitable. Values set via `configure()` affect the in-memory state of the `RPCPluginConfig` singleton.

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

1.  **Schema Defaults**: The hardcoded default values defined in `CONFIG_SCHEMA`.
2.  **Environment Variables (Initial)**: Values already present in the environment when the `RPCPluginConfig` singleton is first initialized.
3.  **Configuration Files (`load_config_from_file`)**: When a file is loaded:
    a.  Values from the file are read.
    b.  These values are used to set/overwrite corresponding environment variables (using key mappings).
    c.  The internal `RPCPluginConfig` state is then entirely reloaded by `RPCPluginConfig.instance().reload()`. This reload process uses the current state of all environment variables (which now includes changes from the loaded file) and applies schema defaults for any settings not found in the environment.
    d.  If multiple files are loaded sequentially using `load_config_from_file()`, the environment variables set by the last-loaded file for a given key will take precedence during that file's subsequent config reload.
4.  **Programmatic `configure()` Calls**: Values passed to `configure()` directly update the in-memory `RPCPluginConfig` state, overriding any values loaded from previous steps (defaults, initial environment, or file-loaded environment variables). `configure()` does *not* change environment variables themselves.

It's crucial to understand that `load_config_from_file()` ultimately works by **modifying the environment variables**, and then triggering a reload of the `RPCPluginConfig` from this updated environment. This makes its behavior consistent with how environment variables are prioritized. The `configure()` function, in contrast, directly modifies the live configuration object without altering the environment.

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
