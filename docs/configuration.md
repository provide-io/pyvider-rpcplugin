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

Configuration can also be loaded from files using the `load_config_from_file()` function. This function reads values from the specified file, sets them as environment variables (mapping keys as needed), and then reloads the internal configuration state from the environment. This means the behavior is similar to setting environment variables directly, but managed via a file.

**Note on Key Mappings:** For JSON and YAML files, common shorter keys (e.g., `magic_cookie`) are mapped to their canonical `PLUGIN_` prefixed environment variable names (e.g., `PLUGIN_MAGIC_COOKIE_VALUE`). For `.env` files, `PYVIDER_` prefixed keys are similarly mapped (e.g., `PYVIDER_MAGIC_COOKIE` maps to `PLUGIN_MAGIC_COOKIE_VALUE`). You can also use the canonical `PLUGIN_` prefixed keys directly in any file type.

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
    magic_cookie="programmatic-cookie-example", # Short names used as arguments
    auto_mtls=True,
    handshake_timeout=25.0,
    log_level="DEBUG",
    transports=["unix"] # This sets both server and client transports
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
    c.  The internal `RPCPluginConfig` state is then entirely reloaded based on the current state of all environment variables (reflecting changes from the loaded file) and schema defaults for anything not in the environment. If multiple files are loaded, the environment variables set by the last-loaded file for a given key will take precedence during the subsequent config reload.
4.  **Programmatic `configure()` Calls**: Values passed to `configure()` directly update the in-memory `RPCPluginConfig` state, overriding any values loaded from previous steps. `configure()` does *not* change environment variables.

It's important to note that `load_config_from_file` modifies the environment variables, which can then affect subsequent re-initializations or reloads of the `RPCPluginConfig`. The `configure()` function, however, only modifies the current in-memory state of the configuration singleton.

## Detailed Environment Variable List

Below is a detailed list of all supported environment variables, their purposes, types, and default values.

### `PLUGIN_AUTO_MTLS`
- **Description**: Flag to enable automatic mTLS (true/false).
- **Type**: `bool`
- **Default**: `"true"`
- **`.env` Alias**: `PYVIDER_AUTO_MTLS`

### `PLUGIN_CLIENT_CERT`
- **Description**: Client certificate in PEM format or 'file://<path>' to read from a file.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_CERT`

### `PLUGIN_CLIENT_ENDPOINT`
- **Description**: Client endpoint for connection.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_ENDPOINT`

### `PLUGIN_CLIENT_KEY`
- **Description**: Client private key in PEM format or 'file://<path>' to read from a file.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_CLIENT_KEY`

### `PLUGIN_CLIENT_ROOT_CERTS`
- **Description**: Root certificates for client in PEM format or 'file://<path>'.
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

### `PLUGIN_MAGIC_COOKIE`
- **Description**: The actual cookie provided by the client.
- **Type**: `str`
- **Default**: `"rpcplugin-default-cookie"`

### `PLUGIN_MAGIC_COOKIE_KEY`
- **Description**: Environment variable name for the magic cookie value.
- **Type**: `str`
- **Default**: `"PLUGIN_MAGIC_COOKIE"`

### `PLUGIN_MAGIC_COOKIE_VALUE`
- **Description**: The expected magic cookie value for validation.
- **Type**: `str`
- **Default**: `"rpcplugin-default-cookie"`
- **`.env` Alias**: `PYVIDER_MAGIC_COOKIE`

### `PLUGIN_PROTOCOL_VERSIONS`
- **Description**: List of supported protocol versions.
- **Type**: `list_int`
- **Default**: `[1]`
- **`.env` Alias**: `PYVIDER_PROTOCOL_VERSIONS`

### `PLUGIN_SERVER_CERT`
- **Description**: Server certificate in PEM format or 'file://<path>' to read from a file.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_CERT`

### `PLUGIN_SERVER_ENDPOINT`
- **Description**: Server endpoint for connection (host:port for TCP, path for Unix).
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_ENDPOINT`

### `PLUGIN_SERVER_KEY`
- **Description**: Server private key in PEM format or 'file://<path>' to read from a file.
- **Type**: `str`
- **Default**: `None`
- **`.env` Alias**: `PYVIDER_SERVER_KEY`

### `PLUGIN_SERVER_ROOT_CERTS`
- **Description**: Root certificates for server in PEM format or 'file://<path>'.
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
