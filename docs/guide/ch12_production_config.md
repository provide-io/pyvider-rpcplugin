# Chapter 12: Production Configuration & Deployment

Deploying `pyvider.rpcplugin`-based applications to a production environment requires careful attention to configuration, security, resource management, and operational practices. This chapter outlines key considerations and references an example script that discusses these aspects.

## Key Configuration Areas for Production

When preparing your plugin and host application for production, focus on the following configuration areas:

*   **Security (mTLS)**:
    *   **Always enable mTLS**: Set `PLUGIN_AUTO_MTLS="True"`.
    *   **Certificates**: Use valid certificates from a trusted Certificate Authority (CA) or a well-managed internal PKI. Do not use self-signed certificates generated on-the-fly for production.
    *   **Key Management**: Securely store and manage private keys. Ensure file permissions are restrictive.
    *   **Certificate Paths**: Correctly configure `PLUGIN_SERVER_CERT`, `PLUGIN_SERVER_KEY`, `PLUGIN_CLIENT_ROOT_CERTS` (for server to verify client), and `PLUGIN_SERVER_ROOT_CERTS` (for client to verify server). Use `file:///` URIs for clarity and consistency.
*   **Magic Cookie**:
    *   Use a strong, unique, and randomly generated `PLUGIN_MAGIC_COOKIE_VALUE` for each distinct plugin service.
    *   Store this value securely (e.g., in a secrets manager) and provide it to both the host application (which sets it in the plugin's environment via `PLUGIN_MAGIC_COOKIE_KEY`) and the plugin server (which configures it as its expected `PLUGIN_MAGIC_COOKIE_VALUE`).
*   **Transport**:
    *   **Unix Domain Sockets (UDS)**: If the host and plugin are always on the same machine, UDS (`transport="unix"`) is generally preferred for performance and because it avoids network port conflicts. Ensure the socket path (`PLUGIN_SERVER_ENDPOINT` or `transport_path`) is in a secure location with appropriate permissions.
    *   **TCP Sockets**: If plugins run on different hosts or in containerized environments where UDS might be complex, use TCP (`transport="tcp"`).
        *   Configure `host` (e.g., `0.0.0.0` to listen on all interfaces within a container, or a specific IP) and `port` (`PLUGIN_SERVER_ENDPOINT="host:port"`).
        *   Ensure firewall rules allow traffic on the chosen port.
*   **Logging**:
    *   Set `PLUGIN_LOG_LEVEL` to `INFO` or `WARNING` for production to reduce log volume. `DEBUG` is usually too verbose.
    *   Integrate with a centralized logging system (e.g., ELK stack, Splunk, Datadog). `pyvider.telemetry` (which `pyvider.rpcplugin` uses) supports structured logging which is beneficial for this.
*   **Timeouts**:
    *   Review and adjust `PLUGIN_HANDSHAKE_TIMEOUT` and `PLUGIN_CONNECTION_TIMEOUT` based on your production environment's typical network latency and plugin initialization times. While defaults are often reasonable, specific environments might require tuning.
*   **Resource Management (External to `pyvider.rpcplugin` but critical)**:
    *   **Plugin Processes**: Set appropriate CPU and memory limits for your plugin processes, especially if running in containers or managed environments.
    *   **File Descriptors**: Ensure the system and process limits for open file descriptors are sufficient, particularly for servers expecting many concurrent connections (though gRPC multiplexes over a few connections).
*   **Health Checks**:
    *   Keep `PLUGIN_HEALTH_SERVICE_ENABLED="True"` (the default).
    *   Integrate the standard gRPC health checks with your orchestration platform (e.g., Kubernetes liveness/readiness probes, Nomad health checks) to monitor plugin health and enable automatic restarts or traffic shifting.
*   **Rate Limiting (Server-Side)**:
    *   If your plugin might be subject to high request volumes or potential abuse, enable and configure server-side rate limiting:
        *   `PLUGIN_RATE_LIMIT_ENABLED="True"`
        *   `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` (e.g., `100.0`)
        *   `PLUGIN_RATE_LIMIT_BURST_CAPACITY` (e.g., `200.0`)
*   **Client-Side Retries**:
    *   The built-in client retry mechanism for initial connection/handshake (`PLUGIN_CLIENT_RETRY_ENABLED="true"`) is generally good for production. Tune `PLUGIN_CLIENT_MAX_RETRIES`, backoff, and total timeout settings based on your plugin's startup characteristics and network reliability.

## Example: Production Configuration (`examples/08_production_config.py`)

The `08_production_config.py` script discusses these production considerations conceptually and shows how some of these might be mapped to `pyvider.rpcplugin` settings using the `configure` function or by setting environment variables.

```python
#!/usr/bin/env python3
# examples/08_production_config.py
import asyncio
import json
import os
from typing import Any
from example_utils import configure_for_example

# Import pyvider.rpcplugin.configure for the new demonstration function
from pyvider.rpcplugin import configure as pyvider_configure
from pyvider.telemetry import logger

# Apply base configuration for examples
configure_for_example() # Sets up paths, basic logging for the example script itself.

async def production_server_config_display() -> None:
    logger.info("🏭 Production Server Configuration (Conceptual Discussion)")

    # This is a conceptual configuration structure a user might have for their application
    conceptual_prod_config = {
        "server_settings": { # Conceptual grouping
            "max_workers": 50, # Example: for a thread pool if the app uses one
            "max_concurrent_rpcs": 1000, # Example: for gRPC server options
        },
        "security_settings": {
            "enable_mtls": True,
            "ca_certificate_file": "/etc/pyvider/certs/ca.pem",
            "server_certificate_file": "/etc/pyvider/certs/server.pem",
            "server_private_key_file": "/etc/pyvider/keys/server.key",
            "client_ca_for_server_verification": "/etc/pyvider/certs/client_ca.pem",
            "expected_magic_cookie": "a-very-strong-production-secret-cookie-value"
        },
        "logging_monitoring": {
            "log_level": "INFO", # Standard production log level
            "enable_grpc_health_service": True,
            "enable_rate_limiting": True,
            "requests_per_second": 50.0,
            "burst_capacity": 100.0
        },
        "transport_config": {
            "type": "tcp", # e.g., TCP for network accessibility
            "host": "0.0.0.0", # Listen on all interfaces (common in containers)
            "port": 9090,
            "handshake_timeout_seconds": 20.0,
            "connection_timeout_seconds": 60.0
        }
    }
    logger.info(f"📋 Conceptual Production Config:\n{json.dumps(conceptual_prod_config, indent=2)}")

    # Now, let's show how these conceptual settings might map to pyvider.rpcplugin's
    # configuration using the `pyvider_configure` function or by setting env vars.

    pyvider_settings_to_apply = {
        # From security_settings
        "auto_mtls": conceptual_prod_config["security_settings"]["enable_mtls"],
        "server_cert": f"file://{conceptual_prod_config['security_settings']['server_certificate_file']}",
        "server_key": f"file://{conceptual_prod_config['security_settings']['server_private_key_file']}",
        "client_root_certs": f"file://{conceptual_prod_config['security_settings']['client_ca_for_server_verification']}",
        # For client-side to verify server, it would use a similar root cert:
        # "server_root_certs": f"file://{conceptual_prod_config['security_settings']['ca_certificate_file']}",
        "magic_cookie": conceptual_prod_config["security_settings"]["expected_magic_cookie"],

        # From logging_monitoring
        # Note: pyvider_configure takes kwargs for PLUGIN_ prefixed vars not in its direct signature
        "PLUGIN_LOG_LEVEL": conceptual_prod_config["logging_monitoring"]["log_level"],
        "PLUGIN_HEALTH_SERVICE_ENABLED": conceptual_prod_config["logging_monitoring"]["enable_grpc_health_service"],
        "PLUGIN_RATE_LIMIT_ENABLED": conceptual_prod_config["logging_monitoring"]["enable_rate_limiting"],
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": conceptual_prod_config["logging_monitoring"]["requests_per_second"],
        "PLUGIN_RATE_LIMIT_BURST_CAPACITY": conceptual_prod_config["logging_monitoring"]["burst_capacity"],

        # From transport_config
        "transports": [conceptual_prod_config["transport_config"]["type"]], # Assuming server supports one type
        "handshake_timeout": conceptual_prod_config["transport_config"]["handshake_timeout_seconds"],
        "connection_timeout": conceptual_prod_config["transport_config"]["connection_timeout_seconds"],
        # For server endpoint, it's usually dynamic or set via PLUGIN_SERVER_ENDPOINT
        # For this example, we are showing how `pyvider_configure` might be used.
        # If setting a static server endpoint:
        # "PLUGIN_SERVER_ENDPOINT": f"{conceptual_prod_config['transport_config']['host']}:{conceptual_prod_config['transport_config']['port']}"
    }

    logger.info(f"🔧 Corresponding pyvider.rpcplugin settings via `configure()`:\n{json.dumps(pyvider_settings_to_apply, indent=2)}")
    # In a real app, you'd call:
    # pyvider_configure(**pyvider_settings_to_apply)
    # This would update the global rpcplugin_config singleton.
    # RPCPluginServer and RPCPluginClient instances created afterwards would use these.
    logger.info("✅ Production server config mapping demonstration completed.")


async def environment_configuration_demo():
    logger.info("🌍 Environment Configuration Demonstration")
    logger.info("   In production, you would typically set these via your deployment system:")
    logger.info("   export PLUGIN_LOG_LEVEL=INFO")
    logger.info("   export PLUGIN_AUTO_MTLS=True")
    logger.info("   export PLUGIN_SERVER_CERT=\"file:///etc/ssl/certs/server.crt\"")
    logger.info("   export PLUGIN_SERVER_KEY=\"file:///etc/ssl/private/server.key\"")
    logger.info("   export PLUGIN_CLIENT_ROOT_CERTS=\"file:///etc/ssl/certs/ca.crt\"")
    logger.info("   export PLUGIN_MAGIC_COOKIE_KEY=\"MYAPP_PLUGIN_AUTH_TOKEN\"")
    logger.info("   export PLUGIN_MAGIC_COOKIE_VALUE=\"super-secret-prod-cookie\"")
    logger.info("   # ... and so on for other relevant PLUGIN_ variables.")
    logger.info("✅ Environment configuration demonstration completed.")

async def deployment_checklist_display(): # Renamed
    logger.info("📋 Production Deployment Checklist (Conceptual)")
    checklist = [
        "Secure mTLS: CA, Server, Client certificates & keys properly configured and secured.",
        "Strong Magic Cookie: Unique and securely managed `PLUGIN_MAGIC_COOKIE_VALUE`.",
        "Appropriate Transport: Unix Sockets for local, TCP for network; firewall rules for TCP.",
        "Logging: `PLUGIN_LOG_LEVEL` set to INFO/WARNING; integrated with central logging.",
        "Timeouts: `PLUGIN_HANDSHAKE_TIMEOUT`, `PLUGIN_CONNECTION_TIMEOUT` tuned.",
        "Resource Limits: CPU/memory for plugin processes set in orchestrator.",
        "Health Checks: `PLUGIN_HEALTH_SERVICE_ENABLED=True`; probes configured.",
        "Rate Limiting: Configured if plugin is exposed to high/untrusted traffic.",
        "Configuration Management: Securely manage all `PLUGIN_` variables.",
        "Plugin Packaging: Plugin packaged as a reliable executable.",
        "Orchestration: Plugin lifecycle (start, stop, restart) managed.",
    ]
    for item in checklist: logger.info(f"  [ ] {item}")
    logger.info("✅ Deployment checklist review completed.")

async def main():
    await production_server_config_display()
    await environment_configuration_demo()
    await deployment_checklist_display()
    logger.info("✅ All production configuration examples completed.")

if __name__ == "__main__":
    asyncio.run(main())
```

**Deployment Strategies:**

*   **Standalone Executable**: Package your plugin server script (e.g., using PyInstaller, Nuitka, or just as a `#!/usr/bin/env python3` script) and have your host application launch it directly. `RPCPluginClient` is designed for this.
*   **Containerization (e.g., Docker)**:
    *   Package your plugin server into a Docker container.
    *   The host application can launch this container, or an orchestrator can manage it.
    *   If client and server are in different containers on the same Docker network or Kubernetes pod, TCP might be simpler than managing UDS mounts. If in the same pod, UDS via a shared volume is possible and performant.
*   **Orchestration (e.g., Kubernetes, Nomad)**:
    *   Deploy plugins as separate services/jobs.
    *   The host application would discover and connect to plugin instances, likely via TCP using service discovery. In this model, the host might not launch the plugin process directly; instead, it would connect to an already running instance (see Chapter 8: Direct Client Connections).

Remember to always prioritize security and robust configuration management in production environments.
