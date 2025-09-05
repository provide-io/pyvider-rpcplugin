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

## Example: Production Configuration (`examples/ch12_production_config_discussion.py`)

The `ch12_production_config_discussion.py` script discusses these production considerations conceptually and shows how some of these might be mapped to `pyvider.rpcplugin` settings. The example code below demonstrates these concepts through several functions:

```python
#!/usr/bin/env python3
# examples/ch12_production_config_discussion.py
"""
Production Configuration - Production deployment patterns and configurations.
"""

import asyncio
import json
import os  # For environment_configuration example
from typing import Any  # For type hinting dict

from example_utils import configure_for_example  # type: ignore[import-not-found]

# Import pyvider.rpcplugin.configure for the new demonstration function
from provide.foundation import logger

# Apply base configuration for examples
configure_for_example()


async def production_server_config() -> None:
    """Example: Production server configuration."""
    logger.info("🏭 Production Server Configuration")

    config = {
        "server": {
            "max_workers": 50,
            "max_concurrent_rpcs": 1000,
            "keepalive_time": 30,
            "keepalive_timeout": 5,
            "max_connection_idle": 300,
            "max_connection_age": 3600,
        },
        "security": {
            "mtls_enabled": True,
            "ca_cert_path": "/etc/ssl/certs/ca.crt",
            "server_cert_path": "/etc/ssl/certs/server.crt",
            "server_key_path": "/etc/ssl/private/server.key",
            "cipher_suites": [
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256",
            ],
        },
        "monitoring": {
            "metrics_enabled": True,
            "health_check_interval": 30,
            "log_level": "INFO",
            "structured_logging": True,
        },
        # The "0.0.0.0" host is illustrative for a production config;
        # in a real deployment, this would be carefully considered for security.
        "transport": {"type": "tcp", "host": "0.0.0.0", "port": 50051, "backlog": 128},  # nosec B104
    }

    logger.info("📋 Production configuration:")
    logger.info(json.dumps(config, indent=2))

    logger.info("✅ Production server config example completed")


async def apply_conceptual_config_to_pyvider(conceptual_config: dict[str, Any]) -> None:
    """
    Demonstrates applying parts of a conceptual config to pyvider.rpcplugin.
    This is illustrative; in a real app, this logic would be more robust.
    This version aligns with the structure shown in the ch12 documentation.
    """
    logger.info(
        "🔧 Applying conceptual config to pyvider.rpcplugin settings (simplified mapping)..."
    )

    # Construct settings for pyvider_configure based on the conceptual_config
    # This matches the simpler structure from the ch12 markdown.
    pyvider_settings_to_apply: dict[str, Any] = {
        "auto_mtls": conceptual_config.get("security", {}).get("mtls_enabled", False),
        "server_cert": (
            f"file://{conceptual_config.get('security', {}).get('server_cert_path', '')}"
        ),
        "server_key": (
            f"file://{conceptual_config.get('security', {}).get('server_key_path', '')}"
        ),
        # For server-side, this would be client_root_certs for verifying clients
        "client_root_certs": (
            f"file://{conceptual_config.get('security', {}).get('ca_cert_path', '')}"
        ),
        # If configuring client-side, it would be server_root_certs:
        # "server_root_certs": (
        #     f"file://{conceptual_config.get('security', {}).get('ca_cert_path', '')}"
        # ),
        "magic_cookie": conceptual_config.get("security", {}).get(
            "expected_magic_cookie", ""
        ),
        # Kwargs for pyvider_configure (will be prefixed with PLUGIN_ internally by it)
        "LOG_LEVEL": conceptual_config.get("monitoring", {}).get("log_level", "INFO"),
        "HEALTH_SERVICE_ENABLED": conceptual_config.get("monitoring", {}).get(
            "enable_grpc_health_service", True
        ),
        "RATE_LIMIT_ENABLED": conceptual_config.get("monitoring", {}).get(
            "enable_rate_limiting", False
        ),
        "RATE_LIMIT_REQUESTS_PER_SECOND": conceptual_config.get("monitoring", {}).get(
            "requests_per_second", 100.0
        ),
        "RATE_LIMIT_BURST_CAPACITY": conceptual_config.get("monitoring", {}).get(
            "burst_capacity", 200.0
        ),
        "server_transports": [
            conceptual_config.get("transport", {}).get("type", "tcp")
        ],
        "handshake_timeout": conceptual_config.get("transport", {}).get(
            "handshake_timeout_seconds", 10.0
        ),
        "connection_timeout": conceptual_config.get("transport", {}).get(
            "connection_timeout_seconds", 30.0
        ),
        # Example for setting server endpoint if needed,
        # passed as a PLUGIN_ prefixed kwarg
        "SERVER_ENDPOINT": (
            f"{conceptual_config.get('transport', {}).get('host', '0.0.0.0')}:"
            f"{conceptual_config.get('transport', {}).get('port', 0)}"
        ),  # nosec B104 # nosec B108
    }

    # Filter out settings with empty paths for certs/keys if mtls is false
    if not pyvider_settings_to_apply.get("auto_mtls"):
        for key in [
            "server_cert",
            "server_key",
            "client_root_certs",
            "server_root_certs",
        ]:
            if (
                key in pyvider_settings_to_apply
                and pyvider_settings_to_apply[key] == "file://"
            ):
                del pyvider_settings_to_apply[key]

    logger.info(
        f"  Calling pyvider_configure with: "
        f"{json.dumps(pyvider_settings_to_apply, indent=2)}"
    )
    # In a real app, you'd call:
    from pyvider.rpcplugin import configure as pyvider_configure # Ensure import
    pyvider_configure(**pyvider_settings_to_apply)
    logger.info(
        "  Called pyvider.rpcplugin.configure() with mapped settings."
    )

    logger.info("✅ Illustrative application of conceptual config completed.")


async def environment_configuration() -> None:
    """Example: Environment-based configuration."""
    logger.info("🌍 Environment Configuration")

    # `os` module imported at the top of the file.
    # Environment-based settings
    env_config = {
        "PYVIDER_LOG_LEVEL": os.getenv("PYVIDER_LOG_LEVEL", "INFO"),
        "PYVIDER_METRICS_ENABLED": os.getenv("PYVIDER_METRICS_ENABLED", "true").lower()
        == "true",
        "PYVIDER_MAX_WORKERS": int(os.getenv("PYVIDER_MAX_WORKERS", "10")),
        "PYVIDER_TLS_CERT_PATH": os.getenv(
            "PYVIDER_TLS_CERT_PATH", "/etc/ssl/certs/server.crt"
        ),
        "PYVIDER_TLS_KEY_PATH": os.getenv(
            "PYVIDER_TLS_KEY_PATH", "/etc/ssl/private/server.key"
        ),
    }

    logger.info("🔧 Environment configuration:")
    for key, value in env_config.items():
        logger.info(f"  {key}: {value}")

    logger.info("✅ Environment configuration example completed")


async def deployment_checklist() -> None:
    """Production deployment checklist."""
    logger.info("📋 Production Deployment Checklist")

    checklist = [
        "🔒 TLS/mTLS certificates configured and valid",
        "🔑 Private keys secured with proper permissions",
        "🌐 Firewall rules configured for required ports",
        "📊 Monitoring and alerting configured",
        "📝 Log aggregation configured",
        "🔄 Health checks implemented",
        "📈 Resource limits configured",
        "🚀 Graceful shutdown handling",
        "🔧 Configuration management in place",
        "🧪 Load testing completed",
        "📚 Runbooks and documentation updated",
        "🔒 Security audit completed",
    ]

    for item in checklist:
        logger.info(f"  {item}")

    logger.info("✅ Deployment checklist review completed")


async def main() -> None:
    """Run production configuration examples."""
    logger.info("🚀 Production Configuration Examples")

    conceptual_config_data: dict[str, Any] = {
        "server": {
            "max_workers": 50,
            "max_concurrent_rpcs": 1000,
            "keepalive_time": 30,
            "keepalive_timeout": 5,
            "max_connection_idle": 300,
            "max_connection_age": 3600,
        },
        "security": {
            "mtls_enabled": True,
            "ca_cert_path": "/etc/ssl/certs/ca.crt",
            "server_cert_path": "/etc/ssl/certs/server.crt",
            "server_key_path": "/etc/ssl/private/server.key",
            "cipher_suites": [
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256",
            ],
        },
        "monitoring": {
            "metrics_enabled": True,
            "health_check_interval": 30,
            "log_level": "DEBUG",  # "DEBUG" for verbose output in this conceptual discussion
            "structured_logging": True,
        },
        # The "0.0.0.0" host is illustrative for a production config;
        # in a real deployment, this would be carefully considered for security.
        "transport": {"type": "tcp", "host": "0.0.0.0", "port": 50051, "backlog": 128},  # nosec B104
    }
    await production_server_config()
    await apply_conceptual_config_to_pyvider(conceptual_config_data)
    await environment_configuration()
    await deployment_checklist()

    logger.info("✅ All production examples completed")


if __name__ == "__main__":
    asyncio.run(main())

# 🐍🏭
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
