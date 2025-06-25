#!/usr/bin/env python3
"""
Production Configuration - Production deployment patterns and configurations.
"""

import asyncio
import json
import os  # For environment_configuration example
from typing import Any  # For type hinting dict

from example_utils import configure_for_example

# Import pyvider.rpcplugin.configure for the new demonstration function
from pyvider.rpcplugin import configure as pyvider_configure
from pyvider.telemetry import logger

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
    """
    logger.info("🔧 Applying conceptual config to pyvider.rpcplugin settings...")

    applied_settings: dict[str, Any] = {}

    if (
        "monitoring" in conceptual_config
        and "log_level" in conceptual_config["monitoring"]
    ):
        log_level = conceptual_config["monitoring"]["log_level"]
        applied_settings["PLUGIN_LOG_LEVEL"] = log_level
        logger.info(
            f"  Conceptual log_level '{log_level}' would map to PLUGIN_LOG_LEVEL."
        )

    if (
        "security" in conceptual_config
        and "mtls_enabled" in conceptual_config["security"]
    ):
        mtls = conceptual_config["security"]["mtls_enabled"]
        applied_settings["PLUGIN_AUTO_MTLS"] = mtls
        logger.info(
            f"  Conceptual mtls_enabled '{mtls}' would map to PLUGIN_AUTO_MTLS."
        )
        if mtls:
            # In a real scenario, we'd also map server_cert_path, etc.
            applied_settings["PLUGIN_SERVER_CERT"] = conceptual_config["security"].get(
                "server_cert_path"
            )
            applied_settings["PLUGIN_SERVER_KEY"] = conceptual_config["security"].get(
                "server_key_path"
            )
            # Assuming CA for client verification
            applied_settings["PLUGIN_CLIENT_ROOT_CERTS"] = conceptual_config[
                "security"
            ].get("ca_cert_path")
            logger.info("  Will also map server certs and client root CAs for mTLS.")

    if applied_settings:
        logger.info(f"  Calling pyvider_configure with: {applied_settings}")
        # Note: `pyvider_configure` takes specific args like `auto_mtls`.
        # It also takes **kwargs for other `PLUGIN_` prefixed keys.
        # We map conceptual keys to these.

        final_configure_args: dict[str, Any] = {}
        if "PLUGIN_AUTO_MTLS" in applied_settings:
            final_configure_args["auto_mtls"] = applied_settings.pop("PLUGIN_AUTO_MTLS")
        if "PLUGIN_SERVER_CERT" in applied_settings:
            final_configure_args["server_cert_path"] = applied_settings.pop(
                "PLUGIN_SERVER_CERT"
            )
        if "PLUGIN_SERVER_KEY" in applied_settings:
            final_configure_args["server_key_path"] = applied_settings.pop(
                "PLUGIN_SERVER_KEY"
            )
        if "PLUGIN_CLIENT_ROOT_CERTS" in applied_settings:
            final_configure_args["client_root_certs_path"] = applied_settings.pop(
                "PLUGIN_CLIENT_ROOT_CERTS"
            )

        # Remaining settings in applied_settings are kwargs (should be PLUGIN_ prefixed)
        final_configure_args.update(applied_settings)

        pyvider_configure(**final_configure_args)
        logger.info("  Illustrative pyvider.rpcplugin.configure() called.")
    else:
        logger.info("  No conceptual settings mapped for pyvider_configure.")

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
            "log_level": "DEBUG",  # Changed for demo
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
