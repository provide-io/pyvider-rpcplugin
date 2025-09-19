"""Configuration management for Pyvider RPC Plugin.

This module provides a Foundation-based configuration system for the Pyvider RPC Plugin framework.
Uses provide.foundation for modern async configuration loading, multi-source support, and validation.

Usage:
    # Get a configuration value
    from pyvider.rpcplugin.config import rpcplugin_config
    cookie_value = rpcplugin_config.plugin_magic_cookie_value

    # Use helper methods
    transports = rpcplugin_config.server_transports()
    timeout = rpcplugin_config.handshake_timeout()

    # Use the simplified configuration helper
    from pyvider.rpcplugin.config import configure
    configure(
        magic_cookie="my-plugin-cookie",
        protocol_version=1,
        transports=["unix", "tcp"],
        auto_mtls=True,
    )
"""

from typing import Any, Literal

from attrs import define
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig
from provide.foundation.errors.config import ValidationError

from ..exception import ConfigError
from .client import ClientConfigMixin
from .core import CoreConfigMixin
from .features import FeaturesConfigMixin
from .grpc import GRPCConfigMixin
from .security import SecurityConfigMixin
from .server import ServerConfigMixin
from .transport import TransportConfigMixin


@define
class RPCPluginConfig(
    RuntimeConfig,
    CoreConfigMixin,
    GRPCConfigMixin,
    TransportConfigMixin,
    SecurityConfigMixin,
    ClientConfigMixin,
    ServerConfigMixin,
    FeaturesConfigMixin,
):
    """
    Configuration class for the RPC plugin system.

    This class combines all configuration mixins and provides a single
    interface for accessing all plugin configuration settings.
    """

    def validate_transport_consistency(self) -> None:
        """Validate that transport configuration is consistent."""
        if not self.plugin_server_transports:
            raise ConfigError("At least one server transport must be specified")

        if not self.plugin_client_transports:
            raise ConfigError("At least one client transport must be specified")

        valid_transports = ["unix", "tcp"]
        for transport in self.plugin_server_transports:
            if transport not in valid_transports:
                raise ConfigError(f"Invalid server transport: {transport}. Must be one of {valid_transports}")

        for transport in self.plugin_client_transports:
            if transport not in valid_transports:
                raise ConfigError(f"Invalid client transport: {transport}. Must be one of {valid_transports}")

    def validate_security_consistency(self) -> None:
        """Validate that security configuration is consistent."""
        # If client cert is specified, client key must also be specified
        if self.plugin_client_cert and not self.plugin_client_key:
            raise ConfigError("Client certificate specified but client key is missing")

        if self.plugin_client_key and not self.plugin_client_cert:
            raise ConfigError("Client key specified but client certificate is missing")

        # If server cert is specified, server key must also be specified
        if self.plugin_server_cert and not self.plugin_server_key:
            raise ConfigError("Server certificate specified but server key is missing")

        if self.plugin_server_key and not self.plugin_server_cert:
            raise ConfigError("Server key specified but server certificate is missing")

    def __attrs_post_init__(self) -> None:
        """Post-initialization validation."""
        super().__attrs_post_init__()
        try:
            self.validate_transport_consistency()
            self.validate_security_consistency()
        except ValidationError as e:
            raise ConfigError(f"Configuration validation failed: {e}") from e


# Create the global configuration instance
rpcplugin_config = RPCPluginConfig()


def configure(
    magic_cookie: str | None = None,
    protocol_version: int | None = None,
    transports: list[str] | None = None,
    auto_mtls: bool | None = None,
    **kwargs: Any,
) -> None:
    """
    Configure the RPC plugin system with common settings.

    This is a convenience function for setting up the most commonly
    used configuration options.

    Args:
        magic_cookie: Magic cookie value for handshake authentication
        protocol_version: Preferred protocol version
        transports: List of supported transports
        auto_mtls: Enable automatic mTLS certificate generation
        **kwargs: Additional configuration parameters
    """
    try:
        if magic_cookie is not None:
            rpcplugin_config.plugin_magic_cookie_value = magic_cookie

        if protocol_version is not None:
            rpcplugin_config.plugin_core_version = protocol_version
            rpcplugin_config.plugin_protocol_versions = [protocol_version]

        if transports is not None:
            rpcplugin_config.plugin_server_transports = transports
            rpcplugin_config.plugin_client_transports = transports

        if auto_mtls is not None:
            rpcplugin_config.plugin_auto_mtls = auto_mtls

        # Apply any additional keyword arguments
        for key, value in kwargs.items():
            if hasattr(rpcplugin_config, key):
                setattr(rpcplugin_config, key, value)
            else:
                logger.warning(f"Unknown configuration parameter: {key}")

        # Validate the configuration after changes
        rpcplugin_config.validate_transport_consistency()
        rpcplugin_config.validate_security_consistency()

    except Exception as e:
        raise ConfigError(f"Failed to configure RPC plugin: {e}") from e


# Export commonly used items for backward compatibility
__all__ = [
    "RPCPluginConfig",
    "rpcplugin_config",
    "configure",
    "CoreConfigMixin",
    "GRPCConfigMixin",
    "TransportConfigMixin",
    "SecurityConfigMixin",
    "ClientConfigMixin",
    "ServerConfigMixin",
    "FeaturesConfigMixin",
]