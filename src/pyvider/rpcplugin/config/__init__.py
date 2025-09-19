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

from typing import Any

from attrs import define
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig

from pyvider.rpcplugin.config.client import ClientConfig
from pyvider.rpcplugin.config.core import CoreConfig
from pyvider.rpcplugin.config.features import FeaturesConfig
from pyvider.rpcplugin.config.grpc import GRPCConfig
from pyvider.rpcplugin.config.security import SecurityConfig
from pyvider.rpcplugin.config.server import ServerConfig
from pyvider.rpcplugin.config.transport import TransportConfig
from pyvider.rpcplugin.exception import ConfigError


@define(slots=True, repr=False)
class RPCPluginConfig(
    RuntimeConfig,
    CoreConfig,
    TransportConfig,
    SecurityConfig,
    GRPCConfig,
    ClientConfig,
    ServerConfig,
    FeaturesConfig,
):
    """
    Unified configuration for the RPC plugin system.

    This class provides all configuration settings organized by functional area
    through composition via multiple inheritance:
    - Core settings (protocol versions, magic cookies)
    - Transport settings (timeouts, buffer sizes, supported transports)
    - Security settings (mTLS, certificates)
    - gRPC settings (keepalive, grace periods)
    - Client settings (retry logic)
    - Server settings (host, port, paths)
    - Feature settings (rate limiting, health checks, UI)
    """

    # =====================================================
    # Helper Methods
    # =====================================================

    def magic_cookie_key(self) -> str:
        """Get the magic cookie key."""
        return self.plugin_magic_cookie_key

    def magic_cookie_value(self) -> str:
        """Get the magic cookie value."""
        return self.plugin_magic_cookie_value

    def server_transports(self) -> list[str]:
        """Get server transport list."""
        return self.plugin_server_transports

    def client_transports(self) -> list[str]:
        """Get client transport list."""
        return self.plugin_client_transports

    def handshake_timeout(self) -> float:
        """Get handshake timeout."""
        return self.plugin_handshake_timeout

    def connection_timeout(self) -> float:
        """Get connection timeout."""
        return self.plugin_connection_timeout

    def channel_ready_timeout(self) -> float:
        """Get gRPC channel ready timeout."""
        return self.plugin_channel_ready_timeout

    def server_ready_timeout(self) -> float:
        """Get server ready timeout."""
        return self.plugin_server_ready_timeout

    def buffer_size(self) -> int:
        """Get default buffer size for data operations in bytes."""
        return self.plugin_buffer_size

    def chunk_size(self) -> int:
        """Get default chunk size for streaming in bytes."""
        return self.plugin_chunk_size

    def grpc_keepalive_time_ms(self) -> int:
        """Get gRPC keepalive time in milliseconds."""
        return self.plugin_grpc_keepalive_time_ms

    def grpc_keepalive_timeout_ms(self) -> int:
        """Get gRPC keepalive timeout in milliseconds."""
        return self.plugin_grpc_keepalive_timeout_ms

    def grpc_grace_period(self) -> float:
        """Get gRPC channel close grace period in seconds."""
        return self.plugin_grpc_grace_period

    def auto_mtls_enabled(self) -> bool:
        """Get auto mTLS enabled flag."""
        return self.plugin_auto_mtls

    def cert_validity_days(self) -> int:
        """Get certificate validity period in days."""
        return self.plugin_cert_validity_days

    def rate_limit_enabled(self) -> bool:
        """Get rate limit enabled flag."""
        return self.plugin_rate_limit_enabled

    def rate_limit_requests_per_second(self) -> float:
        """Get rate limit requests per second."""
        return self.plugin_rate_limit_requests_per_second

    def rate_limit_burst_capacity(self) -> float:
        """Get rate limit burst capacity."""
        return self.plugin_rate_limit_burst_capacity

    def health_service_enabled(self) -> bool:
        """Get health service enabled flag."""
        return self.plugin_health_service_enabled

    # =====================================================
    # Backward Compatibility Properties
    # =====================================================

    @property
    def protocol_versions(self) -> list[int]:
        """Alias for plugin_protocol_versions for backward compatibility."""
        return self.plugin_protocol_versions


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

    except Exception as e:
        raise ConfigError(f"Failed to configure RPC plugin: {e}") from e


# Export commonly used items for backward compatibility
__all__ = [
    "RPCPluginConfig",
    "configure",
    "rpcplugin_config",
]
