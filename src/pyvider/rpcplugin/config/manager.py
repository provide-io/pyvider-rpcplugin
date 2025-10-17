#
# pyvider/rpcplugin/config/manager.py
#
"""
RPC Plugin Configuration Manager.

Provides centralized configuration management for multiple RPC plugin instances
using Foundation's ConfigManager. This enables:
- Managing multiple plugin configurations (multi-tenant scenarios)
- Runtime configuration updates with validation
- Export/import for debugging and persistence
- Backward compatibility with direct config object usage

Examples:
    Basic usage:
        >>> from pyvider.rpcplugin.config import RPCPluginConfig
        >>> from pyvider.rpcplugin.config.manager import register_plugin_config, get_plugin_config
        >>>
        >>> # Register a configuration
        >>> config = RPCPluginConfig(plugin_server_port=8080)
        >>> register_plugin_config("server1", config)
        >>>
        >>> # Retrieve it later
        >>> config = get_plugin_config("server1")
        >>> print(config.plugin_server_port)  # 8080

    Multiple configurations:
        >>> client_config = RPCPluginConfig(plugin_client_max_retries=5)
        >>> server_config = RPCPluginConfig(plugin_server_port=9000)
        >>>
        >>> register_plugin_config("client", client_config)
        >>> register_plugin_config("server", server_config)
        >>>
        >>> # List all registered configs
        >>> configs = list_plugin_configs()
        >>> print(configs)  # ["client", "server"]

Note:
    This module is completely optional and backward compatible.
    Direct usage of RPCPluginConfig without the manager continues to work unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from provide.foundation.config import ConfigManager

if TYPE_CHECKING:
    from pyvider.rpcplugin.config.runtime import RPCPluginConfig

# Global configuration manager for RPC plugins
_plugin_config_manager: ConfigManager | None = None


def get_plugin_config_manager() -> ConfigManager:
    """Get or create the global RPC plugin configuration manager.

    Returns:
        ConfigManager instance for RPC plugin configurations

    Example:
        >>> manager = get_plugin_config_manager()
        >>> manager.register("my-plugin", config=my_config)
    """
    global _plugin_config_manager
    if _plugin_config_manager is None:
        _plugin_config_manager = ConfigManager()
    return _plugin_config_manager


def register_plugin_config(
    name: str,
    config: RPCPluginConfig,
) -> None:
    """Register an RPC plugin configuration.

    Args:
        name: Unique name for this configuration
        config: RPCPluginConfig instance to register

    Raises:
        ValueError: If a configuration with this name already exists

    Example:
        >>> from pyvider.rpcplugin.config import RPCPluginConfig
        >>> config = RPCPluginConfig(plugin_server_port=8080)
        >>> register_plugin_config("server1", config)
    """
    manager = get_plugin_config_manager()
    manager.register(name, config=config)


def get_plugin_config(name: str) -> RPCPluginConfig | None:
    """Get a registered RPC plugin configuration by name.

    Args:
        name: Name of the configuration

    Returns:
        RPCPluginConfig instance or None if not found

    Example:
        >>> config = get_plugin_config("server1")
        >>> if config:
        ...     print(config.plugin_server_port)
    """
    manager = get_plugin_config_manager()
    return manager.get(name)  # type: ignore[return-value]


def unregister_plugin_config(name: str) -> None:
    """Unregister an RPC plugin configuration.

    Args:
        name: Name of the configuration to remove

    Example:
        >>> unregister_plugin_config("server1")
    """
    manager = get_plugin_config_manager()
    manager.unregister(name)


def list_plugin_configs() -> list[str]:
    """List all registered RPC plugin configuration names.

    Returns:
        List of configuration names

    Example:
        >>> configs = list_plugin_configs()
        >>> for name in configs:
        ...     config = get_plugin_config(name)
        ...     print(f"{name}: port={config.plugin_server_port}")
    """
    manager = get_plugin_config_manager()
    return manager.list_configs()


def update_plugin_config(name: str, updates: dict[str, object]) -> None:
    """Update a registered RPC plugin configuration.

    Args:
        name: Name of the configuration
        updates: Dictionary of field updates

    Raises:
        ValueError: If configuration not found

    Example:
        >>> update_plugin_config("server1", {"plugin_server_port": 9000})
        >>> config = get_plugin_config("server1")
        >>> assert config.plugin_server_port == 9000
    """
    manager = get_plugin_config_manager()
    manager.update(name, updates)


def export_plugin_config(name: str, include_sensitive: bool = False) -> dict[str, object]:
    """Export a registered configuration as a dictionary.

    Args:
        name: Name of the configuration
        include_sensitive: Whether to include sensitive fields (e.g., passwords)

    Returns:
        Configuration dictionary

    Raises:
        ValueError: If configuration not found

    Example:
        >>> config_dict = export_plugin_config("server1")
        >>> import json
        >>> json.dump(config_dict, open("config.json", "w"))
    """
    manager = get_plugin_config_manager()
    return manager.export(name, include_sensitive)


def export_all_plugin_configs(include_sensitive: bool = False) -> dict[str, dict[str, object]]:
    """Export all registered configurations.

    Args:
        include_sensitive: Whether to include sensitive fields

    Returns:
        Dictionary mapping config names to their dictionaries

    Example:
        >>> all_configs = export_all_plugin_configs()
        >>> for name, config_dict in all_configs.items():
        ...     print(f"{name}: {config_dict['plugin_server_port']}")
    """
    manager = get_plugin_config_manager()
    return manager.export_all(include_sensitive)


def clear_plugin_configs() -> None:
    """Clear all registered RPC plugin configurations.

    Warning:
        This removes all registered configurations. Use with caution.

    Example:
        >>> clear_plugin_configs()
        >>> assert list_plugin_configs() == []
    """
    manager = get_plugin_config_manager()
    manager.clear()


__all__ = [
    "clear_plugin_configs",
    "export_all_plugin_configs",
    "export_plugin_config",
    "get_plugin_config",
    "get_plugin_config_manager",
    "list_plugin_configs",
    "register_plugin_config",
    "unregister_plugin_config",
    "update_plugin_config",
]
