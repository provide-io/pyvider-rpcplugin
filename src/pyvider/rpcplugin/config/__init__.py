#
# pyvider/rpcplugin/config/__init__.py
#
"""
Configuration management for the RPC Plugin framework.

This module provides centralized configuration management using the Foundation
framework's configuration system. All defaults are defined in defaults.py
following the project's "no inline defaults" policy.

The configuration is organized into separate modules:
- runtime.py: Main RPCPluginConfig class with env_field support
- configure.py: Configuration helper functions
- defaults.py: All default values (no inline defaults)
- manager.py: ConfigManager integration for multi-instance management (optional)
"""

from pyvider.rpcplugin.config.configure import configure
from pyvider.rpcplugin.config.manager import (
    clear_plugin_configs,
    export_all_plugin_configs,
    export_plugin_config,
    get_plugin_config,
    get_plugin_config_manager,
    list_plugin_configs,
    register_plugin_config,
    unregister_plugin_config,
    update_plugin_config,
)
from pyvider.rpcplugin.config.runtime import RPCPluginConfig
from pyvider.rpcplugin.exception import ConfigError

# Create global configuration instance
rpcplugin_config = RPCPluginConfig.from_env()

__all__ = [
    # Core config
    "ConfigError",
    "RPCPluginConfig",
    "clear_plugin_configs",
    "configure",
    "export_all_plugin_configs",
    "export_plugin_config",
    "get_plugin_config",
    # Config manager (optional, for multi-instance scenarios)
    "get_plugin_config_manager",
    "list_plugin_configs",
    "register_plugin_config",
    "rpcplugin_config",
    "unregister_plugin_config",
    "update_plugin_config",
]
