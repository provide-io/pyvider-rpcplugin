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
"""

from pyvider.rpcplugin.config.configure import configure
from pyvider.rpcplugin.config.runtime import RPCPluginConfig
from pyvider.rpcplugin.exception import ConfigError

# Create global configuration instance
rpcplugin_config = RPCPluginConfig.from_env()

__all__ = [
    "ConfigError",
    "RPCPluginConfig",
    "configure",
    "rpcplugin_config",
]
