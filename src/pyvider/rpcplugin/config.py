"""Backward compatibility shim for the original config.py module.

This module re-exports everything from the new config package structure
to maintain backward compatibility with existing code.
"""

# Re-export everything from the new config package
from .config import *  # noqa: F403

# Ensure the global config instance is available
from .config import configure, rpcplugin_config  # noqa: F401
