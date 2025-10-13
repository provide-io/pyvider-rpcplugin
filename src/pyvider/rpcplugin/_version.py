from __future__ import annotations

from provide.foundation.utils.versioning import get_version

"""Version handling for pyvider-rpcplugin.

This module uses the shared versioning utility from provide-foundation.
"""

__version__ = get_version("pyvider-rpcplugin", caller_file=__file__)

__all__ = ["__version__"]
