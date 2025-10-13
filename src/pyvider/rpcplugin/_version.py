from __future__ import annotations

from provide.foundation.utils.versioning import (
    _find_project_root,
    get_version as _get_version,
)

"""Version handling for pyvider-rpcplugin.

This module uses the shared versioning utility from provide-foundation.
"""


def get_version() -> str:
    """Get the version for pyvider-rpcplugin.

    Returns:
        The current version string
    """
    return _get_version("pyvider-rpcplugin", caller_file=__file__)


__version__ = get_version()

__all__ = ["__version__", "get_version", "_find_project_root"]
