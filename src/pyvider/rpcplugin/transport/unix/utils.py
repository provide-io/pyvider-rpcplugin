#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""
Unix Domain Socket utilities and helper functions.

This module provides utility functions for Unix domain socket path
normalization and other common operations.
"""

from provide.foundation.logger import get_logger

logger = get_logger(__name__)


def normalize_unix_path(path: str) -> str:
    """
    Standardized Unix socket path normalization, handling:
    - unix: prefix
    - unix:/ prefix
    - unix:// prefix
    - Multiple leading slashes

    Returns a clean path suitable for socket operations.
    """
    logger.debug(f"📞🔍🚀 * Normalizing Unix path: {path}")

    # Handle unix: prefix formats
    if path.startswith("unix:"):
        path = path[5:]  # Remove 'unix:'

    # Handle multiple leading slashes
    if path.startswith("//"):
        # Split by / and rebuild with single leading slash
        parts = [p for p in path.split("/") if p]
        path = "/" + "/".join(parts)
    elif path.startswith("/"):
        # Keep absolute paths as-is
        pass
    # Relative paths remain unchanged

    logger.debug(f"📞🔍✅ * Normalized Unix path: {path}")
    return path

# 📞🔌🔚
