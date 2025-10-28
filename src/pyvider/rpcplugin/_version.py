#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Version handling for pyvider-rpcplugin.

This module uses the shared versioning utility from provide-foundation.
"""

from provide.foundation.common import get_version

__version__ = get_version("pyvider-rpcplugin", caller_file=__file__)

__all__ = ["__version__"]

# 📞🔌🔚
