#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Skip all Unix socket transport tests on Windows.

Unix domain sockets are not supported on Windows; TCP is the default
transport there. All tests in this directory are Unix-only.
"""

import sys
import pytest


@pytest.fixture(autouse=True)
def skip_on_windows() -> None:
    """Skip every test in this directory on Windows — Unix sockets not supported."""
    if sys.platform == "win32":
        pytest.skip("Unix domain sockets are not supported on Windows")
