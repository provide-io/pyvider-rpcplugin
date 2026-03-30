#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Skip Unix socket tests on Windows for the server test suite.

Uses pytest_collection_modifyitems to mark tests before setup runs,
preventing fixtures (like client_cert) from failing during setup.
"""

import sys

import pytest


def pytest_collection_modifyitems(items: list, config: pytest.Config) -> None:
    """Mark Unix socket tests as skip on Windows before any fixture setup."""
    if sys.platform != "win32":
        return
    skip_mark = pytest.mark.skip(reason="Unix domain sockets are not supported on Windows")
    unix_fixtures = {"managed_unix_socket_path", "temp_unix_socket_path"}
    for item in items:
        if hasattr(item, "fixturenames") and unix_fixtures.intersection(item.fixturenames):
            item.add_marker(skip_mark)
