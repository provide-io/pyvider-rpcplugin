#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Skip Unix socket tests on Windows for the transport test suite.

Uses pytest_collection_modifyitems to mark tests before setup runs,
preventing fixtures from failing during setup on Windows.
"""

import sys

import pytest


def pytest_collection_modifyitems(items: list, config: pytest.Config) -> None:
    """Mark Unix transport tests as skip on Windows before any fixture setup."""
    if sys.platform != "win32":
        return
    skip_mark = pytest.mark.skip(reason="Unix domain sockets are not supported on Windows")
    unix_fixtures = {"managed_unix_socket_path", "temp_unix_socket_path"}
    for item in items:
        if hasattr(item, "fixturenames") and unix_fixtures.intersection(item.fixturenames):
            item.add_marker(skip_mark)
        # Also skip parametrized tests with transport_type="unix"
        elif hasattr(item, "callspec") and item.callspec.params.get("transport_type") == "unix":
            item.add_marker(skip_mark)
