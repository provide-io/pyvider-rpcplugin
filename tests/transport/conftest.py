#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Skip Unix socket tests on Windows for the transport test suite."""

import sys

import pytest


@pytest.fixture(autouse=True)
def skip_unix_tests_on_windows(request: pytest.FixtureRequest) -> None:
    """Skip tests that use Unix sockets on Windows — unix domain sockets not supported."""
    if sys.platform != "win32":
        return
    # Skip if test requests unix socket fixtures
    unix_fixtures = {"managed_unix_socket_path", "temp_unix_socket_path"}
    if unix_fixtures.intersection(request.fixturenames):
        pytest.skip("Unix domain sockets are not supported on Windows")
    # Skip parametrized tests where transport_type == "unix"
    if hasattr(request.node, "callspec"):
        params = request.node.callspec.params
        if params.get("transport_type") == "unix":
            pytest.skip("Unix domain sockets are not supported on Windows")
