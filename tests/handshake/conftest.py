#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Skip Unix socket tests on Windows for the handshake test suite."""

import sys

import pytest


@pytest.fixture(autouse=True)
def skip_unix_tests_on_windows(request: pytest.FixtureRequest) -> None:
    """Skip tests that use Unix socket fixtures on Windows."""
    if sys.platform != "win32":
        return
    unix_fixtures = {"managed_unix_socket_path", "temp_unix_socket_path"}
    if unix_fixtures.intersection(request.fixturenames):
        pytest.skip("Unix domain sockets are not supported on Windows")
