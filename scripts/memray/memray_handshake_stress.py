#!/usr/bin/env python
# SPDX-FileCopyrightText: Copyright (c) 2026 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Memray stress test for handshake parsing and validation hot paths."""

import os

# Suppress logging to isolate allocation profiling
os.environ["PLUGIN_LOG_LEVEL"] = "ERROR"
os.environ["PLUGIN_MAGIC_COOKIE_KEY"] = "STRESS_TEST_COOKIE"
os.environ["PLUGIN_MAGIC_COOKIE_VALUE"] = "stress_cookie_value_12345"
os.environ["STRESS_TEST_COOKIE"] = "stress_cookie_value_12345"

from pyvider.rpcplugin.handshake.core import (
    HandshakeConfig,
    _apply_certificate_padding,
    _prepare_server_cert,
    _split_handshake_response,
    parse_handshake_response,
    validate_magic_cookie,
)


def main() -> None:
    """Stress test handshake parsing and validation."""

    # --- Warmup (separate import-time allocations) ---
    for _ in range(100):
        _split_handshake_response("1|1|tcp|127.0.0.1:8080|grpc|")

    # --- Stress: parse_handshake_response (10K cycles) ---
    # Build representative handshake strings
    cert_body = "MIIBkTCB+wIJAKHBfpHYzpHYMA0GCSqGSIb3DQEBCwUA" * 3
    handshake_strings = [f"1|1|tcp|127.0.0.1:{8000 + (i % 1000)}|grpc|{cert_body}" for i in range(100)]
    for i in range(10_000):
        parse_handshake_response(handshake_strings[i % 100])

    # --- Stress: validate_magic_cookie (5K cycles) ---
    for _ in range(5_000):
        validate_magic_cookie(
            magic_cookie_key="STRESS_TEST_COOKIE",
            magic_cookie_value="stress_cookie_value_12345",
            magic_cookie="stress_cookie_value_12345",
        )

    # --- Stress: _split_handshake_response (10K cycles) ---
    for i in range(10_000):
        _split_handshake_response(handshake_strings[i % 100])

    # --- Stress: _prepare_server_cert (10K cycles) ---
    raw_certs = [
        cert_body + "\\n\\r" * 5,
        "abc123\\ndef456\\r\\n",
        cert_body,
    ]
    for i in range(10_000):
        _prepare_server_cert(raw_certs[i % 3])

    # --- Stress: _apply_certificate_padding (10K cycles) ---
    certs_needing_padding = [
        cert_body[:10],  # needs 2 padding chars
        cert_body[:11],  # needs 1 padding char
        cert_body[:12],  # no padding needed
        cert_body[:13],  # needs 3 padding chars
    ]
    for i in range(10_000):
        _apply_certificate_padding(certs_needing_padding[i % 4])

    # --- Stress: HandshakeConfig creation (5K cycles) ---
    for i in range(5_000):
        HandshakeConfig(
            magic_cookie_key=f"KEY_{i % 10}",
            magic_cookie_value=f"VALUE_{i % 10}",
            protocol_versions=[1, 2, 3],
            supported_transports=["tcp", "unix"],
        )

    print("Handshake stress test complete: 60K total cycles")


if __name__ == "__main__":
    main()
