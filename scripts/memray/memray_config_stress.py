#!/usr/bin/env python
"""Memray stress test for configuration validation and object creation."""

import os

os.environ["PLUGIN_LOG_LEVEL"] = "ERROR"

from pyvider.rpcplugin.config.validators import validate_protocol_versions_list, validate_transport_list
from pyvider.rpcplugin.handshake.core import HandshakeConfig


def main() -> None:
    """Stress test config validation and creation."""

    # --- Warmup ---
    for _ in range(100):
        validate_protocol_versions_list("1,2,3")
        validate_transport_list("unix,tcp")

    # --- Stress: validate_protocol_versions_list (10K cycles) ---
    version_inputs = [
        "1",
        "1,2",
        "1,2,3",
        "1,2,3,4,5",
        [1, 2, 3],
        [1],
        [1, 2, 3, 4, 5, 6, 7],
    ]
    for i in range(10_000):
        validate_protocol_versions_list(version_inputs[i % len(version_inputs)])

    # --- Stress: validate_transport_list (10K cycles) ---
    transport_inputs = [
        "unix",
        "tcp",
        "unix,tcp",
        ["unix"],
        ["tcp"],
        ["unix", "tcp"],
    ]
    for i in range(10_000):
        validate_transport_list(transport_inputs[i % len(transport_inputs)])

    # --- Stress: HandshakeConfig creation (5K cycles) ---
    for i in range(5_000):
        HandshakeConfig(
            magic_cookie_key=f"COOKIE_KEY_{i % 10}",
            magic_cookie_value=f"cookie_value_{i % 10}",
            protocol_versions=[1, 2, 3],
            supported_transports=["tcp", "unix"],
        )

    print("Config stress test complete: 25K total cycles")


if __name__ == "__main__":
    main()
