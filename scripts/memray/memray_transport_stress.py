#!/usr/bin/env python
"""Memray stress test for transport creation and validation hot paths."""

import os

os.environ["PLUGIN_LOG_LEVEL"] = "ERROR"

from pyvider.rpcplugin.transport.tcp import TCPSocketTransport, is_valid_tcp_endpoint
from pyvider.rpcplugin.transport.unix.transport import UnixSocketTransport


def main() -> None:
    """Stress test transport object creation and validation."""

    # --- Warmup ---
    for _ in range(100):
        is_valid_tcp_endpoint("127.0.0.1:8080")

    # --- Stress: is_valid_tcp_endpoint validation (20K cycles) ---
    endpoints = [f"127.0.0.1:{8000 + i}" for i in range(100)] + [
        "invalid",
        ":8080",
        "localhost:abc",
        "",
    ]
    for i in range(20_000):
        is_valid_tcp_endpoint(endpoints[i % len(endpoints)])

    # --- Stress: TCPSocketTransport creation (5K cycles) ---
    # Object creation only, no listen/close to avoid port exhaustion
    for i in range(5_000):
        TCPSocketTransport(
            host="127.0.0.1",
            port=8000 + (i % 1000),
        )

    # --- Stress: UnixSocketTransport creation (5K cycles) ---
    # Object creation only, no listen/close to avoid filesystem overhead
    for i in range(5_000):
        UnixSocketTransport(
            path=f"/tmp/pyvider-stress-{i % 100}.sock",
        )

    print("Transport stress test complete: 30K total cycles")


if __name__ == "__main__":
    main()
