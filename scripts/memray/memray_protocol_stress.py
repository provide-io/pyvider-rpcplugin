#!/usr/bin/env python
# SPDX-FileCopyrightText: Copyright (c) 2026 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Memray stress test for protocol service object creation and management."""

import os

os.environ["PLUGIN_LOG_LEVEL"] = "ERROR"

from pyvider.rpcplugin.protocol.service import SubchannelConnection


def main() -> None:
    """Stress test protocol service object lifecycle."""

    # --- Warmup ---
    for _ in range(100):
        SubchannelConnection(conn_id=0, address="127.0.0.1:9000")

    # --- Stress: SubchannelConnection creation (10K cycles) ---
    connections = []
    for i in range(10_000):
        conn = SubchannelConnection(
            conn_id=i,
            address=f"127.0.0.1:{9000 + (i % 1000)}",
        )
        connections.append(conn)

    # --- Stress: broker dict management (5K insert/delete cycles) ---
    broker_dict: dict[int, SubchannelConnection] = {}
    for i in range(5_000):
        conn = SubchannelConnection(
            conn_id=i,
            address=f"127.0.0.1:{9000 + (i % 500)}",
        )
        broker_dict[i] = conn

    # Delete half the entries
    for i in range(0, 5_000, 2):
        del broker_dict[i]

    # Re-insert with new connections
    for i in range(0, 5_000, 2):
        broker_dict[i] = SubchannelConnection(
            conn_id=i + 10_000,
            address=f"127.0.0.1:{9000 + (i % 500)}",
        )

    # --- Stress: ConnInfo-like dict creation (10K cycles) ---
    # Simulates the allocation pattern of protobuf message creation
    for i in range(10_000):
        {
            "service_id": i,
            "network": "tcp",
            "address": f"127.0.0.1:{9000 + (i % 1000)}",
        }

    # Cleanup
    connections.clear()
    broker_dict.clear()

    print("Protocol stress test complete: 32.5K total cycles")


if __name__ == "__main__":
    main()
